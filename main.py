from typing import List
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime

# Assuming these are in your project, adjust imports as needed
from analyzer.code_inspector import CodeInspector
from models.security_types import SecurityAnalysisReport

app = FastAPI(
    title="Inspectify AI Agent",
    description="API for AI-powered security vulnerability detection and remediation",
    version="0.1.0"
)

# Configure CORS (restrict origins in production!)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins in development; restrict in production!
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def clean_display_path(file_path: str) -> str:
    """
    Clean file paths for display in the UI by removing temporary directory parts
    
    Args:
        file_path: Original file path
        
    Returns:
        str: Cleaned file path for display
    """
    import re
    
    if not file_path:
        return ""
    
    # Remove common temp directory patterns
    path_patterns_to_remove = [
        r'C:\\Users\\[^\\]+\\AppData\\Local\\Temp\\',
        r'C:/Users/[^/]+/AppData/Local/Temp/',
        r'/tmp/',
        r'\\AppData\\Local\\Temp\\',
        r'AppData\\Local\\Temp\\'
    ]
    
    cleaned_path = file_path
    for pattern in path_patterns_to_remove:
        cleaned_path = re.sub(pattern, '', cleaned_path, flags=re.IGNORECASE)
    
    return cleaned_path

class AnalysisRequest(BaseModel):
    repository_url: str
    branch: str = "main"
    scan_depth: int = 3

analyzer = CodeInspector()  # Initialize the analyzer once

@app.post("/analyze/file", response_model=SecurityAnalysisReport)
async def analyze_file(files: List[UploadFile] = File(...)) -> SecurityAnalysisReport:
    """
    Analyze one or more files for security vulnerabilities.
    """
    print("--- Starting analyze_file (FastAPI) ---")
    try:
        reports = []
        for file in files:
            print(f"  Processing file: {file.filename}")
            file_content = await file.read()  # Read file content directly
            print(f"    File content read.  Size: {len(file_content)} bytes")
            report = await analyzer.inspect_code(file_content, file.filename)
            print(f"    Analysis complete for {file.filename}.")
            reports.append(report)

        if len(reports) > 1:
            # Combine reports
            combined_report = SecurityAnalysisReport(
                timestamp=datetime.now(),  # Use current time for combined report
                vulnerabilities=[vuln for r in reports for vuln in r.vulnerabilities],
                chained_vulnerabilities=[chain for r in reports for chain in r.chained_vulnerabilities]
            )
            combined_report.calculate_summary()
            combined_report.calculate_risk_score()
            print("    Combined report created.")
            return combined_report
        elif reports:
            print("    Returning single report.")
            return reports[0]
        else:
            print("    No files to analyze, returning empty report")
            return SecurityAnalysisReport(timestamp=datetime.now(), vulnerabilities=[], chained_vulnerabilities=[])

    except Exception as e:
        print(f"    Error during analysis: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        print("--- Finishing analyze_file (FastAPI) ---")


@app.post("/analyze/repository", response_model=SecurityAnalysisReport)
async def analyze_repository(request: AnalysisRequest) -> SecurityAnalysisReport:
    try:
        report = await analyzer.analyze_repository(
            request.repository_url,
            request.branch,
            request.scan_depth
        )
        # sanitize the file path for display
        for vuln in report.vulnerabilities:
            vuln.location.file_path = clean_display_path(vuln.location.file_path)
        report.calculate_summary()  # Make sure summary is calculated
        report.calculate_risk_score()  # Calculate risk score
        return report
    except Exception as e:
        print(f"    Error during analysis: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8001)