from typing import List
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime

from analyzer.code_analyzer import CodeAnalyzer
from models.vulnerability import VulnerabilityReport
from utils.file_handler import process_uploaded_file

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

class AnalysisRequest(BaseModel):
    repository_url: str
    branch: str = "main"
    scan_depth: int = 3

analyzer = CodeAnalyzer()  # Initialize the analyzer once

@app.post("/analyze/file", response_model=VulnerabilityReport)
async def analyze_file(files: List[UploadFile] = File(...)) -> VulnerabilityReport:
    """
    Analyze a single file for security vulnerabilities.
    """
    print("--- Starting analyze_file (FastAPI) ---")  # Start of function
    try:
        reports = []
        for file in files:
            print(f"  Processing file: {file.filename}")  # File being processed
            file_content = await process_uploaded_file(file)
            print(f"    File content read.  Size: {len(file_content)} bytes")  # Content size
            report = await analyzer.analyze_code(file_content, file.filename)
            print(f"    Analysis complete for {file.filename}.")  # Analysis status
            reports.append(report)
        #Aggregate the reports
        if len(reports) > 1:
            # Combine reports (handle potential conflicts/overlaps)
            combined_report = VulnerabilityReport(
                timestamp=reports[0].timestamp,
                vulnerabilities=[vuln for r in reports for vuln in r.vulnerabilities],
                chained_vulnerabilities=[chain for r in reports for chain in r.chained_vulnerabilities]
            )
            combined_report.calculate_summary()
            combined_report.calculate_risk_score()
            print("    Combined report created.") # Report combination status
            return combined_report
        elif reports:
            print(reports[0])
            print("    Returning single report.") # Single report status
            return reports[0]  # Return single report if only one file
        else:
            print("    No files to analyze, returning empty report")
            return VulnerabilityReport(timestamp=datetime.now(), vulnerabilities=[], chained_vulnerabilities=[])
    except Exception as e:
        print(f"    Error during analysis: {e}")  # Error handling
        raise HTTPException(status_code=500, detail=str(e))
    finally:
      print("--- Finishing analyze_file (FastAPI) ---") # End of function


@app.post("/analyze/repository", response_model=VulnerabilityReport)
async def analyze_repository(request: AnalysisRequest) -> VulnerabilityReport:
    """
    Analyze a git repository for security vulnerabilities.
    """
    try:
        report = await analyzer.analyze_repository(
            request.repository_url,
            request.branch,
            request.scan_depth
        )
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8189)