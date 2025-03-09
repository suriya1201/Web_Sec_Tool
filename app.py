import streamlit as st
import httpx
import asyncio
from models.security_types import SecurityAnalysisReport
from utils.pdf_generator import PDFGenerator  # Add this import
import os
from datetime import datetime
from analyzer.zap_scanner import scan_url
from analyzer.wapiti_scanner import run_wapiti
from analyzer.sqlmap_scanner import run_sqlmap
from analyzer.commix_scanner import run_commix
from analyzer.sstimap_scanner import run_sstimap
from analyzer.XSStrike_scanner import run_xsstrike
from report_manager import ReportManager
from zapv2 import ZAPv2
from analyzer.broken_access_scanner import run_broken_access_scan

zap = ZAPv2(
    proxies={"http": "http://localhost:8081", "https": "http://localhost:8081"},
    apikey=os.getenv("ZAP_API_KEY"),
)


# --- Helper Functions ---
def is_valid_repo_url(url: str) -> bool:
    return url.startswith("http://") or url.startswith("https://")


def is_valid_scan_url(url: str) -> bool:
    return url.startswith("http://") or url.startswith("https://")


def run_scan(target_url, scan_depth, selected_scanners):
    if is_valid_scan_url(target_url):
        if not selected_scanners:
            st.error("Please select at least one scanner.")
            return False
        else:
            report_manager = ReportManager("./scans/consolidated_scan_results.pdf")

            if "ZAP" in selected_scanners:
                st.header("OWASP ZAP Scan:")
                st.write(f"Scanning URL: {target_url} with depth: {scan_depth}")
                scan_url(report_manager, target_url, scan_depth)
                st.markdown("---")
            if "Wapiti" in selected_scanners:
                st.header("Wapiti Scan:")
                run_wapiti(report_manager, target_url, scan_depth)
            if "SQLMap" in selected_scanners:
                st.header("SQLMap Scan:")
                run_sqlmap(report_manager, target_url, scan_depth)
                st.markdown("---")
            if "XSStrike" in selected_scanners:
                st.header("XSStrike Scan:")
                run_xsstrike(report_manager, target_url, scan_depth)
                st.markdown("---")
            if "COMMIX" in selected_scanners:
                st.header("COMMIX Scan:")
                run_commix(report_manager, target_url, scan_depth)
                st.markdown("---")
            if "SSTImap" in selected_scanners:
                st.header("SSTImap Scan:")
                run_sstimap(report_manager, target_url, scan_depth)
                st.markdown("---")
            if "Broken Access Control" in selected_scanners:
                st.header("Broken Access Control Scan:")
                run_broken_access_scan(report_manager, target_url, scan_depth)
                st.markdown("---")

            # Save the PDF to session state
            with open("scans/consolidated_scan_results.pdf", "rb") as file:
                st.session_state.scan_results_pdf = file.read()

            # Mark scan as completed
            st.session_state.scan_completed = True
            return True
    else:
        st.error(
            "Invalid URL. Please enter a valid URL starting with http:// or https://."
        )
        return False


# --- Analysis Logic (using httpx for requests to FastAPI) ---
async def analyze_code_file(files):
    print("--- Starting analyze_code_file (Streamlit) ---")
    async with httpx.AsyncClient(timeout=180.0) as client:
        files_data = []
        for file in files:
            print(f"  Processing file: {file.name}")
            files_data.append(("files", (file.name, file.getvalue(), file.type)))
        print(f"  Files data prepared: {files_data}")

        try:
            print("  Sending POST request to FastAPI...")
            response = await client.post(
                "http://127.0.0.1:8001/analyze/file", files=files_data
            )
            print(f"  Received response. Status: {response.status_code}")
            response.raise_for_status()
            report = SecurityAnalysisReport(**response.json())
            print("  Response parsed successfully.")
            return report
        except httpx.RequestError as e:
            print(f"  Network error: {e}")
            st.error(f"Network error: {e}")
            return None
        except httpx.HTTPStatusError as e:
            print(f"  Server error: {e.response.status_code} - {e.response.text}")
            st.error(f"Server error: {e.response.status_code} - {e.response.text}")
            return None
        except Exception as e:
            print(f"  Unexpected error: {e}")
            st.error(f"Unexpected error: {e}")
            return None
        finally:
            print("--- Finishing analyze_code_file (Streamlit) ---")


async def analyze_repo(repo_url, branch, scan_depth):
    """
    Analyze a code repository for security vulnerabilities with improved error handling and logging.
    
    Args:
        repo_url: The URL of the repository to analyze
        branch: The branch to analyze
        scan_depth: The depth to scan the repository
        
    Returns:
        SecurityAnalysisReport or None: The analysis report or None if an error occurred
    """
    print("--- Starting analyze_repo (Streamlit) ---")
    print(f"  Repository URL: {repo_url}")
    print(f"  Branch: {branch}")
    print(f"  Scan Depth: {scan_depth}")
    
    # Check if the API service is running
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            health_check = await client.get("http://127.0.0.1:8001/health")
            if health_check.status_code != 200:
                st.error("The analysis service is not responding. Please make sure it's running.")
                print(f"  API health check failed: {health_check.status_code}")
                return None
    except Exception as e:
        st.error("Could not connect to the analysis service. Please ensure it's running on port 8001.")
        print(f"  API connection error: {str(e)}")
        return None
        
    # Sanitize repository URL
    if not repo_url.startswith(("http://", "https://")):
        repo_url = f"https://{repo_url}"
        print(f"  URL adjusted to: {repo_url}")
    
    # Proceed with the analysis with an increased timeout
    try:
        async with httpx.AsyncClient(timeout=300.0) as client:  # Increase timeout to 2 minutes
            print("  Sending POST request to FastAPI...")
            response = await client.post(
                "http://127.0.0.1:8001/analyze/repository",
                json={
                    "repository_url": repo_url,
                    "branch": branch,
                    "scan_depth": scan_depth,
                },
            )
            print(f"  Received response. Status: {response.status_code}")
            response.raise_for_status()
            report = SecurityAnalysisReport(**response.json())
            print("  Response parsed successfully.")
            return report
    except httpx.ConnectError:
        error_msg = "Connection error: Could not connect to the analysis service. Make sure the API server is running."
        print(f"  {error_msg}")
        st.error(error_msg)
        return None
    except httpx.TimeoutException:
        error_msg = "Timeout error: The analysis took too long. Try reducing the scan depth or try again later."
        print(f"  {error_msg}")
        st.error(error_msg)
        return None
    except httpx.RequestError as e:
        print(f"  Network error: {e}")
        st.error(f"Network error: {str(e)}")
        return None
    except httpx.HTTPStatusError as e:
        print(f"  Server error: {e.response.status_code} - {e.response.text}")
        st.error(f"Server error: {e.response.status_code} - {e.response.text}")
        return None
    except Exception as e:
        print(f"  Unexpected error: {e}")
        st.error(f"Unexpected error: {str(e)}")
        return None
    finally:
        print("--- Finishing analyze_repo (Streamlit) ---")


# Function to generate PDF for code analysis results
def generate_code_analysis_pdf(report):
    # Ensure the analysis directory exists
    os.makedirs("analysis", exist_ok=True)
    
    # Generate the PDF report using the new method for the new format
    pdf_generator = PDFGenerator("analysis/code_analysis_report.pdf")
    
    # Use the new method for the new structure
    pdf_generator.generate_security_report(report)
    
    # Read and return the PDF content
    with open("analysis/code_analysis_report.pdf", "rb") as file:
        return file.read()


# --- Initialize Session State ---
if "scan_completed" not in st.session_state:
    st.session_state.scan_completed = False
if "scan_results" not in st.session_state:
    st.session_state.scan_results = None
if "scan_results_pdf" not in st.session_state:
    st.session_state.scan_results_pdf = None
# Add session state for code analysis
if "analysis_completed" not in st.session_state:
    st.session_state.analysis_completed = False
if "analysis_results" not in st.session_state:
    st.session_state.analysis_results = None
if "analysis_results_pdf" not in st.session_state:
    st.session_state.analysis_results_pdf = None


# --- UI Setup ---
st.set_page_config(page_title="INSPECTIFY", layout="wide")

# Structure with sidebar for input controls and main area for results
with st.sidebar:
    st.markdown("<h1 style='font-size: 3em;'>INSPECTIFY</h1>", unsafe_allow_html=True)
    st.header("Select task")
    
    # Create tabs in the sidebar
    tab1, tab2 = st.tabs(["Code Analysis", "Vulnerability Scanning"])
    
    # Tab 1: Code Analysis
    with tab1:
        input_type = st.radio(
            "Select Input Type", 
            ["Upload Code File", "Provide Repository URL"]
        )

        if input_type == "Upload Code File":
            uploaded_files = st.file_uploader(
                "Upload Code File(s)",
                type=[
                    "py", "js", "java", "cpp", "c", "cs", "go", "rb",
                    "php", "rs", "swift", "kt", "scala",
                ],
                accept_multiple_files=True,
            )
            if uploaded_files:
                st.write(f"You have uploaded {len(uploaded_files)} file(s).")
            repo_url = None
            branch = None
            code_scan_depth = None

        else:  # input_type == "Provide Repository URL"
            repo_url = st.text_input("Repository URL", key="repo_url_input")
            branch = st.text_input("Branch", "main", key="branch_input")
            code_scan_depth = st.number_input("Scan Depth", min_value=1, value=3, key="code_depth_input")
            uploaded_files = None

        analyze_button = st.button("Analyze", key="analyze_button")
    
    # Tab 2: Vulnerability Scanning
    with tab2:
        st.write("Vulnerability Scanning (Injection and Broken Access Control)")
        target_url = st.text_input("Enter URL to scan", key="target_url_input")
        vuln_scan_depth = st.number_input(
            "Scan Depth", min_value=1, max_value=10, value=1, key="vuln_depth_input"
        )

        # Add the tooltip style
        st.markdown(
            """
            <style>
            .tooltip {
                position: relative;
                display: inline-block;
                cursor: pointer;
            }
            .tooltip .tooltiptext {
                visibility: hidden;
                width: 400px;
                background-color: #555;
                color: #fff;
                text-align: center;
                border-radius: 6px;
                padding: 5px 0;
                position: absolute;
                z-index: 1;
                bottom: 125%;
                left: 50%;
                margin-left: -100px;
                opacity: 0;
                transition: opacity 0.3s;
            }
            .tooltip:hover .tooltiptext {
                visibility: visible;
                opacity: 1;
            }
            </style>
            """,
            unsafe_allow_html=True,
        )
        st.markdown(
            """
            <div style="display: flex; align-items: center;">
                <h3 style="margin: 0;">Select Scanners</h3>
                <div class="tooltip" style="margin-left: 5px;">ℹ️
                    <span class="tooltiptext">
                        <b>OWASP ZAP:</b> A popular security tool for finding vulnerabilities in web applications.<br>
                        <b>Wapiti:</b> A web application vulnerability scanner that audits the security of web applications.<br>
                        <b>SQLMap:</b> An open-source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws.<br>
                        <b>XSStrike:</b> A tool for detecting and exploiting XSS vulnerabilities.<br>
                        <b>COMMIX:</b> A tool for testing web applications for command injection vulnerabilities.(May take long)<br>
                        <b>SSTImap:</b> A tool for detecting and exploiting Server-Side Template Injection vulnerabilities.(May take long)
                        <b>BrokenAccess:</b> A scanner that detects broken access control vulnerabilities such as IDOR and unauthorized access to protected resources.
                    </span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Add a multiselect dropdown for scanners
        selected_scanners = st.multiselect(
            "Options",
            ["ZAP", "Wapiti", "SQLMap", "XSStrike", "COMMIX", "SSTImap", "Broken Access Control"],
            default=["ZAP", "Wapiti"],
            key="scanner_select"
        )

        # Scan button
        if not st.session_state.scan_completed:
            scan_button = st.button("Start Scan", key="scan_button")
        else:
            new_scan_button = st.button("Run New Scan", key="new_scan_button")
            if new_scan_button:
                st.session_state.scan_completed = False
                st.rerun()

# Main content area - for displaying results only
st.title("INSPECTIFY")
st.write("Tool for analyzing code and scanning web applications for vulnerabilities.")

# Display Code Analysis Results in main area
if st.session_state.analysis_completed and st.session_state.analysis_results:
    st.success("Analysis completed successfully!")
    report = st.session_state.analysis_results
    
    st.header("Security Analysis Report")
    st.subheader("Summary")
    
    # Helper function to safely get data from either format
    def get_attribute_or_key(obj, name, default=None):
        if isinstance(obj, dict):
            return obj.get(name, default)
        else:
            return getattr(obj, name, default)
    
    # Check for summary or summary_stats (handle both formats)
    summary_data = None
    if hasattr(report, 'summary') and report.summary:
        summary_data = report.summary
    elif hasattr(report, 'summary_stats') and report.summary_stats:
        summary_data = report.summary_stats
    elif isinstance(report, dict) and report.get('summary_stats'):
        summary_data = report['summary_stats']
    
    if summary_data:
        col1, col2, col3, col4, col5, col6 = st.columns(6)
        
        # Try to get values using different possible key names
        total = get_attribute_or_key(summary_data, 'total', 
                get_attribute_or_key(summary_data, 'total_issues', '0'))
        critical = get_attribute_or_key(summary_data, 'critical',
                get_attribute_or_key(summary_data, 'critical_count', '0'))
        high = get_attribute_or_key(summary_data, 'high',
                get_attribute_or_key(summary_data, 'high_count', '0'))
        medium = get_attribute_or_key(summary_data, 'medium',
                get_attribute_or_key(summary_data, 'medium_count', '0'))
        low = get_attribute_or_key(summary_data, 'low',
                get_attribute_or_key(summary_data, 'low_count', '0'))
        info = get_attribute_or_key(summary_data, 'info',
                get_attribute_or_key(summary_data, 'info_count', '0'))
        
        col1.metric("Total", total)
        col2.metric("Critical", critical)
        col3.metric("High", high)
        col4.metric("Medium", medium)
        col5.metric("Low", low)
        col6.metric("Info", info)
    
    # Get risk score (try both possible field names)
    risk_score = None
    if hasattr(report, 'risk_score'):
        risk_score = report.risk_score
    elif hasattr(report, 'risk_rating'):
        risk_score = report.risk_rating
    elif isinstance(report, dict):
        risk_score = report.get('risk_score', report.get('risk_rating'))
    
    if risk_score is not None:
        try:
            formatted_score = f"{float(risk_score):.2f}"
        except (ValueError, TypeError):
            formatted_score = str(risk_score)
        st.metric("Risk Score", formatted_score)
    
    # Add download button for the analysis report
    if st.session_state.analysis_results_pdf is not None:
        try:
            st.download_button(
                label="📥 Download Security Analysis Report (PDF)",
                data=st.session_state.analysis_results_pdf,
                file_name="security_analysis_report.pdf",
                mime="application/pdf",
                key="analysis_download_button"
            )
        except Exception as e:
            st.error(f"Error with download button: {str(e)}")

    # Display vulnerabilities - handle both formats
    st.subheader("Security Issues")
    
    # Get list of issues/vulnerabilities from either format
    issues = []
    if hasattr(report, 'vulnerabilities'):
        issues = report.vulnerabilities
    elif hasattr(report, 'issues'):
        issues = report.issues
    elif isinstance(report, dict):
        issues = report.get('vulnerabilities', report.get('issues', []))
    
    for issue in issues:
        # Get issue attributes based on format
        if hasattr(issue, 'type'):
            # Old format
            issue_type = issue.type
            severity = issue.severity
            description = issue.description
            impact = issue.impact
            remediation = issue.remediation
            cwe_id = issue.cwe_id
            owasp_category = issue.owasp_category
            cvss_score = issue.cvss_score
            references = getattr(issue, 'references', [])
            proof_of_concept = getattr(issue, 'proof_of_concept', '')
            secure_example = getattr(issue, 'secure_code_example', '')
            
            # Location
            if hasattr(issue, 'location'):
                location = f"{issue.location.file_path}:{issue.location.start_line}"
            else:
                location = "Unknown"
        else:
            # New format
            issue_type = get_attribute_or_key(issue, 'category', 'Unknown')
            severity = get_attribute_or_key(issue, 'severity', 'Medium')
            description = get_attribute_or_key(issue, 'description', 'No description')
            impact = get_attribute_or_key(issue, 'impact', 'No impact information')
            remediation = get_attribute_or_key(issue, 'remediation', 'No remediation information')
            cwe_id = get_attribute_or_key(issue, 'cwe_id', '')
            owasp_category = get_attribute_or_key(issue, 'owasp_category', 'Unknown')
            cvss_score = get_attribute_or_key(issue, 'cvss_score', 'Unknown')
            references = get_attribute_or_key(issue, 'references', [])
            proof_of_concept = get_attribute_or_key(issue, 'proof_of_concept', '')
            secure_example = get_attribute_or_key(issue, 'secure_alternative', 
                                               get_attribute_or_key(issue, 'secure_code_example', ''))
            
            # Location
            position = get_attribute_or_key(issue, 'position', {})
            if position:
                file_path = get_attribute_or_key(position, 'file_path', 'Unknown')
                start_line = get_attribute_or_key(position, 'start_line', '?')
                location = f"{file_path}:{start_line}"
            else:
                location = "Unknown"
        
        # Display the issue with an expander
        with st.expander(f"{issue_type} - {severity} - {location}"):
            st.write(f"**Description:** {description}")
            st.write(f"**Impact:** {impact}")
            st.write(f"**Remediation:** {remediation}")
            
            # Format CWE link
            cwe_clean = str(cwe_id).replace('CWE-', '')
            st.write(f"**CWE ID:** [{cwe_id}](https://cwe.mitre.org/data/definitions/{cwe_clean}.html)")
            
            st.write(f"**OWASP Category:** {owasp_category}")
            st.write(f"**CVSS Score:** {cvss_score}")
            
            if references:
                st.write("**References:**")
                for ref in references:
                    st.write(f"- [{ref}]({ref})")
            
            if proof_of_concept:
                st.write("**Proof of Concept:**")
                st.code(proof_of_concept, language="python")
            
            if secure_example:
                st.write("**Secure Code Example:**")
                st.code(secure_example, language="python")

    # Display issue chains - handle both formats
    chains_title = "Vulnerability Chains" if hasattr(report, 'chained_vulnerabilities') else "Security Issue Chains"
    st.subheader(chains_title)
    
    # Get list of chains from either format
    chains = []
    if hasattr(report, 'chained_vulnerabilities'):
        chains = report.chained_vulnerabilities
    elif hasattr(report, 'issue_chains'):
        chains = report.issue_chains
    elif isinstance(report, dict):
        chains = report.get('chained_vulnerabilities', report.get('issue_chains', []))
    
    if not chains:
        st.write("No vulnerability chains detected.")
    
    for chain in chains:
        # Get chain attributes based on format
        if hasattr(chain, 'combined_severity'):
            # Old format
            combined_severity = chain.combined_severity
            attack_info = getattr(chain, 'attack_path', 'No attack path')
            likelihood = getattr(chain, 'likelihood', 'Unknown')
            prerequisites = getattr(chain, 'prerequisites', [])
            priority = getattr(chain, 'mitigation_priority', 'Unknown')
        else:
            # New format
            combined_severity = get_attribute_or_key(chain, 'combined_severity', 'Unknown')
            attack_info = get_attribute_or_key(chain, 'attack_scenario', 
                                           get_attribute_or_key(chain, 'attack_path', 'No attack information'))
            likelihood = get_attribute_or_key(chain, 'exploit_likelihood', 
                                          get_attribute_or_key(chain, 'likelihood', 'Unknown'))
            prerequisites = get_attribute_or_key(chain, 'prerequisites', [])
            priority = get_attribute_or_key(chain, 'mitigation_priority', 'Unknown')
        
        # Display the chain with an expander
        with st.expander(f"Chain - Combined Severity: {combined_severity}"):
            st.write(f"**Attack Path:** {attack_info}")
            st.write(f"**Likelihood:** {likelihood}")
            
            if prerequisites:
                st.write("**Prerequisites:**")
                for prereq in prerequisites:
                    st.write(f"- {prereq}")
            
            st.write(f"**Mitigation Priority:** {priority}")

# Display Vulnerability Scanning Results in main area
if st.session_state.scan_completed and st.session_state.scan_results_pdf:
    st.success("Scan completed successfully!")
    st.write(f"**Target URL:** {st.session_state.target_url}")
    st.write(f"**Scan Depth:** {st.session_state.scan_depth}")
    st.write(f"**Scanners Used:** {', '.join(st.session_state.selected_scanners)}")

    # Display individual scanner outputs with download buttons
    st.header("Download Scan Results by Tool :")

    for scanner in st.session_state.get("selected_scanners", []):
        st.header(scanner)
        
        try:
            with open(f"scans/{scanner.lower()}_scan_report.pdf", "rb") as pdf_file:
                pdf_data = pdf_file.read()

            # Add a download button
            st.download_button(
                label=f"📥 Download {scanner} Scan Report (PDF)",
                data=pdf_data,
                file_name=f"{scanner.lower()}_scan_report.pdf",
                mime="application/pdf",
                key=f"download_{scanner.lower()}"
            )

        except FileNotFoundError:
            st.error(
                f"File not found: {scanner.lower()}_scan_report.pdf. Ensure the file exists and the path is correct."
            )

    st.markdown("---")

    st.header("Consolidated Scan Results")
    st.download_button(
        label="📥 Download Consolidated Scan Results (PDF)",
        data=st.session_state.scan_results_pdf,
        file_name="consolidated_scan_results.pdf",
        mime="application/pdf",
        key="download_button",
    )

# --- Main Analysis Logic ---
# Handle analyze button click
if 'analyze_button' in locals() and analyze_button:
    if input_type == "Upload Code File" and uploaded_files:
        with st.spinner("Analyzing code..."):
            report = asyncio.run(analyze_code_file(uploaded_files))
            if report:
                # Store results in session state
                st.session_state.analysis_results = report
                st.session_state.analysis_results_pdf = generate_code_analysis_pdf(report)
                st.session_state.analysis_completed = True
                st.success("Analysis completed successfully!")
                st.rerun()  # Refresh to show results

    elif input_type == "Provide Repository URL" and repo_url:
        if not is_valid_repo_url(repo_url):
            st.error("Invalid repository URL.")
        else:
            with st.spinner("Analyzing repository..."):
                report = asyncio.run(analyze_repo(repo_url, branch, code_scan_depth))
                if report:
                    # Store results in session state
                    st.session_state.analysis_results = report
                    st.session_state.analysis_results_pdf = generate_code_analysis_pdf(report)
                    st.session_state.analysis_completed = True
                    st.success("Analysis completed successfully!")
                    st.rerun()  # Refresh to show results

    else:
        st.error("Please provide either a code file or a repository URL.")

# Handle scan button click
if 'scan_button' in locals() and scan_button:
    if target_url:
        with st.spinner("Running scan..."):
            success = run_scan(target_url, vuln_scan_depth, selected_scanners)
            if success:
                # Store important values in session state
                st.session_state.target_url = target_url
                st.session_state.scan_depth = vuln_scan_depth
                st.session_state.selected_scanners = selected_scanners
                st.rerun()  # Refresh to show results
    else:
        st.error("Please enter a URL to scan.")