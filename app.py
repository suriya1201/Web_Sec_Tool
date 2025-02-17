import streamlit as st
import httpx
import asyncio
from models.vulnerability import VulnerabilityReport
from utils.latex_generator import LatexGenerator
import subprocess
import os
from datetime import datetime
from analyzer.zap_scanner import scan_url
from analyzer.wapiti_scanner import run_wapiti  # Import the Wapiti scanner
from zapv2 import ZAPv2


zap = ZAPv2(
    proxies={"http": "http://localhost:8081", "https": "http://localhost:8081"},
    apikey=os.getenv("ZAP_API_KEY"),
)


# --- Helper Functions ---
def is_valid_repo_url(url: str) -> bool:
    """Basic URL validation (you might want a more robust check)."""
    return url.startswith("http://") or url.startswith("https://")


def is_valid_scan_url(url: str) -> bool:
    """Basic URL validation for scanning (you might want a more robust check)."""
    return url.startswith("http://") or url.startswith("https://")


# --- UI Setup ---
st.set_page_config(page_title="SeCoRA - AI SAST", layout="wide")
st.title("Secure Code Review AI Agent (SeCoRA)")
st.write("AI-powered security vulnerability detection and remediation.")

with st.sidebar:
    st.header("Select task")
    tabs = st.tabs(["Code Analysis", "Vulnerability Scanning"])

    with tabs[0]:
        input_type = st.radio(
            "Select Input Type", ["Upload Code File", "Provide Repository URL"]
        )

        if input_type == "Upload Code File":
            uploaded_files = st.file_uploader(
                "Upload Code File(s)",
                type=[
                    "py",
                    "js",
                    "java",
                    "cpp",
                    "c",
                    "cs",
                    "go",
                    "rb",
                    "php",
                    "rs",
                    "swift",
                    "kt",
                    "scala",
                ],
                accept_multiple_files=True,
            )
            if uploaded_files:
                st.write(f"You have uploaded {len(uploaded_files)} file(s).")
            repo_url = None  # Ensure repo_url is defined
            branch = None
            scan_depth = None

        else:  # input_type == "Provide Repository URL"
            repo_url = st.text_input("Repository URL")
            branch = st.text_input("Branch", "main")
            scan_depth = st.number_input("Scan Depth", min_value=1, value=3)
            uploaded_files = None

        analyze_button = st.button("Analyze")

    with tabs[1]:
        st.write("Vulnerability Scanning ( Injection and Broken Access Control )")

        # Add a text box for the user's URL
        target_url = st.text_input("Enter URL to scan")

        # Add options to scan other directories/pages
        scan_options = st.radio("Scan Options", ["Page Only", "Entire Website"])

        # Add a button to start the scan
        scan_button = st.button("Start Scan")

if scan_button:
    if target_url:
        if is_valid_scan_url(target_url):
            st.header("OWASP ZAP Scan:")
            st.write(f"Scanning URL: {target_url} with option: {scan_options}")
            scan_url(target_url, scan_options)
            st.header("Wapiti Scan:")
            run_wapiti(target_url, scan_options)  # Run Wapiti after ZAP with scan options
        else:
            st.error(
                "Invalid URL. Please enter a valid URL starting with http:// or https://."
            )
    else:
        st.error("Please enter a URL to scan.")


# --- Analysis Logic (using httpx for requests to FastAPI) ---
async def analyze_code_file(files):
    print("--- Starting analyze_code_file (Streamlit) ---")  # Start of function
    async with httpx.AsyncClient(follow_redirects=False) as client:
        files_data = []
        for file in files:
            print(f"  Processing file: {file.name}")  # File being processed
            files_data.append(('files', (file.name, file.getvalue(), file.type)))
        print(f"  Files data prepared: {files_data}") # Show the prepared data

        try:
            print("  Sending POST request to FastAPI...")  # Before sending request
            response = await client.post("http://localhost:8001/analyze/file", files=files_data)
            print(f"  Received response from FastAPI. Status code: {response.status_code}")  # Status code
            response.raise_for_status()  # This will raise an exception for 4xx/5xx errors
            print("  Response successful (status code 2xx).")
            report = VulnerabilityReport(**response.json())
            print("  Response parsed successfully into VulnerabilityReport.") # Successful parsing
            return report
        except httpx.RequestError as e:
            print(f"  Network error: {e}")  # Network-level errors
            return None
        except httpx.HTTPStatusError as e:
            print(f"  Server error: {e.response.status_code} - {e.response.text}")  # HTTP errors
            return None
        except Exception as e:
            print(f"  Unexpected error: {e}")  # Other exceptions
            return None
        finally:
          print("--- Finishing analyze_code_file (Streamlit) ---") # End of function


async def analyze_repo(repo_url, branch, scan_depth):
    async with httpx.AsyncClient(follow_redirects=False) as client:
        try:
            response = await client.post(
                "http://localhost:8000/analyze/repository",
                json={
                    "repository_url": repo_url,
                    "branch": branch,
                    "scan_depth": scan_depth,
                },
            )
            response.raise_for_status()
            return VulnerabilityReport(**response.json())
        except httpx.RequestError as e:
            st.error(f"Network error: {e}")
            return None
        except httpx.HTTPStatusError as e:
            st.error(f"Server error: {e.response.status_code} - {e.response.text}")
            return None
        except Exception as e:
            st.error(f"Unexpected error: {e}")
            return None


# --- Main Analysis Execution ---
if analyze_button:
    if input_type == "Upload Code File" and uploaded_files:
        with st.spinner("Analyzing code..."):
            report = asyncio.run(analyze_code_file(uploaded_files))
            if report:  # Check if the report is not None
                # Display results (same as below)
                st.header("Vulnerability Report")
                st.subheader("Summary")
                if report.summary:  # Check if summary is available
                    col1, col2, col3, col4, col5, col6 = st.columns(6)
                    col1.metric("Total", report.summary["total"])
                    col2.metric("Critical", report.summary["critical"])
                    col3.metric("High", report.summary["high"])
                    col4.metric("Medium", report.summary["medium"])
                    col5.metric("Low", report.summary["low"])
                    col6.metric("Info", report.summary["info"])
                st.metric(
                    "Risk Score",
                    (
                        f"{report.risk_score:.2f}"
                        if report.risk_score is not None
                        else "N/A"
                    ),
                )

                st.subheader("Detailed Vulnerabilities")
                for vuln in report.vulnerabilities:
                    with st.expander(
                        f"{vuln.type} - {vuln.severity} - {vuln.location.file_path}:{vuln.location.start_line}"
                    ):
                        st.write(f"**Description:** {vuln.description}")
                        st.write(f"**Impact:** {vuln.impact}")
                        st.write(f"**Remediation:** {vuln.remediation}")
                        st.write(
                            f"**CWE ID:** [{vuln.cwe_id}](https://cwe.mitre.org/data/definitions/{vuln.cwe_id}.html)"
                        )
                        st.write(f"**OWASP Category:** {vuln.owasp_category}")
                        st.write(f"**CVSS Score:** {vuln.cvss_score}")
                        if vuln.references:
                            st.write("**References:**")
                            for ref in vuln.references:
                                st.write(f"- [{ref}]({ref})")
                        if vuln.proof_of_concept:
                            with st.expander("Proof of Concept"):
                                st.code(
                                    vuln.proof_of_concept, language="python"
                                )  # Adjust language as needed
                        if vuln.secure_code_example:
                            with st.expander("Secure Code Example"):
                                st.code(
                                    vuln.secure_code_example, language="python"
                                )  # Adjust language as needed

                st.subheader("Chained Vulnerabilities")
                for chain in report.chained_vulnerabilities:
                    with st.expander(
                        f"Chain - Combined Severity: {chain.combined_severity}"
                    ):
                        st.write(f"**Attack Path:** {chain.attack_path}")
                        st.write(f"**Likelihood:** {chain.likelihood}")
                        st.write("**Prerequisites:**")
                        for prereq in chain.prerequisites:
                            st.write(f"- {prereq}")
                        st.write(
                            f"**Mitigation Priority:** {chain.mitigation_priority}"
                        )
                st.write("---")

                # Generate and offer LaTeX report download
                latex_gen = LatexGenerator()
                latex_report_str = latex_gen.generate_report(report)

                st.download_button(
                    label="Download LaTeX Report",
                    data=latex_report_str,
                    file_name="vulnerability_report.tex",
                    mime="application/x-tex",
                )

                # To also generate and download a PDF (requires pdflatex)
                # Save the LaTeX to a temporary file
                with open("temp_report.tex", "w") as f:
                    f.write(latex_report_str)

                # Run pdflatex (you might need to adjust the path)
                try:
                    # Run pdflatex (ensure pdflatex is in your PATH)
                    result = subprocess.run(
                        ["pdflatex", "-interaction=nonstopmode", "temp_report.tex"],
                        capture_output=True,
                        text=True,
                        check=True,
                    )
                    # Check for errors
                    if result.returncode != 0:
                        st.error(f"Error generating PDF: {result.stderr}")
                    else:
                        with open("temp_report.pdf", "rb") as f:
                            pdf_data = f.read()
                            st.download_button(
                                label="Download PDF Report",
                                data=pdf_data,
                                file_name="vulnerability_report.pdf",
                                mime="application/pdf",
                            )
                except FileNotFoundError:
                    st.error(
                        "pdflatex not found.  Install a LaTeX distribution (e.g., TeX Live, MiKTeX)."
                    )
                except subprocess.CalledProcessError as e:
                    st.error(f"pdflatex failed: {e}")
                finally:
                    # Clean up temporary files
                    for file_ext in [".tex", ".log", ".aux", ".pdf"]:
                        try:
                            os.remove(f"temp_report{file_ext}")
                        except FileNotFoundError:
                            pass  # Ignore if file doesn't exist

    elif input_type == "Provide Repository URL" and repo_url:
        if not is_valid_repo_url(repo_url):
            st.error(
                "Invalid repository URL. Please enter a valid URL starting with http:// or https://."
            )
        else:
            with st.spinner("Analyzing repository..."):
                report = asyncio.run(analyze_repo(repo_url, branch, scan_depth))
                if report:
                    st.header("Vulnerability Report")
                    st.subheader("Summary")
                    if report.summary:
                        col1, col2, col3, col4, col5, col6 = st.columns(6)
                        col1.metric("Total", report.summary["total"])
                        col2.metric("Critical", report.summary["critical"])
                        col3.metric("High", report.summary["high"])
                        col4.metric("Medium", report.summary["medium"])
                        col5.metric("Low", report.summary["low"])
                        col6.metric("Info", report.summary["info"])

                    st.metric(
                        "Risk Score",
                        (
                            f"{report.risk_score:.2f}"
                            if report.risk_score is not None
                            else "N/A"
                        ),
                    )

                    st.subheader("Detailed Vulnerabilities")
                    for vuln in report.vulnerabilities:
                        with st.expander(
                            f"{vuln.type} - {vuln.severity} - {vuln.location.file_path}:{vuln.location.start_line}"
                        ):
                            st.write(f"**Description:** {vuln.description}")
                            st.write(f"**Impact:** {vuln.impact}")
                            st.write(f"**Remediation:** {vuln.remediation}")
                            st.write(
                                f"**CWE ID:** [{vuln.cwe_id}](https://cwe.mitre.org/data/definitions/{vuln.cwe_id}.html)"
                            )
                            st.write(f"**OWASP Category:** {vuln.owasp_category}")
                            st.write(f"**CVSS Score:** {vuln.cvss_score}")
                            if vuln.references:
                                st.write("**References:**")
                                for ref in vuln.references:
                                    st.write(f"- [{ref}]({ref})")
                            if vuln.proof_of_concept:
                                with st.expander("Proof of Concept"):
                                    st.code(vuln.proof_of_concept, language="python")
                            if vuln.secure_code_example:
                                with st.expander("Secure Code Example"):
                                    st.code(vuln.secure_code_example, language="python")

                    st.subheader("Chained Vulnerabilities")
                    for chain in report.chained_vulnerabilities:
                        with st.expander(
                            f"Chain - Combined Severity: {chain.combined_severity}"
                        ):
                            st.write(f"**Attack Path:** {chain.attack_path}")
                            st.write(f"**Likelihood:** {chain.likelihood}")
                            st.write("**Prerequisites:**")
                            for prereq in chain.prerequisites:
                                st.write(f"- {prereq}")
                            st.write(
                                f"**Mitigation Priority:** {chain.mitigation_priority}"
                            )

                    latex_gen = LatexGenerator()
                    latex_report_str = latex_gen.generate_report(report)

                    st.download_button(
                        label="Download LaTeX Report",
                        data=latex_report_str,
                        file_name="vulnerability_report.tex",
                        mime="application/x-tex",
                    )
                    # PDF generation (same as above)
                    with open("temp_report.tex", "w") as f:
                        f.write(latex_report_str)
                    try:
                        result = subprocess.run(
                            ["pdflatex", "-interaction=nonstopmode", "temp_report.tex"],
                            capture_output=True,
                            text=True,
                            check=True,
                        )

                        if result.returncode != 0:
                            st.error(f"Error generating PDF: {result.stderr}")
                        else:
                            with open("temp_report.pdf", "rb") as f:
                                pdf_data = f.read()
                                st.download_button(
                                    label="Download PDF Report",
                                    data=pdf_data,
                                    file_name="vulnerability_report.pdf",
                                    mime="application/pdf",
                                )
                    except FileNotFoundError:
                        st.error("pdflatex not found. Install a LaTeX distribution.")
                    except subprocess.CalledProcessError as e:
                        st.error(f"pdflatex failed: {e}")
                    finally:
                        for file_ext in [".tex", ".log", ".aux", ".pdf"]:
                            try:
                                os.remove(f"temp_report{file_ext}")
                            except FileNotFoundError:
                                pass
    else:
        st.error("Please provide either a code file or a repository URL.")