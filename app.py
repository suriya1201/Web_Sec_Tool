import streamlit as st
import httpx
import asyncio
from models.vulnerability import VulnerabilityReport
from utils.latex_generator import LatexGenerator  # Keep for now
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
    return url.startswith("http://") or url.startswith("https://")

def is_valid_scan_url(url: str) -> bool:
    return url.startswith("http://") or url.startswith("https://")

# --- UI Setup ---
st.set_page_config(page_title="INSPECTIFY", layout="wide")
st.title("INSPECTIFY")
st.write("Tool for analyzing code and scanning web applications for vulnerabilities.")

with st.sidebar:
    st.markdown("<h1 style='font-size: 3em;'>INSPECTIFY</h1>", unsafe_allow_html=True)
    
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
                    "py", "js", "java", "cpp", "c", "cs", "go",
                    "rb", "php", "rs", "swift", "kt", "scala"
                ],
                accept_multiple_files=True,
            )
            if uploaded_files:
                st.write(f"You have uploaded {len(uploaded_files)} file(s).")
            repo_url = None
            branch = None
            scan_depth = None

        else:  # input_type == "Provide Repository URL"
            repo_url = st.text_input("Repository URL")
            branch = st.text_input("Branch", "main")
            scan_depth = st.number_input("Scan Depth", min_value=1, value=3)
            uploaded_files = None

        analyze_button = st.button("Analyze")

    with tabs[1]:
        st.write("Vulnerability Scanning (Injection and Broken Access Control)")
        target_url = st.text_input("Enter URL to scan")
        scan_options = st.radio("Scan Options", ["Page Only", "Entire Website"])

        # # Initialize session state for advanced options visibility
        # if "show_advanced_options" not in st.session_state:
        #     st.session_state.show_advanced_options = False

        # Toggle advanced options visibility
        # if st.button("Advanced Options"):
        #     st.session_state.show_advanced_options = not st.session_state.show_advanced_options

        # Add an expander for advanced options
        # if st.session_state.show_advanced_options:
        #     with st.expander("Advanced Options"):
        #         st.write("Here you can configure advanced scan options.")
        #         # Add your advanced options here
        #         st.checkbox("Option 1")
        #         st.checkbox("Option 2")
        #         st.checkbox("Option 3")

        # Center the "Start Scan" button and make it fill the space
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            scan_button = st.button("Start Scan", use_container_width=True)

if scan_button:
    if target_url:
        if is_valid_scan_url(target_url):
            st.header("OWASP ZAP Scan:")
            st.write(f"Scanning URL: {target_url} with option: {scan_options}")
            scan_url(target_url, scan_options)
            st.markdown("---")
            st.header("Wapiti Scan:")
            run_wapiti(target_url, scan_options)  # Run Wapiti after ZAP with scan options
            st.markdown("---")


            # Change the scan button to a download button
            with open("scans/consolidated_scan_results.md", "r") as file:
                consolidated_results = file.read()

            st.download_button(
                label="Download Consolidated Scan Results",
                data=consolidated_results,
                file_name="consolidated_scan_results.md",
                mime="text/markdown",
            )
        else:
            st.error("Invalid URL. Please enter a valid URL starting with http:// or https://.")
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
            if report:
                # --- Display Results Directly on the Page ---
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
                    f"{report.risk_score:.2f}" if report.risk_score is not None else "N/A"
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
                            st.write("**Proof of Concept:**")  # Just write the heading
                            st.code(vuln.proof_of_concept, language="python")  # Display the code

                        if vuln.secure_code_example:
                            st.write("**Secure Code Example:**")  # Just write the heading
                            st.code(vuln.secure_code_example, language="python")  # Display the code


                st.subheader("Chained Vulnerabilities")
                for chain in report.chained_vulnerabilities:
                    with st.expander(f"Chain - Combined Severity: {chain.combined_severity}"):
                        st.write(f"**Attack Path:** {chain.attack_path}")
                        st.write(f"**Likelihood:** {chain.likelihood}")
                        st.write("**Prerequisites:**")
                        for prereq in chain.prerequisites:
                            st.write(f"- {prereq}")
                        st.write(f"**Mitigation Priority:** {chain.mitigation_priority}")

    elif input_type == "Provide Repository URL" and repo_url:
        if not is_valid_repo_url(repo_url):
            st.error("Invalid repository URL.")
        else:
            with st.spinner("Analyzing repository..."):
                report = asyncio.run(analyze_repo(repo_url, branch, scan_depth))
                if report:
                    # --- Display Results Directly on the Page ---
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
                        f"{report.risk_score:.2f}" if report.risk_score is not None else "N/A"
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
                                st.write("**Proof of Concept:**")  # Just write the heading
                                st.code(vuln.proof_of_concept, language="python")  # Display the code

                            if vuln.secure_code_example:
                                st.write("**Secure Code Example:**")  # Just write the heading
                                st.code(vuln.secure_code_example, language="python")  # Display the code

                    st.subheader("Chained Vulnerabilities")
                    for chain in report.chained_vulnerabilities:
                        with st.expander(f"Chain - Combined Severity: {chain.combined_severity}"):
                            st.write(f"**Attack Path:** {chain.attack_path}")
                            st.write(f"**Likelihood:** {chain.likelihood}")
                            st.write("**Prerequisites:**")
                            for prereq in chain.prerequisites:
                                st.write(f"- {prereq}")
                            st.write(f"**Mitigation Priority:** {chain.mitigation_priority}")

    else:
        st.error("Please provide either a code file or a repository URL.")