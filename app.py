import streamlit as st
import httpx
import asyncio
from models.vulnerability import VulnerabilityReport
from utils.latex_generator import LatexGenerator  # Keep for now
import os

# --- Helper Functions ---
def is_valid_repo_url(url: str) -> bool:
    return url.startswith("http://") or url.startswith("https://")

def is_valid_scan_url(url: str) -> bool:
    return url.startswith("http://") or url.startswith("https://")

# --- Analysis Logic ---
async def analyze_code_file(files):
    print("--- Starting analyze_code_file (Streamlit) ---")
    async with httpx.AsyncClient(timeout=30.0) as client:
        files_data = []
        for file in files:
            print(f"  Processing file: {file.name}")
            files_data.append(('files', (file.name, file.getvalue(), file.type)))
        print(f"  Files data prepared: {files_data}")

        try:
            print("  Sending POST request to FastAPI...")
            response = await client.post("http://127.0.0.1:8001/analyze/file", files=files_data)
            print(f"  Received response. Status: {response.status_code}")
            response.raise_for_status()
            report = VulnerabilityReport(**response.json())
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
    print("--- Starting analyze_repo (Streamlit) ---")
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
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
            report = VulnerabilityReport(**response.json())
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
            print("--- Finishing analyze_repo (Streamlit) ---")

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
        scan_button = st.button("Start Scan")  # Still here, but does nothing

# --- Main Analysis Execution and Display ---
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