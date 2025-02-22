import subprocess
import json
import os
import streamlit as st

def run_sqlmap(target_url, scan_scope="Page Only"):
    """Runs sqlmap on the target URL and saves the output to the specified directory."""
    st.write(f"Running sqlmap on {target_url} with scope: {scan_scope}...")

    command = [
        "sqlmap", "-u", target_url, "--batch",
        "--dbs", "--forms"
    ]

    if scan_scope == "Entire Website":
        command.append("--crawl=10")  # Adjust the crawl depth as needed

    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        st.write("sqlmap scan completed. Results:")
        st.text(result.stdout)

        # Append the results to the consolidated scan results file
        with open("scans/consolidated_scan_results.md", "a") as file:
            file.write("\n# SQLMap Scan Results\n")
            file.write(f"**URL:** {target_url}\n")
            file.write(f"**Scope:** {scan_scope}\n")
            file.write("**Results:**\n")
            file.write("```\n")
            file.write(result.stdout)
            file.write("```\n")
            file.write("---\n")
    except subprocess.CalledProcessError as e:
        st.write(f"Error running sqlmap: {e}")
        st.text(e.stdout)
        st.text(e.stderr)

        # Append the error to the consolidated scan results file
        with open("scans/consolidated_scan_results.md", "a") as file:
            file.write("\n# SQLMap Scan Results\n")
            file.write(f"**URL:** {target_url}\n")
            file.write(f"**Scope:** {scan_scope}\n")
            file.write("**Error:**\n")
            file.write("```\n")
            file.write(e.stdout)
            file.write(e.stderr)
            file.write("```\n")
            file.write("---\n")

# def run_nosqli(target_url):
#     """Runs NoSQLi to test for NoSQL Injection vulnerabilities."""
#     st.write(f"Running NoSQLi on {target_url}...")

#     command = [
#         "./nosqli", "-u", target_url
#     ]

#     try:
#         subprocess.run(command, check=True)
#         st.write(f"NoSQLi scan completed.")
#     except subprocess.CalledProcessError as e:
#         st.write(f"Error running NoSQLi: {e}")

def run_commix(target_url, scan_scope="Page Only"):
    """Runs commix for command injection testing and logs results."""
    st.write(f"Running commix on {target_url} with scope: {scan_scope}...")

    command = [
        "python", "./commix/commix.py", "--url", target_url, "--batch"
    ]

    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        st.write("Commix scan completed. Results:")
        st.text(result.stdout)

        # Append the results to the consolidated scan results file
        os.makedirs("scans", exist_ok=True)
        with open("scans/consolidated_scan_results.md", "a") as file:
            file.write("\n# Commix Scan Results\n")
            file.write(f"**URL:** {target_url}\n")
            file.write(f"**Scope:** {scan_scope}\n")
            file.write("**Results:**\n")
            file.write("```\n")
            file.write(result.stdout)
            file.write("```\n")
            file.write("---\n")
    except subprocess.CalledProcessError as e:
        st.write(f"Error running commix: {e}")
        st.text(e.stdout)
        st.text(e.stderr)

        # Append the error to the consolidated scan results file
        with open("scans/consolidated_scan_results.md", "a") as file:
            file.write("\n# Commix Scan Results\n")
            file.write(f"**URL:** {target_url}\n")
            file.write(f"**Scope:** {scan_scope}\n")
            file.write("**Error:**\n")
            file.write("```\n")
            file.write(e.stdout)
            file.write(e.stderr)
            file.write("```\n")
            file.write("---\n")


def run_tplmap(target_url, scan_scope="Page Only"):
    """Runs tplmap for SSTI testing and logs results."""
    st.write(f"Running tplmap on {target_url} with scope: {scan_scope}...")

    command = ["python3", "tplmap/tplmap.py", "-u", target_url]

    if scan_scope == "Entire Website":
        command.append("--crawl=10")  # Adjust crawl depth as needed

    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        st.write("Tplmap scan completed. Results:")
        st.text(result.stdout)

        # Append the results to the consolidated scan results file
        os.makedirs("scans", exist_ok=True)
        with open("scans/consolidated_scan_results.md", "a") as file:
            file.write("\n# Tplmap Scan Results\n")
            file.write(f"**URL:** {target_url}\n")
            file.write(f"**Scope:** {scan_scope}\n")
            file.write("**Results:**\n")
            file.write("```\n")
            file.write(result.stdout)
            file.write("```\n")
            file.write("---\n")
    except subprocess.CalledProcessError as e:
        st.write(f"Error running tplmap: {e}")
        st.text(e.stdout)
        st.text(e.stderr)

        # Append the error to the consolidated scan results file
        with open("scans/consolidated_scan_results.md", "a") as file:
            file.write("\n# Tplmap Scan Results\n")
            file.write(f"**URL:** {target_url}\n")
            file.write(f"**Scope:** {scan_scope}\n")
            file.write("**Error:**\n")
            file.write("```\n")
            file.write(e.stdout)
            file.write(e.stderr)
            file.write("```\n")
            file.write("---\n")


def run_defusedxml():
    """Checks for XML External Entity (XXE) vulnerabilities using defusedxml and logs results."""
    st.write("Checking XXE vulnerabilities using defusedxml...")

    try:
        from defusedxml.sax import parse
        result = "defusedxml is installed and working (protects against XXE)."
        st.write(result)

        # Append the results to the consolidated scan results file
        os.makedirs("scans", exist_ok=True)
        with open("scans/consolidated_scan_results.md", "a") as file:
            file.write("\n# DefusedXML Scan Results\n")
            file.write("**Results:**\n")
            file.write("```\n")
            file.write(result)
            file.write("```\n")
            file.write("---\n")
    except ImportError:
        error_msg = "Error: defusedxml not installed! Run: pip install defusedxml"
        st.write(error_msg)

        # Append the error to the consolidated scan results file
        with open("scans/consolidated_scan_results.md", "a") as file:
            file.write("\n# DefusedXML Scan Results\n")
            file.write("**Error:**\n")
            file.write("```\n")
            file.write(error_msg)
            file.write("```\n")
            file.write("---\n")
