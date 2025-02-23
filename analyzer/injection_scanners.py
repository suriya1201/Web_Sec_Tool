import subprocess
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


def run_XSStrike(target_url, scan_scope="Page Only"):
    """Runs XSStrike to test for Cross-Site Scripting (XSS) vulnerabilities and logs results."""
    st.write(f"Running XSStrike on {target_url} with scope: {scan_scope}...")

    command = [
        "python", "./XSStrike/xsstrike.py", "--url", target_url
    ]

    if scan_scope == "Entire Website":
        command.append("--crawl -l 10")  # Adjust the crawl depth as needed

    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        st.write("XSStrike scan completed. Results:")
        st.text(result.stdout)

        # Append the results to the consolidated scan results file
        os.makedirs("scans", exist_ok=True)
        with open("scans/consolidated_scan_results.md", "a", encoding='utf-8') as file:
            file.write("\n# XSStrike Scan Results\n")
            file.write(f"**URL:** {target_url}\n")
            file.write(f"**Scope:** {scan_scope}\n")
            file.write("**Results:**\n")
            file.write("```\n")
            file.write(result.stdout)
            file.write("```\n")
            file.write("---\n")
    except subprocess.CalledProcessError as e:
        st.write(f"Error running XSStrike: {e}")
        st.text(e.stdout)
        st.text(e.stderr)

        # Append the error to the consolidated scan results file
        with open("scans/consolidated_scan_results.md", "a", encoding='utf-8') as file:
            file.write("\n# XSStrike Scan Results\n")
            file.write(f"**URL:** {target_url}\n")
            file.write(f"**Scope:** {scan_scope}\n")
            file.write("**Error:**\n")
            file.write("```\n")
            file.write(e.stdout)
            file.write(e.stderr)
            file.write("```\n")
            file.write("---\n")
    except Exception as e:
        st.write(f"Unexpected error: {e}")
        st.text(str(e))

        # Append the unexpected error to the consolidated scan results file
        with open("scans/consolidated_scan_results.md", "a", encoding='utf-8') as file:
            file.write("\n# XSStrike Scan Results\n")
            file.write(f"**URL:** {target_url}\n")
            file.write("**Unexpected Error:**\n")
            file.write("```\n")
            file.write(str(e))
            file.write("```\n")
            file.write("---\n")


def run_commix(target_url, scan_scope="Page Only"):
    """Runs commix for command injection testing and logs results."""
    st.write(f"Running commix on {target_url} with scope: {scan_scope}...")

    command = [
        "python", "./commix/commix.py", "--url", target_url, "--batch"
    ]

    if scan_scope == "Entire Website":
        command.append("--crawl=10")  # Adjust the crawl depth as needed

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


def run_sstimap(target_url, scan_scope="Page Only"):
    """Runs SSTImap to test for Server-Side Template Injection vulnerabilities and logs results."""
    st.write(f"Running SSTImap on {target_url}...")

    command = [
        "python", "./SSTImap/sstimap.py", "--url", target_url, "--no-color", "--forms"
    ]
    if scan_scope == "Entire Website":
        command.append("--crawl=10")  # Adjust the crawl depth as needed

    # Set the PYTHONIOENCODING environment variable to utf-8
    env = os.environ.copy()
    env['PYTHONIOENCODING'] = 'utf-8'

    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True, encoding='utf-8', env=env)
        st.write("SSTImap scan completed. Results:")
        st.text(result.stdout)

        # Append the results to the consolidated scan results file
        os.makedirs("scans", exist_ok=True)
        with open("scans/consolidated_scan_results.md", "a", encoding='utf-8') as file:
            file.write("\n# SSTImap Scan Results\n")
            file.write(f"**URL:** {target_url}\n")
            file.write("**Results:**\n")
            file.write("```\n")
            file.write(result.stdout)
            file.write("```\n")
            file.write("---\n")
    except subprocess.CalledProcessError as e:
        st.write(f"Error running SSTImap: {e}")
        st.text(e.stdout)
        st.text(e.stderr)

        # Append the error to the consolidated scan results file
        with open("scans/consolidated_scan_results.md", "a", encoding='utf-8') as file:
            file.write("\n# SSTImap Scan Results\n")
            file.write(f"**URL:** {target_url}\n")
            file.write("**Error:**\n")
            file.write("```\n")
            file.write(e.stdout)
            file.write(e.stderr)
            file.write("```\n")
            file.write("---\n")
    except Exception as e:
        st.write(f"Unexpected error: {e}")
        st.text(str(e))

        # Append the unexpected error to the consolidated scan results file
        with open("scans/consolidated_scan_results.md", "a", encoding='utf-8') as file:
            file.write("\n# SSTImap Scan Results\n")
            file.write(f"**URL:** {target_url}\n")
            file.write("**Unexpected Error:**\n")
            file.write("```\n")
            file.write(str(e))
            file.write("```\n")
            file.write("---\n")

