import subprocess
import os
import streamlit as st
import re

def run_sqlmap(target_url, scan_depth=1):
    """Runs sqlmap on the target URL and saves the output to the specified directory."""
    st.write(f"Running sqlmap on {target_url} with depth: {scan_depth}...")

    command = [
        "sqlmap", "-u", target_url, "--batch",
        "--dbs", "--forms", f"--crawl={scan_depth}"
    ]

    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        st.write("sqlmap scan completed. Results:")
        st.text(result.stdout)

        # Append the results to the consolidated scan results file
        with open("scans/consolidated_scan_results.md", "a") as file:
            file.write("\n# SQLMap Scan Results\n")
            file.write(f"**URL:** {target_url}\n")
            file.write(f"**Depth:** {scan_depth}\n")
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
            file.write(f"**Depth:** {scan_depth}\n")
            file.write("**Error:**\n")
            file.write("```\n")
            file.write(e.stdout)
            file.write(e.stderr)
            file.write("```\n")
            file.write("---\n")

def remove_ansi_escape_sequences(text):
    """Remove ANSI escape sequences from the text."""
    ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F][0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

def run_XSStrike(target_url, scan_depth=1):
    """Runs XSStrike to test for Cross-Site Scripting (XSS) vulnerabilities and logs results."""
    st.write(f"Running XSStrike on {target_url} with depth: {scan_depth}...")

    command = [
        "python", "./XSStrike/xsstrike.py", "--url", target_url,
        "--crawl", "-l", str(scan_depth)
    ]

    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True, encoding='utf-8')
        

        # Remove ANSI escape sequences from the output
        clean_output = remove_ansi_escape_sequences(result.stdout)
        st.write("XSStrike scan completed. Results:")
        st.text(clean_output)

        # Append the results to the consolidated scan results file
        os.makedirs("scans", exist_ok=True)
        with open("scans/consolidated_scan_results.md", "a", encoding='utf-8') as file:
            file.write("\n# XSStrike Scan Results\n")
            file.write(f"**URL:** {target_url}\n")
            file.write(f"**Depth:** {scan_depth}\n")
            file.write("**Results:**\n")
            file.write("```\n")
            file.write(clean_output)
            file.write("```\n")
            file.write("---\n")
    except subprocess.CalledProcessError as e:
        st.write(f"Error running XSStrike: {e}")
        st.text(e.stdout)
        st.text(e.stderr)

        # Remove ANSI escape sequences from the error output
        clean_stdout = remove_ansi_escape_sequences(e.stdout)
        clean_stderr = remove_ansi_escape_sequences(e.stderr)

        # Append the error to the consolidated scan results file
        with open("scans/consolidated_scan_results.md", "a", encoding='utf-8') as file:
            file.write("\n# XSStrike Scan Results\n")
            file.write(f"**URL:** {target_url}\n")
            file.write(f"**Depth:** {scan_depth}\n")
            file.write("**Error:**\n")
            file.write("```\n")
            file.write(clean_stdout)
            file.write(clean_stderr)
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
            
def run_commix(target_url, scan_depth=1):
    """Runs commix for command injection testing and logs results."""
    st.write(f"Running commix on {target_url} with depth: {scan_depth}...")

    command = [
        "python", "./commix/commix.py", "--url", target_url, "--batch",
        f"--crawl={scan_depth}"
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
            file.write(f"**Depth:** {scan_depth}\n")
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
            file.write(f"**Depth:** {scan_depth}\n")
            file.write("**Error:**\n")
            file.write("```\n")
            file.write(e.stdout)
            file.write(e.stderr)
            file.write("```\n")
            file.write("---\n")

def run_sstimap(target_url, scan_depth=1):
    """Runs SSTImap to test for Server-Side Template Injection vulnerabilities and logs results."""
    st.write(f"Running SSTImap on {target_url} with depth: {scan_depth}...")

    command = [
        "python", "./SSTImap/sstimap.py", "--url", target_url, "--no-color", "--forms",
        f"--crawl={scan_depth}"
    ]

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
            file.write(f"**Depth:** {scan_depth}\n")
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
            file.write(f"**Depth:** {scan_depth}\n")
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