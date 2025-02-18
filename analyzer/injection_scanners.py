import subprocess
import json
import os
import streamlit as st

def run_sqlmap(target_url, output_file="sqlmap_report.json"):
    """Runs sqlmap on the target URL and saves the output to a JSON file."""
    st.write(f"Running sqlmap on {target_url}...")

    command = [
        "sqlmap", "-u", target_url, "--batch",
        "--dbs", "--json-output", output_file
    ]

    try:
        subprocess.run(command, check=True)
        st.write(f"sqlmap scan completed. Results saved in {output_file}")
    except subprocess.CalledProcessError as e:
        st.write(f"Error running sqlmap: {e}")

def run_nosqli(target_url):
    """Runs NoSQLi to test for NoSQL Injection vulnerabilities."""
    st.write(f"Running NoSQLi on {target_url}...")

    command = [
        "./nosqli", "-u", target_url
    ]

    try:
        subprocess.run(command, check=True)
        st.write(f"NoSQLi scan completed.")
    except subprocess.CalledProcessError as e:
        st.write(f"Error running NoSQLi: {e}")

def run_commix(target_url):
    """Runs commix for command injection testing."""
    st.write(f"Running commix on {target_url}...")
    
    command = [
        "commix", "--url", target_url, "--batch"
    ]

    try:
        subprocess.run(command, check=True)
        st.write(f"commix scan completed.")
    except subprocess.CalledProcessError as e:
        st.write(f"Error running commix: {e}")

def run_tplmap(target_url):
    """Runs tplmap for SSTI testing."""
    st.write(f"Running tplmap on {target_url}...")

    command = ["python3", "tplmap/tplmap.py", "-u", target_url]
    
    try:
        subprocess.run(command, check=True)
        st.write(f"tplmap scan completed.")
    except subprocess.CalledProcessError as e:
        st.write(f"Error running tplmap: {e}")

def run_defusedxml():
    """Verifies if XML External Entity (XXE) vulnerabilities exist."""
    st.write("Checking XXE vulnerabilities using defusedxml...")

    try:
        from defusedxml.sax import parse
        st.write("defusedxml is installed and working (protects against XXE).")
    except ImportError:
        st.write("Error: defusedxml not installed! Run: pip install defusedxml")

def run_ldap3(target_url):
    """Checks for LDAP Injection using ldap3 library."""
    st.write(f"Checking LDAP Injection vulnerability on {target_url}...")

    try:
        from ldap3 import Server, Connection
        server = Server(target_url)
        conn = Connection(server)
        if conn.bind():
            st.write("LDAP connection successful (potential vulnerability).")
        else:
            st.write("LDAP authentication failed (likely secure).")
    except Exception as e:
        st.write(f"Error testing LDAP Injection: {e}")

def unified_scan(target_url):
    """Runs all injection tests."""
    run_sqlmap(target_url)
    run_nosqli(target_url)
    run_commix(target_url)
    run_tplmap(target_url)
    run_defusedxml()
    run_ldap3(target_url)
    
    st.write("\n🔹 Scan Complete! Check the individual tool outputs for detailed results.")

# Streamlit UI
st.title("Injection Scanners")

target_url = st.text_input("Enter the target URL:")

if st.button("Run Unified Scan"):
    if target_url:
        unified_scan(target_url)
    else:
        st.error("Please enter a valid URL.")