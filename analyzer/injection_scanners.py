import subprocess
import json
import os
import streamlit as st

def run_sqlmap(target_url, zap_proxy="http://localhost:8081"):
    """Runs sqlmap on the target URL using ZAP Proxy and saves the output to the specified directory."""
    st.write(f"Running sqlmap on {target_url} using ZAP Proxy at {zap_proxy}...")

    command = [
        "sqlmap", "-u", target_url, "--batch",
        "--dbs", "--proxy", zap_proxy
    ]

    try:
        subprocess.run(command, check=True)
        st.write(f"sqlmap scan completed. Results saved in {output_dir}")
    except subprocess.CalledProcessError as e:
        st.write(f"Error running sqlmap: {e}")

# Example usage
if __name__ == "__main__":
    target_url = "http://localhost/bWAPP/sqli_1.php?title=asas&action=search"
    run_sqlmap(target_url)


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

# def run_commix(target_url):
#     """Runs commix for command injection testing."""
#     st.write(f"Running commix on {target_url}...")
    
#     command = [
#         "commix", "--url", target_url, "--batch"
#     ]

#     try:
#         subprocess.run(command, check=True)
#         st.write(f"commix scan completed.")
#     except subprocess.CalledProcessError as e:
#         st.write(f"Error running commix: {e}")

# def run_tplmap(target_url):
#     """Runs tplmap for SSTI testing."""
#     st.write(f"Running tplmap on {target_url}...")

#     command = ["python3", "tplmap/tplmap.py", "-u", target_url]
    
#     try:
#         subprocess.run(command, check=True)
#         st.write(f"tplmap scan completed.")
#     except subprocess.CalledProcessError as e:
#         st.write(f"Error running tplmap: {e}")

# def run_defusedxml():
#     """Verifies if XML External Entity (XXE) vulnerabilities exist."""
#     st.write("Checking XXE vulnerabilities using defusedxml...")

#     try:
#         from defusedxml.sax import parse
#         st.write("defusedxml is installed and working (protects against XXE).")
#     except ImportError:
#         st.write("Error: defusedxml not installed! Run: pip install defusedxml")

# def run_ldap3(target_url):
#     """Checks for LDAP Injection using ldap3 library."""
#     st.write(f"Checking LDAP Injection vulnerability on {target_url}...")

#     try:
#         from ldap3 import Server, Connection
#         server = Server(target_url)
#         conn = Connection(server)
#         if conn.bind():
#             st.write("LDAP connection successful (potential vulnerability).")
#         else:
#             st.write("LDAP authentication failed (likely secure).")
#     except Exception as e:
#         st.write(f"Error testing LDAP Injection: {e}")
