import subprocess
import os
import json
import streamlit as st
import time

def run_wapiti(target_url, scan_scope):
    try:
        st.write(f"Starting Wapiti scan on: {target_url}")
        # Set the PYTHONIOENCODING environment variable to utf-8
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        
        # Specify the modules to run for injection and broken access control vulnerabilities
        modules = [
                "crlf", "exec", "ldap", "log4shell", "sql", "spring4shell", 
                "ssrf", "timesql", "xss", "xxe",  # Injection-related modules
                "csrf", "file", "htaccess", "http_headers", "redirect", 
                "takeover", "upload"  # BAC-related modules
            ]
        
        # Determine the scope of the scan
        if scan_scope == "Entire Website":
            scope_option = "--scope=domain"
        else:
            scope_option = "--scope=page"
        
        # Initialize the progress bar
        progress_bar = st.progress(0)
        progress = 0
        
        # Run the Wapiti scan in a subprocess
        process = subprocess.Popen(
            ["wapiti", "-u", target_url, "-f", "json", "-o", "scans/wapiti_scan_results.json", "-m", ",".join(modules), "-v", "1", scope_option],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env  # Pass the modified environment
        )
        
        # Monitor the progress of the scan
        while process.poll() is None:
            time.sleep(1)  # Wait for a second before checking the progress again
            # Update the progress bar (this is a simple example, you can implement a more accurate progress calculation)
            progress = min(progress + 5, 100)
            progress_bar.progress(progress)
        
        # Wait for the process to complete
        stdout, stderr = process.communicate()
        
        # Update the progress bar to 100% after the scan is complete
        progress_bar.progress(100)
        
        st.write("Wapiti scan completed.")
        
        # Read the JSON results
        with open("scans/wapiti_scan_results.json", "r") as file:
            wapiti_results = json.load(file)
        
        # Extract the vulnerabilities section
        vulnerabilities = wapiti_results.get("vulnerabilities", {})
        
        # Filter out empty vulnerabilities
        filtered_vulnerabilities = {k: v for k, v in vulnerabilities.items() if v}
        
        # Display the filtered vulnerabilities section in a nicer format
        st.write("Vulnerabilities found:")
        with open("scans/consolidated_scan_results.md", "a") as output_file:
            output_file.write("# Wapiti Scan Results\n")
            for vuln_type, vuln_list in filtered_vulnerabilities.items():
                st.subheader(vuln_type)
                output_file.write(f"## {vuln_type}\n")
                for vuln in vuln_list:
                    st.markdown(f"**Path:** {vuln.get('path', 'N/A')}")
                    output_file.write(f"**Path:** {vuln.get('path', 'N/A')}\n")
                    st.markdown(f"**Method:** {vuln.get('method', 'N/A')}")
                    output_file.write(f"**Method:** {vuln.get('method', 'N/A')}\n")
                    st.markdown(f"**Info:** {vuln.get('info', 'N/A')}")
                    output_file.write(f"**Info:** {vuln.get('info', 'N/A')}\n")
                    st.markdown(f"**Level:** {vuln.get('level', 'N/A')}")
                    output_file.write(f"**Level:** {vuln.get('level', 'N/A')}\n")
                    st.markdown(f"**Parameter:** {vuln.get('parameter', 'N/A')}")
                    output_file.write(f"**Parameter:** {vuln.get('parameter', 'N/A')}\n")
                    st.markdown(f"**Referer:** {vuln.get('referer', 'N/A')}")
                    output_file.write(f"**Referer:** {vuln.get('referer', 'N/A')}\n")
                    st.markdown(f"**Module:** {vuln.get('module', 'N/A')}")
                    output_file.write(f"**Module:** {vuln.get('module', 'N/A')}\n")
                    st.markdown(f"**HTTP Request:**")
                    st.code(vuln.get('http_request', 'N/A'))
                    output_file.write(f"**HTTP Request:**\n```\n{vuln.get('http_request', 'N/A')}\n```\n")
                    st.markdown(f"**CURL Command:**")
                    st.code(vuln.get('curl_command', 'N/A'))
                    output_file.write(f"**CURL Command:**\n```\n{vuln.get('curl_command', 'N/A')}\n```\n")
                    st.markdown("---")
                    output_file.write("---\n")
        
        return filtered_vulnerabilities
    except subprocess.CalledProcessError as e:
        st.error(f"Wapiti scan failed: {e.stderr}")
        return None
    except Exception as e:
        st.error(f"An error occurred during Wapiti scan: {e}")
        return None