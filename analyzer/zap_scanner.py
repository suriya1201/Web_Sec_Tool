from dotenv import load_dotenv
import os
from zapv2 import ZAPv2
import time
import streamlit as st

load_dotenv()


def configure_active_scanners(zap):
    zap.ascan.disable_all_scanners()

    # Enable Injection and Broken Access Control related scanners
    injection_ids = [
        "40018",
        "40019",
        "40020",
        "40021",
        "40022",
        "40024",
        "40027",
        "90019",
        "90020",
        "90021",
        "90035",
        "90036",
        "40003",
        "90017",
        "90029",
        "40012",
        "40014",
        "40026",
        "40016",
        "40017",
    ]  # IDs for Injection
    bac_ids = ["6", "10104", "40035", "0", "40028"]  # IDs for Broken Access Control

    st.write("Setting up Injection and Broken Access Control scanners...")

    # Enabling Injection and BAC scanners
    for scanner_id in injection_ids + bac_ids:
        zap.ascan.set_scanner_alert_threshold(
            scanner_id, "MEDIUM"
        )  # Adjust threshold as needed
        zap.ascan.set_scanner_attack_strength(
            scanner_id, "HIGH"
        )  # Set strength for more aggressive checks

    st.write(
        "Configured ZAP to scan only for Injection and Broken Access Control issues."
    )


def disable_passive_scanners(zap):
    zap.pscan.disable_all_scanners()  # Disable all passive scanners
    # Clear all existing alerts
    zap.core.delete_all_alerts()


def scan_url(target, scope):
    # Initialize ZAP API
    api_key = os.getenv("ZAP_API_KEY")
    if not api_key:
        st.error("ZAP_API_KEY not found in environment variables.")
        return

    zap = ZAPv2(
        proxies={"http": "http://localhost:8081", "https": "http://localhost:8081"},
        apikey=api_key,
    )

    # disable_passive_scanners(zap)
    configure_active_scanners(zap)

    # Page Only: Limit Spider to only the given page (no children)
    if scope == "Page Only":
        try:
            st.write(f"Starting Spider scan on: {target} (Page Only)")
            zap.spider.scan(url=target, maxchildren=0)
            time.sleep(5)  # Reduce wait time to give the spider time to start
        except Exception as e:
            st.error(f"Error starting Spider scan: {e}")
            return  # Stop if Spider scan fails

    # Entire Website: Crawl the whole website, follow all links and pages
    elif scope == "Entire Website":
        try:
            st.write(f"Starting Spider scan on: {target} (Entire Website)")
            zap.spider.scan(url=target, maxchildren=2)
            time.sleep(5)  # Reduce wait time to give the spider time to start
        except Exception as e:
            st.error(f"Error starting Spider scan: {e}")
            return  # Stop if Spider scan fails

    # Wait for Spider scan to complete
    while int(zap.spider.status()) < 100:
        time.sleep(2)
    st.write("Spider scan completed. Starting Active scan.")

    try:
        zap.ascan.scan(url=target)
    except Exception as e:
        st.error(f"Error starting Active scan: {e}")
        return  # Stop if Active scan fails

    progress = st.progress(0)
    while int(zap.ascan.status()) < 100:
        progress.progress(int(zap.ascan.status()))
        time.sleep(5)
    progress.progress(100)
    st.write("Active scan completed. Fetching alerts...")

    try:
        alerts = zap.core.alerts(baseurl=target)
    except Exception as e:
        st.error(f"Error fetching alerts: {e}")
        return  # Stop if alerts can't be fetched

    with open("zap_scan_results.txt", "w") as file:
        for alert in alerts:
            alert_message = f"[{alert['risk']}] {alert['name']} - {alert['url']}\n"
            st.write(alert_message)
            file.write(alert_message)

    st.success("Scanning completed. Results saved to zap_scan_results.txt.")
