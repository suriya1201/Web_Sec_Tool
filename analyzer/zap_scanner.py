from dotenv import load_dotenv
import os
from zapv2 import ZAPv2
import time
import streamlit as st

load_dotenv()


def scan_url(target, scope):
    # Initialize ZAP API
    api_key = os.getenv("ZAP_API_KEY")
    if not api_key:
        st.error("ZAP_API_KEY not found in environment variables.")
        return

    zap = ZAPv2(
        proxies={"http": "http://localhost:8081", "https": "http://localhost:8081"},
        apikey=os.getenv("ZAP_API_KEY"),
    )

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
