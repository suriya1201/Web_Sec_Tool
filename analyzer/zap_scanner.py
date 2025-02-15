from dotenv import load_dotenv
import os
from zapv2 import ZAPv2
import time
import streamlit as st

load_dotenv()


def scan_url(target, scope):
    # Initialize ZAP API
    zap = ZAPv2(
        proxies={"http": "http://localhost:8081", "https": "http://localhost:8081"},
        apikey=os.getenv("ZAP_API_KEY"),
    )

    # Show starting scan message in the main content (not in sidebar)
    st.write(f"Starting Spider scan on: {target}")

    # Page Only: Limit Spider to only the given page (no children)
    if scope == "Page Only":
        zap.spider.scan(
            url=target, maxchildren=0
        )  # Only scan the given URL, no recursion or crawling other pages
        time.sleep(5)  # Reduce wait time to give the spider time to start

    # Entire Website: Crawl the whole website, follow all links and pages
    elif scope == "Entire Website":
        # Limit the depth to 2 (instead of crawling all linked pages) or a smaller number
        zap.spider.scan(url=target, maxchildren=2)  # Limit depth of the crawl
        time.sleep(5)  # Wait for the spider to start

    st.write("Spider scan completed. Starting Active scan.")

    # Active scan: Run without custom rules to optimize scan time
    zap.ascan.scan(url=target)

    while int(zap.ascan.status()) < 100:
        st.write(f"Active scan in progress: {zap.ascan.status()}%")
        time.sleep(10)

    st.write("Active scan completed. Fetching alerts...")
    alerts = zap.core.alerts(baseurl=target)

    with open("zap_scan_results.txt", "w") as file:
        for alert in alerts:
            alert_message = f"[{alert['risk']}] {alert['name']} - {alert['url']}\n"
            st.write(alert_message)
            file.write(alert_message)

    st.success("Scanning completed. Results saved to zap_scan_results.txt.")
