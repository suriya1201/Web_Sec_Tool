from dotenv import load_dotenv
import os
from zapv2 import ZAPv2
import time
import streamlit as st
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
import textwrap

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


def disable_passive_scanners(zap):
    zap.pscan.disable_all_scanners()  # Disable all passive scanners
    # Clear all existing alerts
    zap.core.delete_all_alerts()


def generate_pdf_report(alerts):
    """Generates a PDF report using reportlab."""
    pdf_path = "scans/consolidated_scan_results.pdf"

    c = canvas.Canvas(pdf_path, pagesize=letter)
    width, height = letter

    c.setFont("Helvetica-Bold", 18)
    c.setFillColor(colors.blue)
    c.drawString(100, height - 50, "ZAP Scan Results")
    c.setFillColor(colors.black)

    y_position = height - 80  # Initial Y position

    for alert in alerts:
        # Risk: Use color coding for risk level
        c.setFont("Helvetica-Bold", 12)
        risk_color = get_risk_color(alert["risk"])
        c.setFillColor(risk_color)
        wrapped_text = textwrap.fill(f"Risk: {alert['risk']}", width=80)
        y_position = _draw_text(c, wrapped_text, y_position, width)

        # Name
        c.setFont("Helvetica-Bold", 12)
        wrapped_text = textwrap.fill(f"Name: {alert['name']}", width=80)
        y_position = _draw_text(c, wrapped_text, y_position, width)

        c.setFillColor(colors.black)

        # URL
        c.setFont("Helvetica", 12)
        wrapped_text = textwrap.fill(f"URL: {alert['url']}", width=80)
        y_position = _draw_text(c, wrapped_text, y_position, width)

        # Description (long text)
        c.setFont("Helvetica", 12)
        wrapped_text = textwrap.fill(f"Description: {alert['description']}", width=80)
        y_position = _draw_text(c, wrapped_text, y_position, width)

        # Solution (formatted as bullet points)
        c.setFont("Helvetica", 12)
        wrapped_text = textwrap.fill(f"Solution: {alert['solution']}", width=80)
        y_position = _draw_text(c, wrapped_text, y_position, width)

        # Reference (formatted as a link)
        c.setFont("Helvetica-Oblique", 12)
        wrapped_text = textwrap.fill(f"Reference: {alert['reference']}", width=80)
        y_position = _draw_text(c, wrapped_text, y_position, width)

        # Divider line
        c.setFont("Helvetica", 10)
        c.setFillColor(colors.grey)
        c.drawString(100, y_position, "-" * 50)
        y_position -= 20

        if y_position < 50:  # Avoid writing too low
            c.showPage()
            c.setFont("Helvetica", 12)
            y_position = height - 50

    c.save()


def _draw_text(canvas, text, y_position, page_width):
    """Helper function to handle line wrapping and drawing text."""
    lines = text.split("\n")
    for line in lines:
        if y_position < 50:  # Avoid writing too low
            canvas.showPage()
            y_position = letter[1] - 50
        canvas.drawString(100, y_position, line)
        y_position -= 14  # Move down by 14px for the next line
    return y_position


def get_risk_color(risk_level):
    """Returns color based on the risk level."""
    if risk_level == "High":
        return colors.red
    elif risk_level == "Medium":
        return colors.orange
    elif risk_level == "Low":
        return colors.green
    elif risk_level == "Information":
        return colors.blue
    return colors.black  # Default to black for unknown risk levels


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

    with open("scans/zap_scan_results.txt", "w", encoding="utf-8") as file:
        for alert in alerts:
            alert_message = f"🛑 **[{alert['risk']}] {alert['name']}**\n🔗 **URL:** {alert['url']}\n\n"
            # alert_message = f"[{alert['risk']}] {alert['name']} - {alert['url']}\n"
            st.write(alert_message)
            file.write(alert_message)

    generate_pdf_report(alerts)

    st.success("Scanning completed. Results saved to consolidated_scan_results.pdf.")
