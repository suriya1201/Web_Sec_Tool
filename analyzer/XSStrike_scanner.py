from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.pdfgen import canvas
import os
import subprocess
import streamlit as st
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
from PyPDF2 import PdfReader, PdfWriter
import re


def generate_pdf_report(target_url, scan_scope, results):
    """Generates a PDF report for XSStrike scan results."""
    pdf_path = "scans/XSStrike_scan_report.pdf"

    # Ensure the "scans" directory exists
    if not os.path.exists("scans"):
        os.makedirs("scans")

    # Create a new PDF canvas
    c = canvas.Canvas(pdf_path, pagesize=letter)
    page_width, page_height = letter

    # Title
    c.setFont("Helvetica-Bold", 18)
    c.setFillColor(colors.blue)
    c.drawString(100, page_height - 50, "XSStrike Scan Report")
    c.setFillColor(colors.black)

    # Metadata
    c.setFont("Helvetica", 12)
    c.drawString(100, page_height - 80, f"Target URL: {target_url}")
    c.drawString(100, page_height - 100, f"Scope: {scan_scope}")

    # Results
    y_position = page_height - 140
    c.setFont("Helvetica", 10)
    y_position = _draw_text(c, results, y_position, page_width)

    # Save the PDF
    c.save()


def _draw_text(c, text, y_position, page_width):
    """Helper function to handle line wrapping and drawing text."""
    lines = text.split("\n")
    for line in lines:
        # Split line if it's wider than the page width
        while len(line) > 0:
            if y_position < 50:  # Avoid writing too low
                c.showPage()
                y_position = letter[1] - 50  # Reset y_position for the new page
                c.setFont("Helvetica", 10)  # Reapply font on new page

            # Break the line if it's too long for the page width
            if c.stringWidth(line, "Helvetica", 10) > page_width - 200:
                split_index = len(line)  # Assume we print all
                while (
                    c.stringWidth(line[:split_index], "Helvetica", 10)
                    > page_width - 200
                ):
                    split_index -= 1
                c.drawString(100, y_position, line[:split_index])
                line = line[split_index:]  # Remaining text
            else:
                c.drawString(100, y_position, line)
                line = ""

            y_position -= 14  # Move down for the next line
    return y_position


def append_XSStrike_to_pdf(pdf_path, XSStrike_pdf_path, output_pdf_path):
    # Create PDF reader and writer objects
    pdf_reader = PdfReader(pdf_path)
    XSStrike_reader = PdfReader(XSStrike_pdf_path)
    pdf_writer = PdfWriter()

    for page_num in range(len(pdf_reader.pages)):
        pdf_writer.add_page(pdf_reader.pages[page_num])

    # Add all pages from the XSStrike PDF
    for page_num in range(len(XSStrike_reader.pages)):
        pdf_writer.add_page(XSStrike_reader.pages[page_num])

    # Write the combined PDF to a file
    with open(output_pdf_path, "wb") as output_pdf:
        pdf_writer.write(output_pdf)

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


        generate_pdf_report(target_url, scan_depth, result.stdout)
        pdf_path = "scans/consolidated_scan_results.pdf"
        XSStrike_pdf_path = "scans/XSStrike_scan_report.pdf"
        output_pdf_path = "scans/consolidated_scan_results.pdf"
        append_XSStrike_to_pdf(pdf_path, XSStrike_pdf_path, output_pdf_path)

    except subprocess.CalledProcessError as e:
        st.write(f"Error running XSStrike: {e}")
        st.text(e.stdout)
        st.text(e.stderr)


        pdf_path = "scans/consolidated_scan_results.pdf"
        generate_pdf_report(target_url, scan_depth, e.stdout)
        XSStrike_pdf_path = "scans/XSStrike_scan_report.pdf"
        output_pdf_path = "scans/consolidated_scan_results.pdf"
        append_XSStrike_to_pdf(pdf_path, XSStrike_pdf_path, output_pdf_path)