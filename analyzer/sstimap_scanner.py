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


def generate_pdf_report(target_url, scan_scope, results):
    pdf_path = "scans/sstimap_scan_report.pdf"

    # Ensure the "scans" directory exists
    if not os.path.exists("scans"):
        os.makedirs("scans")

    # Create a new PDF canvas
    c = canvas.Canvas(pdf_path, pagesize=letter)
    page_width, page_height = letter

    # Title
    c.setFont("Helvetica-Bold", 18)
    c.setFillColor(colors.blue)
    c.drawString(100, page_height - 50, "Sstimap Scan Report")
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


def append_sstimap_to_pdf(pdf_path, sstimap_pdf_path, output_pdf_path):
    # Create PDF reader and writer objects
    pdf_reader = PdfReader(pdf_path)
    sstimap_reader = PdfReader(sstimap_pdf_path)
    pdf_writer = PdfWriter()

    for page_num in range(len(pdf_reader.pages)):
        pdf_writer.add_page(pdf_reader.pages[page_num])

    for page_num in range(len(sstimap_reader.pages)):
        pdf_writer.add_page(sstimap_reader.pages[page_num])

    with open(output_pdf_path, "wb") as output_pdf:
        pdf_writer.write(output_pdf)


def run_sstimap(target_url, scan_scope="Page Only"):
    """Runs SSTImap to test for Server-Side Template Injection vulnerabilities and logs results."""
    st.write(f"Running SSTImap on {target_url}...")

    command = [
        "python",
        "./SSTImap/sstimap.py",
        "--url",
        target_url,
        "--no-color",
        "--forms",
    ]
    if scan_scope == "Entire Website":
        command.append("--crawl=10")  # Adjust the crawl depth as needed

    # Set the PYTHONIOENCODING environment variable to utf-8
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"

    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=env,
        )
        st.write("SSTImap scan completed. Results:")
        st.text(result.stdout)

        # Append the results to the consolidated scan results file
        os.makedirs("scans", exist_ok=True)
        with open("scans/consolidated_scan_results.md", "a", encoding="utf-8") as file:
            file.write("\n# SSTImap Scan Results\n")
            file.write(f"**URL:** {target_url}\n")
            file.write("**Results:**\n")
            file.write("```\n")
            file.write(result.stdout)
            file.write("```\n")
            file.write("---\n")

        pdf_path = "scans/consolidated_scan_results.pdf"
        generate_pdf_report(target_url, scan_scope, result.stdout)
        sstimap_pdf_path = "scans/sstimap_scan_report.pdf"
        output_pdf_path = "scans/consolidated_scan_results.pdf"
        append_sstimap_to_pdf(pdf_path, sstimap_pdf_path, output_pdf_path)

    except subprocess.CalledProcessError as e:
        st.write(f"Error running SSTImap: {e}")
        st.text(e.stdout)
        st.text(e.stderr)

        # Append the error to the consolidated scan results file
        with open("scans/consolidated_scan_results.md", "a", encoding="utf-8") as file:
            file.write("\n# SSTImap Scan Results\n")
            file.write(f"**URL:** {target_url}\n")
            file.write("**Error:**\n")
            file.write("```\n")
            file.write(e.stdout)
            file.write(e.stderr)
            file.write("```\n")
            file.write("---\n")

        generate_pdf_report(target_url, scan_scope, e.stdout)
        pdf_path = "scans/consolidated_scan_results.pdf"
        sstimap_pdf_path = "scans/sstimap_scan_report.pdf"
        output_pdf_path = "scans/consolidated_scan_results.pdf"
        append_sstimap_to_pdf(pdf_path, sstimap_pdf_path, output_pdf_path)

    except Exception as e:
        st.write(f"Unexpected error: {e}")
        st.text(str(e))

        # Append the unexpected error to the consolidated scan results file
        with open("scans/consolidated_scan_results.md", "a", encoding="utf-8") as file:
            file.write("\n# SSTImap Scan Results\n")
            file.write(f"**URL:** {target_url}\n")
            file.write("**Unexpected Error:**\n")
            file.write("```\n")
            file.write(str(e))
            file.write("```\n")
            file.write("---\n")
