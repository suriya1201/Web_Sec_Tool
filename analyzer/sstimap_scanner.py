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
import openai  # Import OpenAI library
from dotenv import load_dotenv  # Import load_dotenv

load_dotenv()  # Load environment variables from .env file
api_key = os.getenv("OPENAI_API_KEY")  # Get OpenAI API key

if api_key is None:
    raise ValueError("API key not found. Please check your .env file.")

client = openai.OpenAI(api_key=api_key)  # Set API key


def generate_pdf_report(target_url, scan_scope, results, summary):
    pdf_path = "scans/sstimap_scan_report.pdf"

    # Ensure the "scans" directory exists
    if not os.path.exists("scans"):
        os.makedirs("scans")

    # Deletes the file if it already exists
    if os.path.exists(pdf_path):
        os.remove(pdf_path)

    # Create a new PDF canvas
    c = canvas.Canvas(pdf_path, pagesize=letter)
    page_width, page_height = letter

    # Title
    c.setFont("Helvetica-Bold", 18)
    c.setFillColor(colors.blue)
    c.drawString(100, page_height - 50, "SSTImap Scan Report")
    c.setFillColor(colors.black)

    # Metadata
    c.setFont("Helvetica", 12)
    c.drawString(100, page_height - 80, f"Target URL: {target_url}")
    c.drawString(100, page_height - 100, f"Scope: {scan_scope}")

    # Results
    y_position = page_height - 140
    c.setFont("Helvetica", 10)
    y_position = _draw_text(c, results, y_position, page_width)

    # AI Summary
    c.setFont("Helvetica-Bold", 12)
    c.drawString(100, y_position - 20, "AI Summary:")
    y_position -= 40
    c.setFont("Helvetica", 10)
    y_position = _draw_text(c, summary, y_position, page_width)

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

def get_ai_summary(text):
    """Get AI summary with OpenAI API, handling rate limits."""
    prompt = f"""
    Summarize the following SSTImap scan results in a structured report format. Include the following details:
    - The target URL tested
    - The types of SSTI vulnerabilities detected
    - Any additional information about the vulnerabilities

    SSTImap Scan Results:
    {text}
    
    Provide the summary in this structured format:

    The SSTImap tool was used to test for SSTI vulnerabilities on **[Target URL]**. 
    The detected SSTI vulnerabilities included:
    - **[Vulnerability 1]**
    - **[Vulnerability 2]**
    - **[Vulnerability 3]**
    
    Additional information:
    - **[Additional Info 1]**
    - **[Additional Info 2]**
    """
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "user", "content": prompt}
        ],
        max_tokens=1500
    )
    return response.choices[0].message.content.strip()

def run_sstimap(report_manager, target_url, scan_depth=1):
    """Runs SSTImap to test for Server-Side Template Injection vulnerabilities and logs results."""
    st.write(f"Running SSTImap on {target_url} with depth: {scan_depth}...")

    command = [
        "python",
        "./SSTImap/sstimap.py",
        "--url",
        target_url,
        "--no-color",
        "--forms",
         "--empty-forms",
        f"--crawl={scan_depth}",
    ]

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

        # Get AI summary
        summary = get_ai_summary(result.stdout)
        st.header("AI Summary:")
        st.markdown(summary)  # Use st.markdown to render the summary with Markdown formatting

        generate_pdf_report(target_url, scan_depth, result.stdout, summary)
        report_manager.append_to_pdf("./scans/sstimap_scan_report.pdf")

    except subprocess.CalledProcessError as e:
        st.write(f"Error running SSTImap: {e}")
        st.text(e.stdout)
        st.text(e.stderr)

        generate_pdf_report(target_url, scan_depth, e.stdout, "")
        report_manager.append_to_pdf("./scans/sstimap_scan_report.pdf")