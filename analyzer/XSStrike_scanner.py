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
import openai  # Import OpenAI library
from dotenv import load_dotenv  # Import load_dotenv

load_dotenv()  # Load environment variables from .env file
api_key = os.getenv("OPENAI_API_KEY")  # Get OpenAI API key


if api_key is None:
    raise ValueError("API key not found. Please check your .env file.")

client = openai.OpenAI(api_key=api_key)  # Set API key

def generate_pdf_report(target_url, scan_scope, results, summary):
    """Generates a PDF report for XSStrike scan results."""
    pdf_path = "scans/xsstrike_scan_report.pdf"

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

    # AI Summary
    c.setFont("Helvetica-Bold", 12)
    c.drawString(100, y_position - 20, "AI Summary:")
    y_position -= 40
    c.setFont("Helvetica", 10)
    y_position = _draw_text(c, summary, y_position, page_width)

    # Save the PDF
    c.save()

def _draw_text(c, text, y_position, page_width):
    """Helper function to handle line wrapping and drawing text with bold words."""
    lines = text.split("\n")
    max_width = page_width - 150  # Adjust margin
    
    for line in lines:
        while len(line) > 0:
            if y_position < 50:  # Avoid writing too low
                c.showPage()
                y_position = letter[1] - 50  # Reset y_position for the new page
                c.setFont("Helvetica", 10)  # Reapply font on new page
            
            bold_pattern = re.compile(r'\*\*(.*?)\*\*')
            matches = list(bold_pattern.finditer(line))
            
            x_position = 100
            last_end = 0
            wrapped_line = ""
            
            if matches:
                for match in matches:
                    start, end = match.span()
                    
                    # Draw text before the bold word
                    normal_text = line[last_end:start]
                    if normal_text.strip():
                        c.setFont("Helvetica", 10)
                        if x_position + c.stringWidth(normal_text, "Helvetica", 10) > max_width:
                            y_position -= 14
                            x_position = 100
                        c.drawString(x_position, y_position, normal_text)
                        x_position += c.stringWidth(normal_text, "Helvetica", 10)
                    
                    # Draw the bold word
                    bold_text = match.group(1)
                    c.setFont("Helvetica-Bold", 10)
                    if x_position + c.stringWidth(bold_text, "Helvetica-Bold", 10) > max_width:
                        y_position -= 14
                        x_position = 100
                    c.drawString(x_position, y_position, bold_text)
                    x_position += c.stringWidth(bold_text, "Helvetica-Bold", 10)
                    
                    last_end = end
                
                # Draw any remaining text after the last bold word
                remaining_text = line[last_end:]
                if remaining_text.strip():
                    c.setFont("Helvetica", 10)
                    if x_position + c.stringWidth(remaining_text, "Helvetica", 10) > max_width:
                        y_position -= 14
                        x_position = 100
                    c.drawString(x_position, y_position, remaining_text)
            else:
                # No bold words, handle normal text wrapping
                c.setFont("Helvetica", 10)
                words = line.split(" ")
                for word in words:
                    word_width = c.stringWidth(word + " ", "Helvetica", 10)
                    if x_position + word_width > max_width:
                        y_position -= 14
                        x_position = 100
                    c.drawString(x_position, y_position, word + " ")
                    x_position += word_width
            
            line = ""
            y_position -= 14  # Move down for the next line
    return y_position

def remove_ansi_escape_sequences(text):
    """Remove ANSI escape sequences from the text."""
    ansi_escape = re.compile(r"(?:\x1B[@-_]|[\x80-\x9F][0-?]*[ -/]*[@-~])")
    return ansi_escape.sub("", text)

def get_ai_summary(text):
    """Get AI summary with OpenAI API, handling rate limits."""
    prompt = f"""
    Summarize the following XSStrike scan results in a structured report format. Include the following details:
    - The target URL tested
    - The types of XSS vulnerabilities detected
    - Any additional information about the vulnerabilities

    XSStrike Scan Results:
    {text}
    
    Provide the summary in this structured format:

    The XSStrike tool was used to test for XSS vulnerabilities on **[Target URL]**. 
    The detected XSS vulnerabilities included:
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

def run_XSStrike(report_manager, target_url, scan_depth=1):
    """Runs XSStrike to test for Cross-Site Scripting (XSS) vulnerabilities and logs results."""
    st.write(f"Running XSStrike on {target_url} with depth: {scan_depth}...")

    command = [
        "python",
        "./XSStrike/xsstrike.py",
        "--url",
        target_url,
        "--crawl",
        "-l",
        str(scan_depth),
    ]

    try:
        result = subprocess.run(
            command, check=True, capture_output=True, text=True, encoding="utf-8"
        )

        # Remove ANSI escape sequences from the output
        clean_output = remove_ansi_escape_sequences(result.stdout)
        st.write("XSStrike scan completed. Results:")
        st.text(clean_output)

        # Get AI summary
        summary = get_ai_summary(clean_output)
        st.header("AI Summary:")
        st.markdown(summary)  # Use st.markdown to render the summary with Markdown formatting

        generate_pdf_report(target_url, scan_depth, clean_output, summary)
        report_manager.append_to_pdf("./scans/XSStrike_scan_report.pdf")

    except subprocess.CalledProcessError as e:
        st.write(f"Error running XSStrike: {e}")
        st.text(e.stdout)
        st.text(e.stderr)

        generate_pdf_report(target_url, scan_depth, e.stdout, "")
        report_manager.append_to_pdf("./scans/XSStrike_scan_report.pdf")