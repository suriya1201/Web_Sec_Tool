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
    """Generates a PDF report for sqlmap scan results."""
    pdf_path = "./scans/sqlmap_scan_report.pdf"

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
    c.drawString(100, page_height - 50, "SQLMap Scan Report")
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
                # Check for bold words
                words = line.split(" ")
                x_position = 100
                for word in words:
                    if word.startswith("**") and word.endswith("**"):
                        c.setFont("Helvetica-Bold", 10)
                        word = word[2:-2]  # Remove the ** markers
                    else:
                        c.setFont("Helvetica", 10)
                    
                    c.drawString(x_position, y_position, word)
                    x_position += c.stringWidth(word + " ", "Helvetica", 10)
                line = ""

            y_position -= 14  # Move down for the next line
    return y_position

import time

def get_ai_summary(text):
    """Get AI summary with OpenAI API, handling rate limits."""
    prompt = f"""
    Summarize the following SQLMap scan results in a structured report format. Include the following details:
    - The target URL tested
    - The parameter(s) found to be injectable
    - The types of SQL injection detected
    - The identified database management system (DBMS)
    - Any additional system information (server version, OS, PHP version, etc.)
    - The databases found

    SQLMap Scan Results:
    {text}
    
    Provide the summary in this structured format:

    The SQLMap tool was used to test for SQL injection vulnerabilities on **[Target URL]**. 
    The tool identified an injectable parameter (**[parameter name]**) in **[location (e.g., form submission, URL parameter)]**.
    The detected SQL injection techniques included:
    - **[Technique 1]**
    - **[Technique 2]**
    - **[Technique 3]**
    
    The database management system (DBMS) was confirmed as **[DBMS name]**, and the server was running **[OS]** with **[server details]**.
    The following databases were found:
    - **[Database 1]**
    - **[Database 2]**
    """
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "user", "content": prompt}
        ],
        max_tokens=1500
    )
    return response.choices[0].message.content.strip()

def run_sqlmap(report_manager, target_url, scan_depth=1):
    """Runs sqlmap on the target URL and saves the output to the specified directory."""
    st.write(f"Running sqlmap on {target_url} with depth: {scan_depth}...")

    command = [
        "sqlmap",
        "-u",
        target_url,
        "--batch",
        "--dbs",
        "--forms",
        f"--crawl={scan_depth}",
    ]

    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        st.write("sqlmap scan completed. Results:")
        st.text(result.stdout)

        # Get AI summary
        summary = get_ai_summary(result.stdout)
        st.header("AI Summary:")
        st.markdown(summary)  # Use st.markdown to render the summary with Markdown formatting

        generate_pdf_report(target_url, scan_depth, result.stdout, summary)
        report_manager.append_to_pdf("./scans/sqlmap_scan_report.pdf")

    except subprocess.CalledProcessError as e:
        st.write(f"Error running sqlmap: {e}")
        st.text(e.stdout)
        st.text(e.stderr)