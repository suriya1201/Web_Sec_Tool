# utils/pdf_generator.py
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, ListFlowable, ListItem
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_JUSTIFY, TA_LEFT
from reportlab.lib import colors
from models.vulnerability import VulnerabilityReport, VulnerabilitySeverity

class PDFGenerator:
    def __init__(self, filename="vulnerability_report.pdf"):
        self.filename = filename
        self.doc = SimpleDocTemplate(self.filename, pagesize=letter)
        self.styles = getSampleStyleSheet()
        self.elements = []

    def generate_report(self, report: VulnerabilityReport):
        self._add_header(report)
        self._add_summary(report)
        self._add_detailed_vulnerabilities(report)
        if report.chained_vulnerabilities:
            self._add_chained_vulnerabilities(report)
        self.doc.build(self.elements)
        return self.filename


    def _add_header(self, report: VulnerabilityReport):
        title_style = self.styles["Heading1"]
        title_style.alignment = TA_LEFT
        self.elements.append(Paragraph("Security Vulnerability Report", title_style))
        self.elements.append(Paragraph(f"Generated: {report.timestamp}", self.styles["Normal"]))
        self.elements.append(Spacer(1, 12))

    def _add_summary(self, report: VulnerabilityReport):
        """Add the executive summary section to the PDF using ReportLab."""
        # Add summary title
        self.elements.append(Paragraph("Executive Summary", self.styles["Heading2"]))
        self.elements.append(Spacer(1, 6))
        
        # Check if summary exists
        if not hasattr(report, 'summary') or report.summary is None:
            self.elements.append(Paragraph("No summary data available.", self.styles["Normal"]))
            self.elements.append(Spacer(1, 12))
            return
        
        # Get summary data with safe fallbacks
        total_vulns = report.summary.get('total', 'N/A') if isinstance(report.summary, dict) else 'N/A'
        high_risk = report.summary.get('high', 'N/A') if isinstance(report.summary, dict) else 'N/A'
        medium_risk = report.summary.get('medium', 'N/A') if isinstance(report.summary, dict) else 'N/A'
        low_risk = report.summary.get('low', 'N/A') if isinstance(report.summary, dict) else 'N/A'
        
        # Create summary list
        summary_data = [
            f"<b>Total Vulnerabilities:</b> {total_vulns}",
            f"<b>High Risk:</b> {high_risk}",
            f"<b>Medium Risk:</b> {medium_risk}",
            f"<b>Low Risk:</b> {low_risk}"
        ]
        
        # Add summary list
        bullet_list = ListFlowable(
            [ListItem(Paragraph(data, self.styles['Normal'])) for data in summary_data],
            bulletType='bullet',
            leftIndent=20
        )
        self.elements.append(bullet_list)
        
        # Add general assessment if available
        if isinstance(report.summary, dict) and 'assessment' in report.summary:
            self.elements.append(Spacer(1, 10))
            self.elements.append(Paragraph("General Assessment:", self.styles["Heading3"]))
            self.elements.append(Paragraph(report.summary['assessment'], self.styles["Normal"]))
        
        self.elements.append(Spacer(1, 12))


    def _add_detailed_vulnerabilities(self, report: VulnerabilityReport):
        self.elements.append(Paragraph("Detailed Vulnerabilities", self.styles["Heading2"]))

        for vuln in report.vulnerabilities:
            # Vulnerability Title
            title = f"{vuln.type} ({vuln.severity})"
            title_style = ParagraphStyle(
                name='VulnTitle',
                parent=self.styles['Heading3'],
                textColor=self._get_severity_color(vuln.severity),
            )
            self.elements.append(Paragraph(title, title_style))


            # Vulnerability Details (as a bullet list)
            details_data = [
                f"<b>Description:</b> {vuln.description}",
                f"<b>Impact:</b> {vuln.impact}",
                f"<b>Location:</b> {vuln.location.file_path}:{vuln.location.start_line}",
                f"<b>CWE ID:</b> <a href='https://cwe.mitre.org/data/definitions/{vuln.cwe_id}.html'>{vuln.cwe_id}</a>",  #Link
                f"<b>OWASP Category:</b> {vuln.owasp_category}",
                f"<b>CVSS Score:</b> {vuln.cvss_score}",
                f"<b>Remediation:</b> {vuln.remediation}",
            ]

            # Add main details
            bullet_list = ListFlowable(
                [ListItem(Paragraph(data, self.styles['Normal'])) for data in details_data],
                bulletType='bullet',
                leftIndent=20  # Apply leftIndent to the entire ListFlowable, not individual items
            )
            self.elements.append(bullet_list)

            # Add References (as a separate section)
            if vuln.references:
                self.elements.append(Paragraph("<b>References:</b>", self.styles['Normal']))
                ref_list = ListFlowable(
                    [ListItem(Paragraph(f"<a href='{ref}'>{ref}</a>", self.styles['Normal'])) for ref in vuln.references],
                    bulletType='bullet',
                    leftIndent=40  # Indented further to show hierarchy
                )
                self.elements.append(ref_list)

            # Add PoC and Secure Code Example as paragraphs
            if vuln.proof_of_concept:
                self.elements.append(Paragraph("<b>Proof of Concept:</b>", self.styles['Normal']))
                self.elements.append(Paragraph(vuln.proof_of_concept, self.styles['Code']))  # Use a code style if available

            if vuln.secure_code_example:
                self.elements.append(Paragraph("<b>Secure Code Example:</b>", self.styles['Normal']))
                self.elements.append(Paragraph(vuln.secure_code_example, self.styles['Code']))  # Use a code style if available

            self.elements.append(Spacer(1, 12))



    def _add_chained_vulnerabilities(self, report: VulnerabilityReport):
        self.elements.append(Paragraph("Chained Vulnerabilities", self.styles["Heading2"]))
        for chain in report.chained_vulnerabilities:
            # Chain Title
            title = f"Vulnerability Chain (Combined Severity: {chain.combined_severity})"
            self.elements.append(Paragraph(title, self.styles["Heading3"]))

            # Chain Details
            details_data = [
                f"<b>Attack Path:</b> {chain.attack_path}",
                f"<b>Likelihood:</b> {chain.likelihood}",
                f"<b>Mitigation Priority:</b> {chain.mitigation_priority}"
            ]

            # Add main chain details
            bullet_list = ListFlowable(
                [ListItem(Paragraph(data, self.styles['Normal'])) for data in details_data],
                bulletType='bullet',
                leftIndent=20  # Apply leftIndent to the entire ListFlowable
            )
            self.elements.append(bullet_list)

            # Add prerequisites as a separate section
            self.elements.append(Paragraph("<b>Prerequisites:</b>", self.styles['Normal']))
            prereq_list = ListFlowable(
                [ListItem(Paragraph(prereq, self.styles['Normal'])) for prereq in chain.prerequisites],
                bulletType='bullet',
                leftIndent=40  # Indented further to show hierarchy
            )
            self.elements.append(prereq_list)

            self.elements.append(Spacer(1, 12))


    def _get_severity_color(self, severity: VulnerabilitySeverity):
        if severity == VulnerabilitySeverity.CRITICAL:
            return colors.red
        elif severity == VulnerabilitySeverity.HIGH:
            return colors.orange
        elif severity == VulnerabilitySeverity.MEDIUM:
            return colors.yellow
        elif severity == VulnerabilitySeverity.LOW:
            return colors.green
        else:  # INFO
            return colors.blue