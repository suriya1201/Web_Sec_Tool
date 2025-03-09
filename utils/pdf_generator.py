# utils/pdf_generator.py
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, ListFlowable, ListItem
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_JUSTIFY, TA_LEFT
from reportlab.lib import colors
from datetime import datetime

class PDFGenerator:
    def __init__(self, filename="vulnerability_report.pdf"):
        self.filename = filename
        self.doc = SimpleDocTemplate(self.filename, pagesize=letter)
        self.styles = getSampleStyleSheet()
        
        # Check if 'Code' style already exists before adding it
        if 'Code' not in self.styles:
            self.styles.add(ParagraphStyle(
                name='Code',
                fontName='Courier',
                fontSize=8,
                leading=10
            ))
        self.elements = []

    def generate_report(self, report):
        """Generate PDF report for old VulnerabilityReport format."""
        self._add_header(report)
        self._add_summary(report)
        self._add_detailed_vulnerabilities(report)
        if hasattr(report, 'chained_vulnerabilities') and report.chained_vulnerabilities:
            self._add_chained_vulnerabilities(report)
        self.doc.build(self.elements)
        return self.filename

    def generate_security_report(self, report):
        """Generate PDF report for new SecurityAnalysisReport format."""
        self._add_security_header(report)
        self._add_security_summary(report)
        self._add_security_issues(report)
        if self._has_attribute_or_key(report, 'issue_chains'):
            chains = self._get_attribute_or_item(report, 'issue_chains', [])
            if chains:
                self._add_security_chains(report)
        self.doc.build(self.elements)
        return self.filename

    def _has_attribute_or_key(self, obj, name):
        """Check if object has attribute or dictionary has key."""
        if isinstance(obj, dict):
            return name in obj
        else:
            return hasattr(obj, name)

    def _get_attribute_or_item(self, obj, name, default=None):
        """Get attribute from object or item from dictionary."""
        if isinstance(obj, dict):
            return obj.get(name, default)
        else:
            return getattr(obj, name, default)

    def _add_header(self, report):
        """Add report header for old format."""
        title_style = self.styles["Heading1"]
        title_style.alignment = TA_LEFT
        self.elements.append(Paragraph("Security Vulnerability Report", title_style))
        
        # Handle timestamp in different formats
        timestamp = None
        if hasattr(report, 'timestamp'):
            timestamp = report.timestamp
        elif hasattr(report, 'generated_at'):
            timestamp = report.generated_at
        else:
            timestamp = datetime.now()
            
        self.elements.append(Paragraph(f"Generated: {timestamp}", self.styles["Normal"]))
        self.elements.append(Spacer(1, 12))

    def _add_security_header(self, report):
        """Add report header for new format."""
        title_style = self.styles["Heading1"]
        title_style.alignment = TA_LEFT
        self.elements.append(Paragraph("Security Analysis Report", title_style))
        
        # Get timestamp from new format (object or dictionary)
        timestamp = self._get_attribute_or_item(report, 'generated_at', datetime.now().isoformat())
        if isinstance(timestamp, str):
            # Try to parse ISO format string if needed
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                pass
            
        self.elements.append(Paragraph(f"Generated: {timestamp}", self.styles["Normal"]))
        
        # Add repository info if available
        repo_url = self._get_attribute_or_item(report, 'repository_url')
        if repo_url:
            self.elements.append(Paragraph(f"Repository: {repo_url}", self.styles["Normal"]))
            
        branch_name = self._get_attribute_or_item(report, 'branch_name')
        if branch_name:
            self.elements.append(Paragraph(f"Branch: {branch_name}", self.styles["Normal"]))
            
        self.elements.append(Spacer(1, 12))

    def _add_summary(self, report):
        """Add summary section for old format."""
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
        critical = report.summary.get('critical', 'N/A') if isinstance(report.summary, dict) else 'N/A'
        high_risk = report.summary.get('high', 'N/A') if isinstance(report.summary, dict) else 'N/A'
        medium_risk = report.summary.get('medium', 'N/A') if isinstance(report.summary, dict) else 'N/A'
        low_risk = report.summary.get('low', 'N/A') if isinstance(report.summary, dict) else 'N/A'
        info = report.summary.get('info', 'N/A') if isinstance(report.summary, dict) else 'N/A'
        
        # Create summary list
        summary_data = [
            f"<b>Total Vulnerabilities:</b> {total_vulns}",
            f"<b>Critical:</b> {critical}",
            f"<b>High Risk:</b> {high_risk}",
            f"<b>Medium Risk:</b> {medium_risk}",
            f"<b>Low Risk:</b> {low_risk}",
            f"<b>Info:</b> {info}"
        ]
        
        # Add summary list
        bullet_list = ListFlowable(
            [ListItem(Paragraph(data, self.styles['Normal'])) for data in summary_data],
            bulletType='bullet',
            leftIndent=20
        )
        self.elements.append(bullet_list)
        
        # Add risk score if available
        if hasattr(report, 'risk_score') and report.risk_score is not None:
            self.elements.append(Spacer(1, 10))
            self.elements.append(Paragraph(f"<b>Risk Score:</b> {report.risk_score:.2f}", self.styles["Normal"]))
        
        self.elements.append(Spacer(1, 12))

    def _add_security_summary(self, report):
        """Add summary section for new format."""
        # Add summary title
        self.elements.append(Paragraph("Executive Summary", self.styles["Heading2"]))
        self.elements.append(Spacer(1, 6))
        
        # Check if summary exists
        summary_stats = self._get_attribute_or_item(report, 'summary_stats')
        if not summary_stats:
            self.elements.append(Paragraph("No summary data available.", self.styles["Normal"]))
            self.elements.append(Spacer(1, 12))
            return
        
        # Get summary data with safe fallbacks
        if isinstance(summary_stats, dict):
            total_issues = summary_stats.get('total_issues', 'N/A')
            critical_count = summary_stats.get('critical_count', 'N/A')
            high_count = summary_stats.get('high_count', 'N/A')
            medium_count = summary_stats.get('medium_count', 'N/A')
            low_count = summary_stats.get('low_count', 'N/A')
            info_count = summary_stats.get('info_count', 'N/A')
            chain_count = summary_stats.get('chain_count', 'N/A')
        else:
            # If it's an object, try to get attributes
            total_issues = getattr(summary_stats, 'total_issues', 'N/A')
            critical_count = getattr(summary_stats, 'critical_count', 'N/A')
            high_count = getattr(summary_stats, 'high_count', 'N/A')
            medium_count = getattr(summary_stats, 'medium_count', 'N/A')
            low_count = getattr(summary_stats, 'low_count', 'N/A')
            info_count = getattr(summary_stats, 'info_count', 'N/A')
            chain_count = getattr(summary_stats, 'chain_count', 'N/A')
        
        # Create summary list
        summary_data = [
            f"<b>Total Issues:</b> {total_issues}",
            f"<b>Critical:</b> {critical_count}",
            f"<b>High:</b> {high_count}",
            f"<b>Medium:</b> {medium_count}",
            f"<b>Low:</b> {low_count}",
            f"<b>Info:</b> {info_count}",
            f"<b>Issue Chains:</b> {chain_count}"
        ]
        
        # Add summary list
        bullet_list = ListFlowable(
            [ListItem(Paragraph(data, self.styles['Normal'])) for data in summary_data],
            bulletType='bullet',
            leftIndent=20
        )
        self.elements.append(bullet_list)
        
        # Add risk rating if available
        risk_rating = self._get_attribute_or_item(report, 'risk_rating')
        if risk_rating is not None:
            self.elements.append(Spacer(1, 10))
            try:
                formatted_rating = f"{float(risk_rating):.2f}"
            except (ValueError, TypeError):
                formatted_rating = str(risk_rating)
            self.elements.append(Paragraph(f"<b>Risk Rating:</b> {formatted_rating}", self.styles["Normal"]))
        
        self.elements.append(Spacer(1, 12))

    def _add_detailed_vulnerabilities(self, report):
        """Add detailed vulnerabilities section for old format."""
        self.elements.append(Paragraph("Detailed Vulnerabilities", self.styles["Heading2"]))

        if not hasattr(report, 'vulnerabilities') or not report.vulnerabilities:
            self.elements.append(Paragraph("No vulnerabilities found.", self.styles["Normal"]))
            self.elements.append(Spacer(1, 12))
            return

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
                leftIndent=20
            )
            self.elements.append(bullet_list)

            # Add References (as a separate section)
            if hasattr(vuln, 'references') and vuln.references:
                self.elements.append(Paragraph("<b>References:</b>", self.styles['Normal']))
                ref_list = ListFlowable(
                    [ListItem(Paragraph(f"<a href='{ref}'>{ref}</a>", self.styles['Normal'])) for ref in vuln.references],
                    bulletType='bullet',
                    leftIndent=40
                )
                self.elements.append(ref_list)

            # Add PoC and Secure Code Example as paragraphs
            if hasattr(vuln, 'proof_of_concept') and vuln.proof_of_concept:
                self.elements.append(Paragraph("<b>Proof of Concept:</b>", self.styles['Normal']))
                self.elements.append(Paragraph(vuln.proof_of_concept, self.styles['Code']))

            if hasattr(vuln, 'secure_code_example') and vuln.secure_code_example:
                self.elements.append(Paragraph("<b>Secure Code Example:</b>", self.styles['Normal']))
                self.elements.append(Paragraph(vuln.secure_code_example, self.styles['Code']))

            self.elements.append(Spacer(1, 12))

    def _add_security_issues(self, report):
        """Add security issues section for new format."""
        self.elements.append(Paragraph("Security Issues", self.styles["Heading2"]))

        issues = self._get_attribute_or_item(report, 'issues', [])
        if not issues:
            self.elements.append(Paragraph("No security issues found.", self.styles["Normal"]))
            self.elements.append(Spacer(1, 12))
            return

        for issue in issues:
            if isinstance(issue, dict):
                # Dictionary approach
                category = issue.get("category", "UNKNOWN")
                severity = issue.get("severity", "MEDIUM")
                description = issue.get('description', 'No description')
                impact = issue.get('impact', 'No impact information')
                remediation = issue.get('remediation', 'No remediation information')
                owasp_category = issue.get('owasp_category', 'Unknown')
                cvss_score = issue.get('cvss_score', 'Unknown')
                cwe_id = issue.get('cwe_id', '')
                references = issue.get("references", [])
                proof_of_concept = issue.get("proof_of_concept", "")
                secure_alternative = issue.get("secure_alternative", "")
                
                # Position information
                position = issue.get("position", {})
                if isinstance(position, dict):
                    file_path = position.get("file_path", "unknown")
                    start_line = position.get("start_line", 0)
                    end_line = position.get("end_line", 0)
                else:
                    # Position is an object
                    file_path = getattr(position, "file_path", "unknown")
                    start_line = getattr(position, "start_line", 0)
                    end_line = getattr(position, "end_line", 0)
            else:
                # Object approach
                category = getattr(issue, "category", "UNKNOWN")
                severity = getattr(issue, "severity", "MEDIUM")
                description = getattr(issue, 'description', 'No description')
                impact = getattr(issue, 'impact', 'No impact information')
                remediation = getattr(issue, 'remediation', 'No remediation information')
                owasp_category = getattr(issue, 'owasp_category', 'Unknown')
                cvss_score = getattr(issue, 'cvss_score', 'Unknown')
                cwe_id = getattr(issue, 'cwe_id', '')
                references = getattr(issue, "references", [])
                proof_of_concept = getattr(issue, "proof_of_concept", "")
                secure_alternative = getattr(issue, "secure_alternative", "")
                
                # Position information
                position = getattr(issue, "position", None)
                if position:
                    file_path = getattr(position, "file_path", "unknown")
                    start_line = getattr(position, "start_line", 0)
                    end_line = getattr(position, "end_line", 0)
                else:
                    file_path = "unknown"
                    start_line = 0
                    end_line = 0
            
            # Issue Title
            title = f"{category} ({severity})"
            title_style = ParagraphStyle(
                name='IssueTitle',
                parent=self.styles['Heading3'],
                textColor=self._get_severity_color_from_string(severity),
            )
            self.elements.append(Paragraph(title, title_style))

            # Format location
            location = f"{file_path}:{start_line}"
            if start_line != end_line:
                location = f"{file_path}:{start_line}-{end_line}"

            # Issue Details (as a bullet list)
            details_data = [
                f"<b>Description:</b> {description}",
                f"<b>Impact:</b> {impact}",
                f"<b>Location:</b> {location}",
                f"<b>CWE ID:</b> <a href='https://cwe.mitre.org/data/definitions/{cwe_id.replace('CWE-', '')}.html'>{cwe_id}</a>",
                f"<b>OWASP Category:</b> {owasp_category}",
                f"<b>CVSS Score:</b> {cvss_score}",
                f"<b>Remediation:</b> {remediation}",
            ]

            # Add main details
            bullet_list = ListFlowable(
                [ListItem(Paragraph(data, self.styles['Normal'])) for data in details_data],
                bulletType='bullet',
                leftIndent=20
            )
            self.elements.append(bullet_list)

            # Add References (as a separate section)
            if references:
                self.elements.append(Paragraph("<b>References:</b>", self.styles['Normal']))
                ref_list = ListFlowable(
                    [ListItem(Paragraph(f"<a href='{ref}'>{ref}</a>", self.styles['Normal'])) for ref in references],
                    bulletType='bullet',
                    leftIndent=40
                )
                self.elements.append(ref_list)

            # Add PoC and Secure Alternative as paragraphs
            if proof_of_concept:
                self.elements.append(Paragraph("<b>Proof of Concept:</b>", self.styles['Normal']))
                self.elements.append(Paragraph(proof_of_concept, self.styles['Code']))

            if secure_alternative:
                self.elements.append(Paragraph("<b>Secure Alternative:</b>", self.styles['Normal']))
                self.elements.append(Paragraph(secure_alternative, self.styles['Code']))

            self.elements.append(Spacer(1, 12))

    def _add_chained_vulnerabilities(self, report):
        """Add chained vulnerabilities section for old format."""
        self.elements.append(Paragraph("Chained Vulnerabilities", self.styles["Heading2"]))
        
        if not hasattr(report, 'chained_vulnerabilities') or not report.chained_vulnerabilities:
            self.elements.append(Paragraph("No vulnerability chains found.", self.styles["Normal"]))
            self.elements.append(Spacer(1, 12))
            return
            
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
                leftIndent=20
            )
            self.elements.append(bullet_list)

            # Add prerequisites as a separate section
            if hasattr(chain, 'prerequisites') and chain.prerequisites:
                self.elements.append(Paragraph("<b>Prerequisites:</b>", self.styles['Normal']))
                prereq_list = ListFlowable(
                    [ListItem(Paragraph(prereq, self.styles['Normal'])) for prereq in chain.prerequisites],
                    bulletType='bullet',
                    leftIndent=40
                )
                self.elements.append(prereq_list)

            self.elements.append(Spacer(1, 12))

    def _add_security_chains(self, report):
        """Add security issue chains section for new format."""
        self.elements.append(Paragraph("Security Issue Chains", self.styles["Heading2"]))
        
        chains = self._get_attribute_or_item(report, 'issue_chains', [])
        if not chains:
            self.elements.append(Paragraph("No security issue chains found.", self.styles["Normal"]))
            self.elements.append(Spacer(1, 12))
            return
            
        for chain in chains:
            if isinstance(chain, dict):
                # Dictionary approach
                combined_severity = chain.get("combined_severity", "UNKNOWN")
                attack_scenario = chain.get('attack_scenario', 'No scenario available')
                exploit_likelihood = chain.get('exploit_likelihood', 0)
                mitigation_priority = chain.get('mitigation_priority', 0)
                prerequisites = chain.get("prerequisites", [])
            else:
                # Object approach
                combined_severity = getattr(chain, "combined_severity", "UNKNOWN")
                attack_scenario = getattr(chain, 'attack_scenario', 'No scenario available')
                exploit_likelihood = getattr(chain, 'exploit_likelihood', 0)
                mitigation_priority = getattr(chain, 'mitigation_priority', 0)
                prerequisites = getattr(chain, "prerequisites", [])
                
            # Chain Title
            title = f"Issue Chain (Combined Severity: {combined_severity})"
            self.elements.append(Paragraph(title, self.styles["Heading3"]))

            # Chain Details
            details_data = [
                f"<b>Attack Scenario:</b> {attack_scenario}",
                f"<b>Exploit Likelihood:</b> {exploit_likelihood}",
                f"<b>Mitigation Priority:</b> {mitigation_priority}"
            ]

            # Add main chain details
            bullet_list = ListFlowable(
                [ListItem(Paragraph(data, self.styles['Normal'])) for data in details_data],
                bulletType='bullet',
                leftIndent=20
            )
            self.elements.append(bullet_list)

            # Add prerequisites as a separate section
            if prerequisites:
                self.elements.append(Paragraph("<b>Prerequisites:</b>", self.styles['Normal']))
                prereq_list = ListFlowable(
                    [ListItem(Paragraph(prereq, self.styles['Normal'])) for prereq in prerequisites],
                    bulletType='bullet',
                    leftIndent=40
                )
                self.elements.append(prereq_list)

            self.elements.append(Spacer(1, 12))

    def _get_severity_color(self, severity):
        """Get severity color based on old format enum."""
        severity_str = str(severity).upper() if severity else "INFO"
        return self._get_severity_color_from_string(severity_str)

    def _get_severity_color_from_string(self, severity_str):
        """Get severity color based on string."""
        severity_upper = severity_str.upper() if isinstance(severity_str, str) else "INFO"
        
        if "CRITICAL" in severity_upper:
            return colors.red
        elif "HIGH" in severity_upper:
            return colors.orange
        elif "MEDIUM" in severity_upper:
            return colors.yellow
        elif "LOW" in severity_upper:
            return colors.green
        else:  # INFO or unknown
            return colors.blue