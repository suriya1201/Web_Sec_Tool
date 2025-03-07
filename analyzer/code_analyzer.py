# analyzer/code_analyzer.py
import logging
import os
import re
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Set

import git

from models.vulnerability import (
    CodeLocation,
    Vulnerability,
    VulnerabilityChain,
    VulnerabilityReport,
    VulnerabilitySeverity,
    VulnerabilityType
)
from utils.ai_client import AIClient
from utils.code_parser import CodeParser


class CodeAnalyzer:
    """
    CodeAnalyzer class for analyzing code for security vulnerabilities
    """

    def __init__(self) -> None:
        """
        Initialize the code analyzer with caching enabled
        """

        self.ai_client = AIClient()
        self.code_parser = CodeParser()
        self._repo_cache: Dict[str, str] = {}

        # Common attack chains based on vulnerability types
        self.attack_chains = {
            VulnerabilityType.SQL_INJECTION: [
                VulnerabilityType.BROKEN_AUTHENTICATION,
                VulnerabilityType.SENSITIVE_DATA_EXPOSURE,
                VulnerabilityType.BROKEN_ACCESS_CONTROL
            ],
            VulnerabilityType.CROSS_SITE_SCRIPTING: [
                VulnerabilityType.BROKEN_AUTHENTICATION,
                VulnerabilityType.CSRF,
                VulnerabilityType.SENSITIVE_DATA_EXPOSURE
            ],
            VulnerabilityType.BROKEN_AUTHENTICATION: [
                VulnerabilityType.BROKEN_ACCESS_CONTROL,
                VulnerabilityType.SENSITIVE_DATA_EXPOSURE,
                VulnerabilityType.INSECURE_DIRECT_OBJECT_REFERENCE
            ],
            VulnerabilityType.PATH_TRAVERSAL: [
                VulnerabilityType.FILE_INCLUSION,
                VulnerabilityType.REMOTE_CODE_EXECUTION,
                VulnerabilityType.SENSITIVE_DATA_EXPOSURE
            ],
            VulnerabilityType.INSECURE_DESERIALIZATION: [
                VulnerabilityType.REMOTE_CODE_EXECUTION,
                VulnerabilityType.OS_COMMAND_INJECTION,
                VulnerabilityType.CODE_INJECTION
            ]
        }

    async def analyze_code(self, code_content: str, filename: str) -> VulnerabilityReport:
        """
        Analyze a single file for security vulnerabilities with improved validation.
        Empty files are ignored and return an empty report.

        Args:
            code_content: The code content to analyze
            filename: The name of the file

        Returns:
            VulnerabilityReport: The vulnerability report, empty for empty files
        """

        # convert code content to string
        code_content = str(code_content)
        # Check for empty file
        if not code_content or not isinstance(code_content, str) or code_content.isspace():
            logging.info(f"Skipping empty file: {filename}")
            return VulnerabilityReport(
                file_name=filename,
                vulnerabilities=[],
                chained_vulnerabilities=[],
                timestamp=datetime.now()
            )

        # Validate filename
        if not filename or not isinstance(filename, str) or filename.isspace():
            raise ValueError("Filename must be a non-empty string")

        # Parse the code to get relevant information
        try:
            parsed_code = self.code_parser.parse(code_content, filename)
        except Exception as e:
            logging.error(f"Failed to parse code: {str(e)}")
            raise ValueError(f"Invalid code content: {str(e)}")

        # Generate and validate the security analysis prompt
        analysis_prompt = self._generate_security_prompt(parsed_code)
        if not analysis_prompt:
            raise ValueError("Failed to generate analysis prompt")

        # Get AI analysis with retry logic
        try:
            analysis_result = await self._get_analysis_with_retry(analysis_prompt)
        except Exception as e:
            logging.error(f"AI analysis failed: {str(e)}")
            raise RuntimeError(f"Security analysis failed: {str(e)}")

        # Process vulnerabilities with enhanced error handling
        try:
            # Process and validate vulnerabilities
            vulnerabilities = self._process_ai_response(analysis_result)

            # Chain vulnerabilities to find compound risks
            chained_vulnerabilities = self._chain_vulnerabilities(vulnerabilities)

            # Create and return the report
            report = VulnerabilityReport(
                file_name=filename,
                vulnerabilities=vulnerabilities,
                chained_vulnerabilities=chained_vulnerabilities,
                timestamp=datetime.now()
            )

            # Calculate summary statistics
            report.calculate_summary()
            report.calculate_risk_score()

            return report
        except Exception as e:
            logging.error(f"Failed during vulnerability processing: {str(e)}")
            # Return a basic report without detailed processing instead of failing
            return VulnerabilityReport(
                file_name=filename,
                vulnerabilities=[],
                chained_vulnerabilities=[],
                timestamp=datetime.now()
            )

    async def _get_analysis_with_retry(self, prompt: str, max_retries: int = 3) -> Dict[str, Any]:
        """
        Get AI analysis with retry logic and caching

        Args:
            prompt: The analysis prompt
            max_retries: Maximum number of retry attempts

        Returns:
            Dict[str, Any]: The analysis result

        Raises:
            RuntimeError: If all retry attempts fail
        """

        for attempt in range(max_retries):
            try:
                return await self.ai_client.analyze_security(prompt)
            except Exception as e:
                if attempt == max_retries - 1:
                    raise RuntimeError(f"Failed to get AI analysis after {max_retries} attempts: {str(e)}")
                logging.warning(f"Retry {attempt + 1}/{max_retries} failed: {str(e)}")
                continue

    def _chain_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> List[VulnerabilityChain]:
        """
        Identify chains of related vulnerabilities with improved detection logic

        Args:
            vulnerabilities: List of vulnerabilities to analyze

        Returns:
            List[VulnerabilityChain]: List of vulnerability chains
        """

        chains: List[VulnerabilityChain] = []
        visited: Set[str] = set()

        for vuln in vulnerabilities:
            if vuln.id in visited:
                continue

            # Find related vulnerabilities with improved relationship detection
            related_vulns = self._find_related_vulnerabilities(vuln, vulnerabilities)
            if len(related_vulns) > 1:
                chain = VulnerabilityChain(
                    vulnerabilities=related_vulns,
                    combined_severity=self._calculate_chain_severity(related_vulns),
                    attack_path=self._generate_attack_path(related_vulns),
                    likelihood=self._calculate_likelihood(related_vulns),
                    prerequisites=self._calculate_prerequisites(related_vulns),
                    mitigation_priority=self._calculate_mitigation_priority(related_vulns)
                )
                chains.append(chain)

            visited.update(v.id for v in related_vulns)

        return chains

    def _calculate_chain_severity(self, chain: List[Vulnerability]) -> VulnerabilitySeverity:
        """
        Calculate the combined severity of a vulnerability chain
        """

        # Define severity weights
        severity_weights = {
            VulnerabilitySeverity.CRITICAL: 5,
            VulnerabilitySeverity.HIGH: 4,
            VulnerabilitySeverity.MEDIUM: 3,
            VulnerabilitySeverity.LOW: 2,
            VulnerabilitySeverity.INFO: 1
        }

        # Calculate the maximum severity in the chain
        max_severity = max(severity_weights[v.severity] for v in chain)

        # Increase severity based on chain length
        chain_multiplier = 1 + (len(chain) - 1) * 0.2

        # Calculate the weighted severity
        weighted_severity = max_severity * chain_multiplier

        # Map back to VulnerabilitySeverity enum
        if weighted_severity >= 5:
            return VulnerabilitySeverity.CRITICAL
        elif weighted_severity >= 4:
            return VulnerabilitySeverity.HIGH
        elif weighted_severity >= 3:
            return VulnerabilitySeverity.MEDIUM
        elif weighted_severity >= 2:
            return VulnerabilitySeverity.LOW

        return VulnerabilitySeverity.INFO

    async def analyze_repository(
        self,
        repo_url: str,
        branch: str = "main",
        scan_depth: int = 3
    ) -> VulnerabilityReport:
        """
        Analyze an entire repository for security vulnerabilities

        Args:
            repo_url: The URL of the repository to analyze
            branch: The branch to analyze (default: "main")
            scan_depth: The depth to scan the repository (default: 3)

        Returns:
            VulnerabilityReport: The vulnerability report
        """

        # Clone/fetch repository
        repo_path = await self._fetch_repository(repo_url, branch)

        # Get all relevant files
        files_to_analyze = self._get_repository_files(repo_path, scan_depth)

        # Analyze each file
        all_vulnerabilities = []
        for file_path in files_to_analyze:
            with open(file_path, 'r') as f:
                content = f.read()
            report = await self.analyze_code(content, str(file_path))
            all_vulnerabilities.extend(report.vulnerabilities)

        # Chain vulnerabilities across files
        chained_vulnerabilities = self._chain_vulnerabilities(all_vulnerabilities)

        return VulnerabilityReport(
            repository_url=repo_url,
            branch=branch,
            vulnerabilities=all_vulnerabilities,
            chained_vulnerabilities=chained_vulnerabilities,
            timestamp=datetime.now()
        )

    def _generate_security_prompt(self, parsed_code: Dict[str, Any]) -> str:
        """
        Generate a prompt for security analysis
        """

        return f"""Perform a comprehensive security analysis of this {parsed_code['language']} code. Follow this methodology:
1. Identify vulnerabilities from these categories:
    - OWASP Top 10 2023
    - SANS/CWE Top 25
    - Language-specific security pitfalls
    - Framework-specific misconfigurations

2. For each finding include:
    - Vulnerability type (use exact CWE/OWASP names)
    - CVSS 3.1 vector string
    - Data flow analysis of the vulnerability
    - Taint propagation path
    - Secure alternative implementation
    - Severity level
    - Location in code
    - Description of the issue
    - Potential impact
    - Recommended fixes with secure code example

3. Code Context:
    - Imports: {parsed_code.get('imports', [])}
    - Functions: {[f['name'] for f in parsed_code.get('functions', [])]}
    - Classes: {[c['name'] for c in parsed_code.get('classes', [])]}
    - File type: {parsed_code['file_type']}

4. Analysis Requirements:
    - Validate user input sources
    - Check data sanitization flows
    - Verify proper authz checks
    - Confirm secure defaults
    - Ensure error handling doesn't leak secrets

{parsed_code['content']}

Format response as JSON matching the Vulnerability model structure.
"""

    def _process_ai_response(self, analysis_result: Dict[str, Any]) -> List[Vulnerability]:
        """
        Process and validate the AI analysis response into Vulnerability objects.

        Args:
            analysis_result: Raw analysis result from AI

        Returns:
            List[Vulnerability]: List of validated vulnerabilities
        """

        vulnerabilities = []
        unprocessed_types = set()

        for vuln_data in analysis_result.get('vulnerabilities', []):
            try:
                # Convert CVSS string to float score
                if isinstance(vuln_data.get('cvss_score'), str):
                    if vuln_data['cvss_score'].startswith('CVSS:'):
                        cvss_metrics = vuln_data['cvss_score'].split('/')
                        severity_metrics = [m for m in cvss_metrics if ':' in m and m[0] in 'CIA']

                        score = 0.0
                        for metric in severity_metrics:
                            if metric.endswith(':H'):
                                score += 3.3
                            elif metric.endswith(':M'):
                                score += 2.0
                            elif metric.endswith(':L'):
                                score += 1.0

                        vuln_data['cvss_score'] = min(10.0, score)
                    else:
                        vuln_data['cvss_score'] = 5.0

                # Map severity strings to VulnerabilitySeverity enum
                severity_mapping = {
                    'CRITICAL': VulnerabilitySeverity.CRITICAL,
                    'HIGH': VulnerabilitySeverity.HIGH,
                    'MEDIUM': VulnerabilitySeverity.MEDIUM,
                    'LOW': VulnerabilitySeverity.LOW,
                    'INFO': VulnerabilitySeverity.INFO,
                    # Add case-insensitive variations
                    'Critical': VulnerabilitySeverity.CRITICAL,
                    'High': VulnerabilitySeverity.HIGH,
                    'Medium': VulnerabilitySeverity.MEDIUM,
                    'Low': VulnerabilitySeverity.LOW,
                    'Info': VulnerabilitySeverity.INFO
                }

                # Convert severity string to enum value
                severity_str = vuln_data.get('severity', 'MEDIUM').upper()
                severity = severity_mapping.get(severity_str, VulnerabilitySeverity.MEDIUM)

                # Handle vulnerability type mapping
                try:
                    vuln_type = VulnerabilityType(vuln_data['type'])
                except ValueError:
                    # Map common variations to standard types
                    type_mapping = {
                        'HARD_CODED_CREDENTIALS': VulnerabilityType.HARDCODED_CREDENTIALS,
                        'HARDCODED_CREDENTIAL': VulnerabilityType.HARDCODED_CREDENTIALS,
                        'WEAK_PASSWORD': VulnerabilityType.BROKEN_AUTHENTICATION,
                        'WEAK_PASSWORDS': VulnerabilityType.BROKEN_AUTHENTICATION,
                        'AUTH_BYPASS': VulnerabilityType.BROKEN_AUTHENTICATION,
                        'INSECURE_CONFIGURATION': VulnerabilityType.SECURITY_MISCONFIGURATION,
                        'MISCONFIGURATION': VulnerabilityType.SECURITY_MISCONFIGURATION,
                        'XSS': VulnerabilityType.CROSS_SITE_SCRIPTING,
                        'CROSS_SITE_SCRIPT': VulnerabilityType.CROSS_SITE_SCRIPTING,
                        'SQL_INJECTION_VULNERABILITY': VulnerabilityType.SQL_INJECTION,
                        'SQLI': VulnerabilityType.SQL_INJECTION,
                        'RCE': VulnerabilityType.REMOTE_CODE_EXECUTION,
                        'REMOTE_CODE_EXEC': VulnerabilityType.REMOTE_CODE_EXECUTION,
                        'COMMAND_EXEC': VulnerabilityType.OS_COMMAND_INJECTION,
                        'OS_COMMAND_EXEC': VulnerabilityType.OS_COMMAND_INJECTION,
                        'PATH_TRAVERSAL_VULNERABILITY': VulnerabilityType.PATH_TRAVERSAL,
                        'DIRECTORY_TRAVERSAL': VulnerabilityType.PATH_TRAVERSAL,
                        'IDOR': VulnerabilityType.INSECURE_DIRECT_OBJECT_REFERENCE,
                        'DIRECT_OBJECT_REFERENCE': VulnerabilityType.INSECURE_DIRECT_OBJECT_REFERENCE,
                    }

                    original_type = vuln_data['type']
                    mapped_type = type_mapping.get(original_type)

                    if mapped_type is None:
                        # IMPORTANT CHANGE: Instead of skipping with continue, use a default type
                        logging.warning(f"Unknown vulnerability type encountered: {original_type}. Using GENERIC_SECURITY_ISSUE as fallback.")
                        unprocessed_types.add(original_type)
                        vuln_type = VulnerabilityType.GENERIC_SECURITY_ISSUE
                    else:
                        vuln_type = mapped_type
                        logging.info(f"Mapped vulnerability type '{original_type}' to '{vuln_type.value}'")

                # Create CodeLocation object
                location_data = vuln_data.get('location', {})
                location = CodeLocation(
                    file_path=location_data.get('file_path', ''),
                    start_line=location_data.get('start_line', 0),
                    end_line=location_data.get('end_line', 0),
                    start_col=location_data.get('start_col', 0),
                    end_col=location_data.get('end_col', 0),
                    context=location_data.get('context', '')
                )

                # Create Vulnerability object with validated data
                vulnerability = Vulnerability(
                    type=vuln_type,
                    severity=severity,
                    location=location,
                    description=vuln_data.get('description', ''),
                    impact=vuln_data.get('impact', ''),
                    remediation=vuln_data.get('remediation', ''),
                    cwe_id=vuln_data.get('cwe_id', ''),
                    owasp_category=vuln_data.get('owasp_category', ''),
                    cvss_score=float(vuln_data.get('cvss_score', 5.0)),
                    references=vuln_data.get('references', []),
                    proof_of_concept=vuln_data.get('proof_of_concept', ''),
                    secure_code_example=vuln_data.get('secure_code_example', '')
                )

                vulnerabilities.append(vulnerability)

            except Exception as e:
                logging.error(f"Error processing vulnerability: {vuln_data}. Error: {str(e)}")
                continue

        # Log summary of unprocessed types at the end
        if unprocessed_types:
            logging.warning(
                "Summary of unprocessed vulnerability types:\n" +
                "\n".join(f"- {t}" for t in sorted(unprocessed_types))
            )

        return vulnerabilities

    def _find_related_vulnerabilities(
        self,
        source_vuln: Vulnerability,
        all_vulns: List[Vulnerability]
    ) -> List[Vulnerability]:
        """
        Find vulnerabilities that could be chained together with improved detection logic.

        Args:
            source_vuln: The source vulnerability
            all_vulns: A list of all vulnerabilities

        Returns:
            List[Vulnerability]: A list of related vulnerabilities
        """

        related = [source_vuln]

        for vuln in all_vulns:
            if vuln.id != source_vuln.id:
                if self._are_vulnerabilities_related(source_vuln, vuln):
                    related.append(vuln)

        # Sort related vulnerabilities by severity
        related.sort(
            key=lambda v: {
                VulnerabilitySeverity.CRITICAL: 0,
                VulnerabilitySeverity.HIGH: 1,
                VulnerabilitySeverity.MEDIUM: 2,
                VulnerabilitySeverity.LOW: 3,
                VulnerabilitySeverity.INFO: 4
            }[v.severity]
        )

        return related

    def _are_vulnerabilities_related(
        self,
        vuln1: Vulnerability,
        vuln2: Vulnerability
    ) -> bool:
        """
        Determine if two vulnerabilities could be chained together with improved detection logic.

        Args:
            vuln1: The first vulnerability
            vuln2: The second vulnerability

        Returns:
            bool: True if vulnerabilities are related, False otherwise
        """

        # Check if vulnerabilities are in the same file or connected files
        same_file = vuln1.location.file_path == vuln2.location.file_path
        connected_files = self._are_files_connected(vuln1.location.file_path, vuln2.location.file_path)

        # Check if vulnerabilities are in a known attack chain
        in_attack_chain = (
            vuln2.type in self.attack_chains.get(vuln1.type, []) or
            vuln1.type in self.attack_chains.get(vuln2.type, [])
        )

        # Check if vulnerabilities share common attack vectors or prerequisites
        common_prerequisites = any(
            prereq in self._calculate_prerequisites([vuln2])
            for prereq in self._calculate_prerequisites([vuln1])
        )

        # Check for code proximity if in same file
        code_proximity = False
        if same_file:
            line_distance = abs(vuln1.location.start_line - vuln2.location.start_line)
            code_proximity = line_distance <= 10  # Consider vulnerabilities within 10 lines as related

        # Check for data flow relationship
        data_flow_related = self._check_data_flow_relationship(vuln1, vuln2)

        # Check for common security context
        security_context_related = self._share_security_context(vuln1, vuln2)

        # Calculate relationship score based on multiple factors
        relationship_score = sum([
            2.0 if in_attack_chain else 0.0,
            1.0 if same_file else (0.5 if connected_files else 0.0),
            1.0 if common_prerequisites else 0.0,
            1.0 if code_proximity else 0.0,
            1.5 if data_flow_related else 0.0,
            1.0 if security_context_related else 0.0
        ])

        # Consider vulnerabilities related if they score above threshold
        RELATIONSHIP_THRESHOLD = 2.0
        return relationship_score >= RELATIONSHIP_THRESHOLD

    def _are_files_connected(self, file1: str, file2: str) -> bool:
        """
        Determine if two files are connected through imports or references.

        Args:
            file1: Path to first file
            file2: Path to second file

        Returns:
            bool: True if files are connected, False otherwise
        """

        # Check if files are in same directory
        same_directory = Path(file1).parent == Path(file2).parent

        # Check if one file imports the other
        # This is a simplified check - could be enhanced with actual import analysis
        imports_connected = False
        try:
            with open(file1, 'r') as f:
                content1 = f.read()
            with open(file2, 'r') as f:
                content2 = f.read()

            file1_name = Path(file1).stem
            file2_name = Path(file2).stem

            imports_connected = (
                file2_name in content1 or
                file1_name in content2
            )
        except Exception:
            pass

        return same_directory or imports_connected

    def _check_data_flow_relationship(self, vuln1: Vulnerability, vuln2: Vulnerability) -> bool:
        """
        Check if vulnerabilities are related through data flow.

        Args:
            vuln1: First vulnerability
            vuln2: Second vulnerability

        Returns:
            bool: True if vulnerabilities are related through data flow
        """

        # Check if vulnerabilities involve similar data patterns
        data_patterns = {
            'user_input': ['input', 'request', 'param', 'query', 'form'],
            'file_operations': ['file', 'path', 'directory', 'read', 'write'],
            'database': ['sql', 'query', 'db', 'database'],
            'authentication': ['auth', 'login', 'password', 'credential'],
            'session': ['session', 'token', 'cookie']
        }

        def get_data_categories(vuln: Vulnerability) -> Set[str]:
            categories = set()
            text = f"{vuln.description} {vuln.impact}".lower()

            for category, patterns in data_patterns.items():
                if any(pattern in text for pattern in patterns):
                    categories.add(category)
            return categories

        vuln1_categories = get_data_categories(vuln1)
        vuln2_categories = get_data_categories(vuln2)

        return bool(vuln1_categories & vuln2_categories)

    def _share_security_context(self, vuln1: Vulnerability, vuln2: Vulnerability) -> bool:
        """
        Check if vulnerabilities share a common security context.

        Args:
            vuln1: First vulnerability
            vuln2: Second vulnerability

        Returns:
            bool: True if vulnerabilities share security context
        """

        # Define security contexts
        security_contexts = {
            'authentication': {
                VulnerabilityType.BROKEN_AUTHENTICATION,
                VulnerabilityType.HARDCODED_CREDENTIALS,
                VulnerabilityType.SENSITIVE_DATA_EXPOSURE
            },
            'injection': {
                VulnerabilityType.SQL_INJECTION,
                VulnerabilityType.OS_COMMAND_INJECTION,
                VulnerabilityType.CODE_INJECTION
            },
            'access_control': {
                VulnerabilityType.BROKEN_ACCESS_CONTROL,
                VulnerabilityType.INSECURE_DIRECT_OBJECT_REFERENCE,
                VulnerabilityType.CSRF
            },
            'data_exposure': {
                VulnerabilityType.SENSITIVE_DATA_EXPOSURE,
                VulnerabilityType.INFORMATION_EXPOSURE_THROUGH_QUERY_STRING,
                VulnerabilityType.EXPOSED_SENSITIVE_INFORMATION
            }
        }

        # Check if vulnerabilities belong to the same security context
        for context_types in security_contexts.values():
            if vuln1.type in context_types and vuln2.type in context_types:
                return True

        return False

    def _generate_attack_path(self, chain: List[Vulnerability]) -> str:
        """
        Generate a detailed description of the attack path based on the vulnerabilities in the chain.

        Args:
            chain: List of vulnerabilities in the chain

        Returns:
            str: A detailed description of the potential attack path
        """

        if not chain:
            return "No attack path identified"

        # Sort vulnerabilities by severity to prioritize critical/high severity entries
        sorted_chain = sorted(
            chain,
            key=lambda v: {
                VulnerabilitySeverity.CRITICAL: 0,
                VulnerabilitySeverity.HIGH: 1,
                VulnerabilitySeverity.MEDIUM: 2,
                VulnerabilitySeverity.LOW: 3,
                VulnerabilitySeverity.INFO: 4
            }[v.severity]
        )

        # Build the attack path description
        path_steps = []

        for i, vuln in enumerate(sorted_chain, 1):
            # Format the location for better readability
            location = f"{vuln.location.file_path}:{vuln.location.start_line}"
            if vuln.location.end_line != vuln.location.start_line:
                location += f"-{vuln.location.end_line}"

            # Create a detailed step description
            step = (
                f"Step {i}: {vuln.type.value} ({vuln.severity.value})\n"
                f"   Location: {location}\n"
                f"   Attack Vector: {vuln.description.split('.')[0]}\n"
                f"   Potential Impact: {vuln.impact.split('.')[0]}"
            )
            path_steps.append(step)

            # Add connection description between steps
            if i < len(sorted_chain):
                next_vuln = sorted_chain[i]
                if self._are_vulnerabilities_related(vuln, next_vuln):
                    path_steps.append(
                        f"   ↓ Chain Effect: This vulnerability could facilitate or amplify the next attack step"
                    )
                else:
                    path_steps.append(
                        f"   ↓ Parallel Attack: This vulnerability can be exploited independently"
                    )

        # Add overall chain severity and prerequisites
        chain_severity = self._calculate_chain_severity(sorted_chain)
        prerequisites = self._calculate_prerequisites(sorted_chain)

        header = (
            f"Attack Chain Severity: {chain_severity.value}\n"
            f"Prerequisites: {', '.join(prerequisites)}\n"
            f"Attack Path Analysis:\n"
        )

        return header + "\n".join(path_steps)

    def _calculate_likelihood(self, chain: List[Vulnerability]) -> float:
        """
        Calculate the likelihood of a successful attack based on the vulnerabilities in the chain.
        Uses multiple factors including severity, prerequisites, and chain complexity.

        Args:
            chain: List of vulnerabilities in the chain

        Returns:
            float: A value representing the likelihood of a successful attack (0.0 to 1.0)
        """

        if not chain:
            return 0.0

        # Base weights for different factors
        severity_weights = {
            VulnerabilitySeverity.CRITICAL: 1.0,
            VulnerabilitySeverity.HIGH: 0.8,
            VulnerabilitySeverity.MEDIUM: 0.6,
            VulnerabilitySeverity.LOW: 0.4,
            VulnerabilitySeverity.INFO: 0.2
        }

        # Calculate base likelihood from severity
        base_likelihood = sum(severity_weights[v.severity] for v in chain) / len(chain)

        # Adjust based on prerequisites complexity
        prereqs = self._calculate_prerequisites(chain)
        prereq_complexity = len(prereqs) * 0.1  # More prerequisites reduce likelihood

        # Adjust based on chain complexity
        chain_complexity = 1.0
        if len(chain) > 1:
            # Longer chains are harder to exploit
            chain_complexity = 1.0 - (len(chain) - 1) * 0.1

            # Check for related vulnerabilities which might make exploitation easier
            related_pairs = sum(
                1 for i, v1 in enumerate(chain[:-1])
                for v2 in chain[i+1:]
                if self._are_vulnerabilities_related(v1, v2)
            )
            if related_pairs:
                chain_complexity += related_pairs * 0.05  # Related vulns increase likelihood

        # Additional factors that affect likelihood
        factors = {
            'has_public_exploit': 1.2,  # Increase if public exploits exist
            'requires_authentication': 0.7,  # Decrease if auth required
            'requires_user_interaction': 0.8,  # Decrease if user interaction needed
            'network_accessible': 1.1  # Increase if remotely exploitable
        }

        # Apply relevant factors based on vulnerability types
        factor_multiplier = 1.0
        for vuln in chain:
            if 'CVE' in vuln.references:  # Has public exploit
                factor_multiplier *= factors['has_public_exploit']
            if 'authentication' in vuln.description.lower():
                factor_multiplier *= factors['requires_authentication']
            if 'user interaction' in vuln.description.lower():
                factor_multiplier *= factors['requires_user_interaction']
            if 'remote' in vuln.description.lower():
                factor_multiplier *= factors['network_accessible']

        # Calculate final likelihood
        likelihood = (
            base_likelihood *
            max(0.1, chain_complexity) *
            max(0.1, 1.0 - prereq_complexity) *
            factor_multiplier
        )

        # Ensure result is between 0 and 1
        return round(min(1.0, max(0.0, likelihood)), 4)

    def _calculate_prerequisites(self, chain: List[Vulnerability]) -> List[str]:
        """
        Determine the prerequisites for exploiting the vulnerabilities in the chain.
        Analyzes vulnerability types, descriptions, and relationships to identify required conditions.

        Args:
            chain: List of vulnerabilities in the chain

        Returns:
            List[str]: A list of prerequisites needed to exploit the vulnerabilities
        """

        if not chain:
            return ["None"]

        prerequisites = set()

        # Common prerequisite patterns to check for
        auth_patterns = ['authentication', 'login', 'credentials', 'session']
        access_patterns = ['local access', 'physical access', 'network access', 'admin access']
        user_patterns = ['user interaction', 'user input', 'user-supplied']
        config_patterns = ['configuration', 'settings', 'environment']

        for vuln in chain:
            # Check vulnerability type specific prerequisites
            type_prereqs = {
                VulnerabilityType.SQL_INJECTION: ['Database access', 'Input injection point'],
                VulnerabilityType.CROSS_SITE_SCRIPTING: ['Active user session', 'Input reflection point'],
                VulnerabilityType.CSRF: ['Active user session', 'Predictable form structure'],
                VulnerabilityType.PATH_TRAVERSAL: ['File system access', 'Directory traversal point'],
                VulnerabilityType.OS_COMMAND_INJECTION: ['Command execution context', 'Input injection point'],
                VulnerabilityType.INSECURE_DESERIALIZATION: ['Serialized data input', 'Custom class definitions']
            }

            # Add type-specific prerequisites
            if vuln.type in type_prereqs:
                prerequisites.update(type_prereqs[vuln.type])

            # Analyze description and impact for additional prerequisites
            desc_lower = vuln.description.lower()
            impact_lower = vuln.impact.lower()

            # Check for authentication requirements
            if any(pattern in desc_lower for pattern in auth_patterns):
                prerequisites.add('Valid authentication credentials')

            # Check for access requirements
            if any(pattern in desc_lower for pattern in access_patterns):
                if 'local' in desc_lower:
                    prerequisites.add('Local system access')
                if 'physical' in desc_lower:
                    prerequisites.add('Physical device access')
                if 'network' in desc_lower:
                    prerequisites.add('Network connectivity')
                if 'admin' in desc_lower:
                    prerequisites.add('Administrative privileges')

            # Check for user interaction requirements
            if any(pattern in desc_lower for pattern in user_patterns):
                prerequisites.add('User interaction')

            # Check for configuration requirements
            if any(pattern in desc_lower for pattern in config_patterns):
                if 'debug' in desc_lower:
                    prerequisites.add('Debug mode enabled')
                if 'environment' in desc_lower:
                    prerequisites.add('Specific environment configuration')

            # Check CVSS metrics if available
            if hasattr(vuln, 'cvss_score') and vuln.cvss_score:
                if vuln.cvss_score >= 7.0:
                    prerequisites.add('No special access required (High severity)')
                elif 'network' in desc_lower:
                    prerequisites.add('Network access')

            # Add specific technical prerequisites based on vulnerability details
            if 'bypass' in impact_lower:
                prerequisites.add('Knowledge of security mechanism')
            if 'memory' in impact_lower:
                prerequisites.add('Memory manipulation capability')
            if 'race condition' in desc_lower:
                prerequisites.add('Ability to perform concurrent requests')

        # Sort prerequisites for consistent output
        return sorted(list(prerequisites))

    def _calculate_mitigation_priority(self, chain: List[Vulnerability]) -> int:
        """
        Calculate the priority for mitigating the vulnerabilities in the chain.

        Args:
            chain: List of vulnerabilities in the chain

        Returns:
            int: A priority level for mitigation (1 = highest priority, higher numbers = lower priority)
        """

        # Mapping of severity levels to numeric values
        severity_to_value = {
            VulnerabilitySeverity.CRITICAL: 1,
            VulnerabilitySeverity.HIGH: 2,
            VulnerabilitySeverity.MEDIUM: 3,
            VulnerabilitySeverity.LOW: 4,
            VulnerabilitySeverity.INFO: 5
        }

        if not chain:
            return 5  # Default low priority if no vulnerabilities

        return max(severity_to_value[vuln.severity] for vuln in chain)  # Assuming lower severity value means higher priority

    async def _fetch_repository(self, repo_url: str, branch: str) -> str:
        """
        Clone or fetch the repository from the given URL.

        Args:
            repo_url: The URL of the repository to clone or fetch
            branch: The branch to check out

        Returns:
            str: The local path to the cloned or fetched repository
        """

        # Validate the repo_url format
        if not re.match(r'^https?://', repo_url):
            raise ValueError("Invalid repository URL")

        repo_name = re.sub(r'[^a-zA-Z0-9_\-]', '_', repo_url.split('/')[-1].replace('.git', ''))

        # Get system-appropriate temporary directory
        if os.name == 'nt':  # Windows
            temp_dir = os.path.join(os.environ.get('TEMP') or os.environ.get('TMP') or 'C:\\Windows\\Temp')
        else:  # Unix-like systems
            temp_dir = '/tmp'

        repo_path = os.path.normpath(os.path.join(temp_dir, repo_name))

        # Ensure the repo_path is within the temp directory
        if not repo_path.startswith(os.path.normpath(temp_dir)):
            raise ValueError("Invalid repository path")

        if os.path.exists(repo_path):
            # If the repository already exists, fetch the latest changes
            repo = git.Repo(repo_path)
            origin = repo.remotes.origin
            origin.fetch()
            repo.git.checkout(branch)
        else:
            # Clone the repository if it doesn't exist
            repo = git.Repo.clone_from(repo_url, repo_path, branch=branch)

        return repo_path

    def _get_repository_files(self, repo_path: str, scan_depth: int) -> List[str]:
        """
        Get all relevant files from the repository up to a specified scan depth.

        Args:
            repo_path: The local path to the repository
            scan_depth: The depth to scan the repository

        Returns:
            List[str]: A list of file paths to analyze
        """

        relevant_files = []
        for root, dirs, files in os.walk(repo_path):
            # Calculate the current depth
            current_depth = root.count(os.sep) - repo_path.count(os.sep)
            if current_depth < scan_depth:
                for file in files:
                    file_path = os.path.join(root, file)
                    # Add logic to filter files if needed (e.g., only .py files)
                    if file.endswith('.py'):  # Example: only analyze Python files
                        relevant_files.append(file_path)

        return relevant_files