# security/code_inspector.py

import asyncio
import logging
import os
import re
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Third-party dependencies
import git

# Local imports
from models.security_types import (
    CodePosition,
    IssueChain,
    RiskSeverity,
    SecurityAnalysisReport,
    SecurityIssue,
    SecurityIssueCategory
)
from utils.ai_service import SecurityAnalysisService, ModelProvider, SecurityAnalysisConfig
from utils.code_processor import CodeProcessor

class CodeInspector:
    """
    Inspector class for analyzing code and identifying security issues.
    Uses AI services to detect vulnerabilities and builds relationship chains.
    """

    def __init__(self, 
                 analysis_service: Optional[SecurityAnalysisService] = None,
                 code_processor: Optional[CodeProcessor] = None) -> None:
        """
        Initialize the code inspector with services and attack pattern database.
        
        Args:
            analysis_service: Optional custom SecurityAnalysisService instance
            code_processor: Optional custom CodeProcessor instance
        """
        self.logger = logging.getLogger(__name__)
        
        # Initialize services or use provided ones
        self.analysis_service = analysis_service or SecurityAnalysisService()
        self.code_processor = code_processor or CodeProcessor()
        
        # Cache for repository paths
        self._repo_cache: Dict[str, str] = {}
        
        # Load attack pattern database
        self.attack_patterns = self._load_attack_patterns()
    
    def _load_attack_patterns(self) -> Dict[SecurityIssueCategory, List[SecurityIssueCategory]]:
        """
        Load the database of potential attack chains and relationships.
        
        Returns:
            Dictionary mapping vulnerability types to related vulnerability types
        """
        # Define common attack chains between vulnerability types
        return {
            SecurityIssueCategory.SQL_INJECTION: [
                SecurityIssueCategory.BROKEN_AUTHENTICATION,
                SecurityIssueCategory.SENSITIVE_DATA_EXPOSURE,
                SecurityIssueCategory.BROKEN_ACCESS_CONTROL
            ],
            SecurityIssueCategory.CROSS_SITE_SCRIPTING: [
                SecurityIssueCategory.BROKEN_AUTHENTICATION,
                SecurityIssueCategory.CSRF,
                SecurityIssueCategory.SENSITIVE_DATA_EXPOSURE
            ],
            SecurityIssueCategory.BROKEN_AUTHENTICATION: [
                SecurityIssueCategory.BROKEN_ACCESS_CONTROL,
                SecurityIssueCategory.SENSITIVE_DATA_EXPOSURE,
                SecurityIssueCategory.INSECURE_DIRECT_OBJECT_REFERENCE
            ],
            SecurityIssueCategory.PATH_TRAVERSAL: [
                SecurityIssueCategory.FILE_INCLUSION,
                SecurityIssueCategory.REMOTE_CODE_EXECUTION,
                SecurityIssueCategory.SENSITIVE_DATA_EXPOSURE
            ],
            SecurityIssueCategory.INSECURE_DESERIALIZATION: [
                SecurityIssueCategory.REMOTE_CODE_EXECUTION,
                SecurityIssueCategory.OS_COMMAND_INJECTION,
                SecurityIssueCategory.CODE_INJECTION
            ],
            SecurityIssueCategory.EXPOSED_SECRET: [
                SecurityIssueCategory.HARDCODED_CREDENTIALS,
                SecurityIssueCategory.SENSITIVE_DATA_EXPOSURE,
                SecurityIssueCategory.BROKEN_AUTHENTICATION
            ],
            SecurityIssueCategory.INSUFFICIENT_INPUT_VALIDATION: [
                SecurityIssueCategory.INJECTION,
                SecurityIssueCategory.CROSS_SITE_SCRIPTING,
                SecurityIssueCategory.SQL_INJECTION,
                SecurityIssueCategory.OS_COMMAND_INJECTION
            ]
        }
    
    async def inspect_code(self, code_content: str, filename: str) -> SecurityAnalysisReport:
        """
        Analyze a single file for security issues with comprehensive validation.
        
        Args:
            code_content: The source code content to analyze
            filename: The name of the file
            
        Returns:
            SecurityAnalysisReport containing identified issues and chains
        """
        # Validate and standardize inputs
        code_content = str(code_content)
        if not code_content or code_content.isspace():
            self.logger.info(f"Skipping empty file: {filename}")
            return SecurityAnalysisReport(
                target_file=filename,
                issues=[],
                issue_chains=[]
            )
        
        if not filename or filename.isspace():
            raise ValueError("Filename must be a non-empty string")
        
        # Process code to extract relevant structural information 
        try:
            processed_code = self.code_processor.process(code_content, filename)
        except Exception as e:
            self.logger.error(f"Code processing failed: {str(e)}")
            raise ValueError(f"Invalid code content: {str(e)}")
        
        # Generate AI analysis prompt from processed code
        analysis_prompt = self._create_analysis_prompt(processed_code)
        
        # Send for AI analysis with retries
        try:
            analysis_result = await self._get_analysis_with_retries(analysis_prompt)
        except Exception as e:
            self.logger.error(f"AI security analysis failed: {str(e)}")
            raise RuntimeError(f"Security analysis failed: {str(e)}")
        
        # Transform AI results into structured security issues
        try:
            issues = self._transform_analysis_to_issues(analysis_result, filename)
            
            # Build chains of related issues
            issue_chains = self._build_issue_chains(issues)
            
            # Create comprehensive report
            report = SecurityAnalysisReport(
                target_file=filename,
                issues=issues,
                issue_chains=issue_chains
            )
            
            # Calculate statistics and risk rating
            report.calculate_stats()
            report.calculate_risk_rating()
            
            return report
        except Exception as e:
            self.logger.error(f"Report generation failed: {str(e)}")
            # Return minimal report rather than failing completely
            return SecurityAnalysisReport(
                target_file=filename,
                issues=[],
                issue_chains=[]
            )
    
    async def _get_analysis_with_retries(self, prompt: str, max_retries: int = 3) -> Dict[str, Any]:
        """
        Get AI analysis with retry logic and result caching.
        
        Args:
            prompt: The analysis prompt
            max_retries: Maximum retry attempts
            
        Returns:
            Analysis result dictionary
            
        Raises:
            RuntimeError: If all retry attempts fail
        """
        last_error = None
        
        for attempt in range(max_retries):
            try:
                self.logger.debug(f"Analysis attempt {attempt + 1}/{max_retries}")
                return await self.analysis_service.analyze_code_security(prompt)
            except Exception as e:
                last_error = e
                self.logger.warning(f"Analysis retry {attempt + 1}/{max_retries} failed: {str(e)}")
                # Wait with exponential backoff before retrying
                if attempt < max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
        
        # If we get here, all retries failed
        raise RuntimeError(f"Analysis failed after {max_retries} attempts: {str(last_error)}")
    
    def _create_analysis_prompt(self, processed_code: Dict[str, Any]) -> str:
        """
        Create a detailed prompt for security analysis.
        
        Args:
            processed_code: Dictionary with processed code information
            
        Returns:
            Formatted analysis prompt string
        """
        language = processed_code.get('language', 'Unknown')
        file_type = processed_code.get('file_type', 'unknown')
        imports = processed_code.get('imports', [])
        functions = [f.get('name', '') for f in processed_code.get('functions', [])]
        classes = [c.get('name', '') for c in processed_code.get('classes', [])]
        
        prompt = f"""Perform a detailed security analysis of this {language} code file.

Code Context Information:
- File name: {processed_code.get('file_name', 'unknown')}
- Language: {language}
- File type: {file_type}
- Total lines: {processed_code.get('line_count', 0)}
- Imports/Dependencies: {', '.join(imports) if imports else 'None'}
- Functions defined: {', '.join(functions) if functions else 'None'}
- Classes defined: {', '.join(classes) if classes else 'None'}

Analysis Guidelines:
1. Identify security vulnerabilities from these categories:
   - OWASP Top 10 (2021 edition)
   - SANS/CWE Top 25 security weaknesses
   - {language}-specific security vulnerabilities
   - Security best practices and secure coding patterns

2. For each identified issue, provide:
   - Precise vulnerability categorization
   - Severity assessment with CVSS score
   - Exact code location (line numbers)
   - Issue description and potential impact
   - Remediation recommendations with secure code examples
   - CWE ID and OWASP category mapping
   - References to security standards or documentation

3. Pay particular attention to:
   - Input validation and sanitization
   - Authentication and authorization mechanisms
   - Data encryption and protection
   - Error handling and information exposure
   - Secure dependency management
   - Configuration security

SOURCE CODE:
{processed_code.get('content', '')}

Please format your response as a JSON object matching the required SecurityIssue structure.
"""
        return prompt
    
    def _transform_analysis_to_issues(self, analysis_result: Dict[str, Any], 
                                      file_path: str) -> List[SecurityIssue]:
        """
        Transform raw analysis results into structured SecurityIssue objects.
        
        Args:
            analysis_result: Raw analysis result from AI service
            file_path: Path to the analyzed file
            
        Returns:
            List of validated SecurityIssue objects
        """
        issues = []
        unprocessed_types = set()
        
        for issue_data in analysis_result.get('vulnerabilities', []):
            try:
                # Process CVSS score
                cvss_score = self._process_cvss_score(issue_data.get('cvss_score', 5.0))
                
                # Map severity
                severity = self._map_severity(issue_data.get('severity', 'MEDIUM'), cvss_score)
                
                # Map and validate issue category
                try:
                    category = SecurityIssueCategory(issue_data.get('type', 'GENERIC_SECURITY_ISSUE'))
                except ValueError:
                    # Map to known types or use generic fallback
                    original_type = issue_data.get('type', '')
                    mapped_category = self._map_issue_category(original_type)
                    
                    if mapped_category is None:
                        self.logger.warning(f"Unknown issue category: {original_type}")
                        unprocessed_types.add(original_type)
                        category = SecurityIssueCategory.GENERIC_SECURITY_ISSUE
                    else:
                        category = mapped_category
                
                # Create CodePosition
                location_data = issue_data.get('location', {})
                position = CodePosition(
                    file_path=file_path or location_data.get('file_path', ''),
                    start_line=int(location_data.get('start_line', 0)),
                    end_line=int(location_data.get('end_line', 0)),
                    start_column=location_data.get('start_col'),
                    end_column=location_data.get('end_col'),
                    code_context=location_data.get('context', '')
                )
                
                # Create SecurityIssue
                issue = SecurityIssue(
                    category=category,
                    severity=severity,
                    position=position,
                    description=issue_data.get('description', ''),
                    impact=issue_data.get('impact', ''),
                    remediation=issue_data.get('remediation', ''),
                    cwe_id=issue_data.get('cwe_id', ''),
                    owasp_category=issue_data.get('owasp_category', ''),
                    cvss_score=cvss_score,
                    references=issue_data.get('references', []),
                    proof_of_concept=issue_data.get('proof_of_concept', ''),
                    secure_alternative=issue_data.get('secure_code_example', '')
                )
                
                issues.append(issue)
                
            except Exception as e:
                self.logger.error(f"Error processing issue: {str(e)}")
                continue
        
        # Log summary of unprocessed types
        if unprocessed_types:
            self.logger.warning(f"Unprocessed issue types: {', '.join(sorted(unprocessed_types))}")
        
        return issues
    
    def _process_cvss_score(self, cvss_value: Any) -> float:
        """
        Process and normalize CVSS score from various formats.
        
        Args:
            cvss_value: Raw CVSS value (string, float, etc.)
            
        Returns:
            Normalized float CVSS score
        """
        if isinstance(cvss_value, (int, float)):
            return float(min(10.0, max(0.0, cvss_value)))
        
        if isinstance(cvss_value, str):
            # Handle CVSS vector strings
            if cvss_value.startswith('CVSS:'):
                # Extract base score or calculate from components
                vector_parts = cvss_value.split('/')
                
                # Look for explicit base score
                base_score_part = next((p for p in vector_parts if p.startswith('BS:')), None)
                if base_score_part:
                    try:
                        return float(base_score_part.split(':')[1])
                    except (IndexError, ValueError):
                        pass
                
                # Calculate from CIA components
                severity_metrics = [m for m in vector_parts if ':' in m and m[0] in 'CIA']
                score = 0.0
                for metric in severity_metrics:
                    if metric.endswith(':H'):
                        score += 3.3
                    elif metric.endswith(':M'):
                        score += 2.0
                    elif metric.endswith(':L'):
                        score += 1.0
                
                return min(10.0, score)
            
            # Try to parse as float
            try:
                return float(min(10.0, max(0.0, float(cvss_value))))
            except ValueError:
                pass
        
        # Default fallback
        return 5.0
    
    def _map_severity(self, severity_str: str, cvss_score: float) -> RiskSeverity:
        """
        Map severity string to RiskSeverity enum.
        
        Args:
            severity_str: Raw severity string
            cvss_score: CVSS score as fallback
            
        Returns:
            Mapped RiskSeverity enum value
        """
        severity_mapping = {
            'CRITICAL': RiskSeverity.CRITICAL,
            'HIGH': RiskSeverity.HIGH,
            'MEDIUM': RiskSeverity.MEDIUM,
            'LOW': RiskSeverity.LOW,
            'INFO': RiskSeverity.INFO,
            'INFORMATIONAL': RiskSeverity.INFO,
            'NONE': RiskSeverity.INFO
        }
        
        # Try case-insensitive mapping
        upper_severity = severity_str.upper()
        if upper_severity in severity_mapping:
            return severity_mapping[upper_severity]
        
        # Fallback to CVSS-based severity
        return RiskSeverity.from_cvss(cvss_score)
    
    def _map_issue_category(self, category_str: str) -> Optional[SecurityIssueCategory]:
        """
        Map raw issue category string to SecurityIssueCategory enum.
        
        Args:
            category_str: Raw category string
            
        Returns:
            Mapped SecurityIssueCategory or None if no match
        """
        # Common synonyms and variations
        category_mapping = {
            'HARD_CODED_CREDENTIALS': SecurityIssueCategory.HARDCODED_CREDENTIALS,
            'HARDCODED_CREDENTIAL': SecurityIssueCategory.HARDCODED_CREDENTIALS,
            'WEAK_PASSWORD': SecurityIssueCategory.BROKEN_AUTHENTICATION,
            'WEAK_PASSWORDS': SecurityIssueCategory.BROKEN_AUTHENTICATION,
            'AUTH_BYPASS': SecurityIssueCategory.BROKEN_AUTHENTICATION,
            'INSECURE_CONFIGURATION': SecurityIssueCategory.SECURITY_MISCONFIGURATION,
            'MISCONFIGURATION': SecurityIssueCategory.SECURITY_MISCONFIGURATION,
            'XSS': SecurityIssueCategory.CROSS_SITE_SCRIPTING,
            'CROSS_SITE_SCRIPT': SecurityIssueCategory.CROSS_SITE_SCRIPTING,
            'SQL_INJECTION_VULNERABILITY': SecurityIssueCategory.SQL_INJECTION,
            'SQLI': SecurityIssueCategory.SQL_INJECTION,
            'RCE': SecurityIssueCategory.REMOTE_CODE_EXECUTION,
            'REMOTE_CODE_EXEC': SecurityIssueCategory.REMOTE_CODE_EXECUTION,
            'COMMAND_EXEC': SecurityIssueCategory.OS_COMMAND_INJECTION,
            'OS_COMMAND_EXEC': SecurityIssueCategory.OS_COMMAND_INJECTION,
            'PATH_TRAVERSAL_VULNERABILITY': SecurityIssueCategory.PATH_TRAVERSAL,
            'DIRECTORY_TRAVERSAL': SecurityIssueCategory.PATH_TRAVERSAL,
            'IDOR': SecurityIssueCategory.INSECURE_DIRECT_OBJECT_REFERENCE,
            'DIRECT_OBJECT_REFERENCE': SecurityIssueCategory.INSECURE_DIRECT_OBJECT_REFERENCE,
        }
        
        # Try direct mapping first
        if category_str in category_mapping:
            return category_mapping[category_str]
        
        # Try standardized version (replace spaces/hyphens with underscores)
        standardized = re.sub(r'[\s-]', '_', category_str.upper())
        if standardized in category_mapping:
            return category_mapping[standardized]
        
        # Try to match with enum values
        try:
            return SecurityIssueCategory(standardized)
        except ValueError:
            # Try similarity matching with enum values
            for enum_val in SecurityIssueCategory:
                if enum_val.value in standardized or standardized in enum_val.value:
                    return enum_val
        
        return None
    
    def _build_issue_chains(self, issues: List[SecurityIssue]) -> List[IssueChain]:
        """
        Identify chains of related security issues.
        
        Args:
            issues: List of security issues to analyze
            
        Returns:
            List of issue chains representing attack paths
        """
        chains = []
        visited_ids = set()
        
        for issue in issues:
            if issue.id in visited_ids:
                continue
            
            # Find related issues
            related_issues = self._find_related_issues(issue, issues)
            
            # Only create chains with multiple issues
            if len(related_issues) > 1:
                # Calculate chain properties
                chain = IssueChain(
                    issues=related_issues,
                    combined_severity=self._calculate_chain_severity(related_issues),
                    attack_scenario=self._generate_attack_scenario(related_issues),
                    exploit_likelihood=self._calculate_exploit_likelihood(related_issues),
                    prerequisites=self._determine_prerequisites(related_issues),
                    mitigation_priority=self._calculate_mitigation_priority(related_issues)
                )
                chains.append(chain)
            
            # Mark all issues in this chain as visited
            visited_ids.update(i.id for i in related_issues)
        
        return chains
    
    def _find_related_issues(self, source_issue: SecurityIssue,
                            all_issues: List[SecurityIssue]) -> List[SecurityIssue]:
        """
        Find issues that could form an attack chain with the source issue.
        
        Args:
            source_issue: The starting issue
            all_issues: List of all issues to check against
            
        Returns:
            List of related issues including the source issue
        """
        related = [source_issue]
        
        for issue in all_issues:
            if issue.id != source_issue.id and self._are_issues_related(source_issue, issue):
                related.append(issue)
        
        # Sort by severity (most severe first)
        return sorted(related, key=lambda i: i.severity.numerical_value)
    
    def _are_issues_related(self, issue1: SecurityIssue, issue2: SecurityIssue) -> bool:
        """
        Determine if two issues are related in an attack chain.
        
        Args:
            issue1: First issue
            issue2: Second issue
            
        Returns:
            True if issues are related, False otherwise
        """
        # Check if issues are in the same file or connected files
        same_file = issue1.position.file_path == issue2.position.file_path
        
        # Check for attack pattern relationship
        attack_pattern_related = (
            issue2.category in self.attack_patterns.get(issue1.category, []) or
            issue1.category in self.attack_patterns.get(issue2.category, [])
        )
        
        # Check for code proximity if in same file
        code_proximity = False
        if same_file:
            line_distance = abs(issue1.position.start_line - issue2.position.start_line)
            code_proximity = line_distance <= 15  # Related if within 15 lines
        
        # Check for data flow relationship based on descriptions
        data_flow_related = self._check_data_flow_relationship(issue1, issue2)
        
        # Check for common security context
        security_context_related = self._share_security_context(issue1, issue2)
        
        # Calculate relationship score based on multiple factors
        relationship_score = sum([
            2.0 if attack_pattern_related else 0.0,
            1.0 if same_file else 0.0,
            1.0 if code_proximity else 0.0,
            1.5 if data_flow_related else 0.0,
            1.0 if security_context_related else 0.0,
            1.0 if issue1.is_related_to(issue2) else 0.0  # Use built-in relation check
        ])
        
        # Consider related if score exceeds threshold
        return relationship_score >= 2.5
    
    def _check_data_flow_relationship(self, issue1: SecurityIssue, issue2: SecurityIssue) -> bool:
        """
        Check if issues are related through data flow patterns.
        
        Args:
            issue1: First issue
            issue2: Second issue
            
        Returns:
            True if data flow relationship exists, False otherwise
        """
        # Data flow patterns to check for
        data_patterns = {
            'user_input': ['input', 'request', 'param', 'query', 'form', 'data', 'get', 'post'],
            'file_operations': ['file', 'path', 'directory', 'read', 'write', 'open'],
            'database': ['sql', 'query', 'db', 'database', 'record', 'table'],
            'authentication': ['auth', 'login', 'password', 'credential', 'session', 'token'],
            'serialization': ['serialize', 'deserialize', 'marshal', 'unmarshal', 'pickle'],
            'encryption': ['encrypt', 'decrypt', 'hash', 'cipher', 'key', 'secret']
        }
        
        def get_data_categories(issue: SecurityIssue) -> Set[str]:
            """Extract data flow categories from issue description and impact."""
            categories = set()
            text = f"{issue.description} {issue.impact}".lower()
            
            for category, patterns in data_patterns.items():
                if any(pattern in text for pattern in patterns):
                    categories.add(category)
            return categories
        
        # Get categories for each issue
        issue1_categories = get_data_categories(issue1)
        issue2_categories = get_data_categories(issue2)
        
        # Consider related if they share at least one category
        return bool(issue1_categories & issue2_categories)
    
    def _share_security_context(self, issue1: SecurityIssue, issue2: SecurityIssue) -> bool:
        """
        Check if issues share a common security context.
        
        Args:
            issue1: First issue
            issue2: Second issue
            
        Returns:
            True if issues share security context, False otherwise
        """
        # Define security contexts as sets of related issue categories
        security_contexts = {
            'authentication': {
                SecurityIssueCategory.BROKEN_AUTHENTICATION,
                SecurityIssueCategory.HARDCODED_CREDENTIALS,
                SecurityIssueCategory.SENSITIVE_DATA_EXPOSURE
            },
            'injection': {
                SecurityIssueCategory.SQL_INJECTION,
                SecurityIssueCategory.OS_COMMAND_INJECTION,
                SecurityIssueCategory.CODE_INJECTION,
                SecurityIssueCategory.INJECTION
            },
            'access_control': {
                SecurityIssueCategory.BROKEN_ACCESS_CONTROL,
                SecurityIssueCategory.INSECURE_DIRECT_OBJECT_REFERENCE,
                SecurityIssueCategory.CSRF
            },
            'data_exposure': {
                SecurityIssueCategory.SENSITIVE_DATA_EXPOSURE,
                SecurityIssueCategory.INFORMATION_EXPOSURE_THROUGH_QUERY_STRING,
                SecurityIssueCategory.EXPOSED_SENSITIVE_INFORMATION,
                SecurityIssueCategory.EXPOSED_SECRET
            }
        }
        
        # Check if both issues belong to the same context
        for context_categories in security_contexts.values():
            if issue1.category in context_categories and issue2.category in context_categories:
                return True
        
        return False
    
    def _calculate_chain_severity(self, issues: List[SecurityIssue]) -> RiskSeverity:
        """
        Calculate combined severity for a chain of related issues.
        
        Args:
            issues: List of related issues
            
        Returns:
            Combined RiskSeverity level
        """
        if not issues:
            return RiskSeverity.INFO
        
        # Get the base severity from the most severe issue
        severities = [issue.severity.numerical_value for issue in issues]
        base_severity = min(severities)  # Lower numerical value = higher severity
        
        # Consider chain length as a severity multiplier
        chain_factor = 1 + (len(issues) - 1) * 0.2
        weighted_severity = max(1, base_severity - int(chain_factor - 1))
        
        # Map back to RiskSeverity enum
        severity_map = {
            1: RiskSeverity.CRITICAL,
            2: RiskSeverity.HIGH,
            3: RiskSeverity.MEDIUM,
            4: RiskSeverity.LOW,
            5: RiskSeverity.INFO
        }
        
        return severity_map.get(weighted_severity, RiskSeverity.MEDIUM)
    
    def _generate_attack_scenario(self, issues: List[SecurityIssue]) -> str:
        """
        Generate a detailed attack scenario narrative for related issues.
        
        Args:
            issues: List of related issues
            
        Returns:
            Detailed attack scenario description
        """
        if not issues:
            return "No attack scenario possible: no vulnerabilities detected"
        
        # Sort issues by severity (most severe first)
        sorted_issues = sorted(issues, key=lambda i: i.severity.numerical_value)
        
        # Build attack path description
        scenario_parts = []
        
        # Add header with severity assessment
        chain_severity = self._calculate_chain_severity(issues)
        scenario_parts.append(f"Attack Chain Severity: {chain_severity.value}")
        
        # Add prerequisites
        prerequisites = self._determine_prerequisites(issues)
        scenario_parts.append(f"Attack Prerequisites: {', '.join(prerequisites)}")
        
        # Add likelihood assessment
        likelihood = self._calculate_exploit_likelihood(issues)
        likelihood_desc = "Very High" if likelihood > 0.8 else \
                        "High" if likelihood > 0.6 else \
                        "Medium" if likelihood > 0.4 else \
                        "Low" if likelihood > 0.2 else "Very Low"
        scenario_parts.append(f"Exploitation Likelihood: {likelihood_desc} ({likelihood:.2f})")
        
        # Build step-by-step attack path
        scenario_parts.append("\nAttack Path Analysis:")
        
        for i, issue in enumerate(sorted_issues, 1):
            # Format the code location
            location = issue.position.location_display
            
            # Create a detailed step description
            step = (
                f"Step {i}: {issue.category.value} ({issue.severity.value})\n"
                f"   Location: {location}\n"
                f"   Attack Vector: {issue.description.split('.')[0]}\n"
                f"   Potential Impact: {issue.impact.split('.')[0]}"
            )
            scenario_parts.append(step)
            
            # Add connection to next step if applicable
            if i < len(sorted_issues):
                next_issue = sorted_issues[i]
                if self._are_issues_related(issue, next_issue):
                    scenario_parts.append(
                        f"   ↓ Chain Effect: This vulnerability enables or amplifies the next attack step"
                    )
                else:
                    scenario_parts.append(
                        f"   ↓ Parallel Vector: This vulnerability can be exploited independently"
                    )
        
        return "\n".join(scenario_parts)
    
    def _determine_prerequisites(self, issues: List[SecurityIssue]) -> List[str]:
        """
        Determine prerequisites needed to exploit the vulnerabilities.
        
        Args:
            issues: List of related issues
            
        Returns:
            List of prerequisite conditions for exploitation
        """
        if not issues:
            return ["None"]
        
        prerequisites = set()
        
        # Common patterns to check for
        auth_patterns = ['authentication', 'login', 'credentials', 'session']
        access_patterns = ['local access', 'physical access', 'network access', 'admin access']
        user_patterns = ['user interaction', 'user input', 'user-supplied']
        config_patterns = ['configuration', 'settings', 'environment']
        
        # Issue-type specific prerequisites
        type_prereqs = {
            SecurityIssueCategory.SQL_INJECTION: ['Database access', 'Input injection point'],
            SecurityIssueCategory.CROSS_SITE_SCRIPTING: ['Active user session', 'Input reflection point'],
            SecurityIssueCategory.CSRF: ['Active user session', 'Predictable request structure'],
            SecurityIssueCategory.PATH_TRAVERSAL: ['File system access', 'Directory traversal point'],
            SecurityIssueCategory.OS_COMMAND_INJECTION: ['Command execution context', 'Unsanitized input'],
            SecurityIssueCategory.INSECURE_DESERIALIZATION: ['Serialized data input', 'Class definitions access']
        }
        
        for issue in issues:
            # Add type-specific prerequisites
            if issue.category in type_prereqs:
                prerequisites.update(type_prereqs[issue.category])
            
            # Extract prerequisites from description text
            desc_lower = issue.description.lower()
            impact_lower = issue.impact.lower()
            
            # Check auth requirements
            if any(pattern in desc_lower for pattern in auth_patterns):
                prerequisites.add('Valid authentication credentials')
            
            # Check access requirements
            if any(pattern in desc_lower for pattern in access_patterns):
                if 'local' in desc_lower:
                    prerequisites.add('Local system access')
                if 'physical' in desc_lower:
                    prerequisites.add('Physical device access')
                if 'network' in desc_lower:
                    prerequisites.add('Network connectivity')
                if 'admin' in desc_lower:
                    prerequisites.add('Administrative privileges')
            
            # Check user interaction requirements
            if any(pattern in desc_lower for pattern in user_patterns):
                prerequisites.add('User interaction')
            
            # Check configuration requirements
            if any(pattern in desc_lower for pattern in config_patterns):
                if 'debug' in desc_lower:
                    prerequisites.add('Debug mode enabled')
                if 'environment' in desc_lower:
                    prerequisites.add('Specific environment configuration')
            
            # Check CVSS implications
            if issue.cvss_score >= 7.0:
                prerequisites.add('No special access required (High severity issue)')
            
            # Add technical prerequisites based on impact details
            if 'bypass' in impact_lower:
                prerequisites.add('Knowledge of security mechanisms')
            if 'memory' in impact_lower:
                prerequisites.add('Memory manipulation capability')
            if 'race condition' in desc_lower:
                prerequisites.add('Ability to execute concurrent requests')
        
        # Return sorted prerequisites
        return sorted(list(prerequisites))
    
    def _calculate_exploit_likelihood(self, issues: List[SecurityIssue]) -> float:
        """
        Calculate likelihood of successful exploitation of the issue chain.
        
        Args:
            issues: List of related issues
            
        Returns:
            Float likelihood value between 0.0 and 1.0
        """
        if not issues:
            return 0.0
        
        # Base weights for severity levels
        severity_weights = {
            RiskSeverity.CRITICAL: 1.0,
            RiskSeverity.HIGH: 0.8,
            RiskSeverity.MEDIUM: 0.6,
            RiskSeverity.LOW: 0.4,
            RiskSeverity.INFO: 0.2
        }
        
        # Calculate base likelihood from severities
        base_likelihood = sum(severity_weights[issue.severity] for issue in issues) / len(issues)
        
        # Adjust for prerequisites complexity
        prereqs = self._determine_prerequisites(issues)
        prereq_complexity = len(prereqs) * 0.1  # More prerequisites = harder to exploit
        
        # Adjust for chain complexity
        chain_complexity = 1.0
        if len(issues) > 1:
            # Longer chains are harder to exploit
            chain_complexity = 1.0 - (len(issues) - 1) * 0.1
            
            # Check for related issues which might make exploitation easier
            related_pairs = sum(
                1 for i, issue1 in enumerate(issues[:-1])
                for issue2 in issues[i+1:]
                if self._are_issues_related(issue1, issue2)
            )
            if related_pairs:
                chain_complexity += related_pairs * 0.05  # Related issues increase likelihood
        
        # Additional exploitation factors
        factors = {
            'has_public_exploit': 1.2,  # Increase if public exploits exist
            'requires_authentication': 0.7,  # Decrease if auth required
            'requires_user_interaction': 0.8,  # Decrease if user interaction needed
            'network_accessible': 1.1  # Increase if remotely exploitable
        }
        
        # Apply relevant factors
        factor_multiplier = 1.0
        for issue in issues:
            # Check for public exploit references
            if any('CVE' in ref for ref in issue.references):
                factor_multiplier *= factors['has_public_exploit']
            
            # Check description for other factors
            desc_lower = issue.description.lower()
            if 'authentication' in desc_lower:
                factor_multiplier *= factors['requires_authentication']
            if 'user interaction' in desc_lower:
                factor_multiplier *= factors['requires_user_interaction']
            if 'remote' in desc_lower or 'network' in desc_lower:
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
    
    def _calculate_mitigation_priority(self, issues: List[SecurityIssue]) -> int:
        """
        Calculate priority level for mitigating the issue chain.
        
        Args:
            issues: List of related issues
            
        Returns:
            Integer priority level (1=highest priority, 5=lowest)
        """
        if not issues:
            return 5  # Lowest priority if no issues
        
        # Base priority on most severe issue
        priority = min(issue.severity.numerical_value for issue in issues)
        
        # Consider exploitation likelihood as a factor
        likelihood = self._calculate_exploit_likelihood(issues)
        if likelihood > 0.7:  # High likelihood
            priority = max(1, priority - 1)  # Increase priority (lower number)
        
        return priority
    
    async def inspect_repository(self, repo_url: str, branch: str = "main", 
                               scan_depth: int = 3) -> SecurityAnalysisReport:
        """
        Analyze an entire repository for security issues.
        
        Args:
            repo_url: URL of the repository to analyze
            branch: Branch to analyze
            scan_depth: Directory depth to scan
            
        Returns:
            SecurityAnalysisReport containing all identified issues
        """
        # Clone/update repository
        repo_path = await self._fetch_repository(repo_url, branch)
        
        # Get relevant files for analysis
        files_to_analyze = self._get_repository_files(repo_path, scan_depth)
        
        # Analyze each file
        all_issues = []
        file_reports = []
        
        for file_path in files_to_analyze:
            self.logger.info(f"Analyzing file: {file_path}")
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Create relative path for reporting
                rel_path = os.path.relpath(file_path, repo_path)
                report = await self.inspect_code(content, rel_path)
                file_reports.append(report)
                all_issues.extend(report.issues)
            except Exception as e:
                self.logger.error(f"Error analyzing {file_path}: {str(e)}")
        
        # Chain vulnerabilities across files
        issue_chains = self._build_issue_chains(all_issues)
        
        # Create consolidated report
        report = SecurityAnalysisReport(
            repository_url=repo_url,
            branch_name=branch,
            issues=all_issues,
            issue_chains=issue_chains
        )
        
        # Calculate statistics
        report.calculate_stats()
        report.calculate_risk_rating()
        
        return report
    
    async def _fetch_repository(self, repo_url: str, branch: str) -> str:
        """
        Clone or update a git repository for analysis.
        
        Args:
            repo_url: URL of the repository
            branch: Branch to check out
            
        Returns:
            Local path to the cloned repository
        """
        # Validate URL format
        if not re.match(r'^https?://', repo_url):
            raise ValueError(f"Invalid repository URL format: {repo_url}")
        
        # Extract repository name from URL
        repo_name = re.sub(r'[^a-zA-Z0-9_\-]', '_', repo_url.split('/')[-1].replace('.git', ''))
        
        # Determine system-appropriate temp directory
        temp_dir = os.path.join(
            os.environ.get('TEMP') or os.environ.get('TMP') or '/tmp',
            'security_analysis'
        )
        os.makedirs(temp_dir, exist_ok=True)
        
        repo_path = os.path.normpath(os.path.join(temp_dir, repo_name))
        
        # Validate path is within temp directory
        if not os.path.normpath(repo_path).startswith(os.path.normpath(temp_dir)):
            raise ValueError(f"Invalid repository path: {repo_path}")
        
        # Clone or update repository
        if os.path.exists(repo_path):
            # Update existing repository
            self.logger.info(f"Updating repository: {repo_url}")
            repo = git.Repo(repo_path)
            origin = repo.remotes.origin
            origin.fetch()
            repo.git.checkout(branch)
        else:
            # Clone new repository
            self.logger.info(f"Cloning repository: {repo_url}")
            repo = git.Repo.clone_from(repo_url, repo_path, branch=branch)
        
        return repo_path
    
    def _get_repository_files(self, repo_path: str, scan_depth: int) -> List[str]:
        """
        Get relevant files from repository for security analysis.
        
        Args:
            repo_path: Path to local repository
            scan_depth: Directory depth to scan
            
        Returns:
            List of file paths to analyze
        """
        relevant_files = []
        
        # Define file extensions to analyze
        security_relevant_extensions = {
            '.py', '.js', '.ts', '.java', '.go', '.rb', '.php',
            '.c', '.cpp', '.cs', '.scala', '.kt', '.swift'
        }
        
        # Skip these directories
        skip_dirs = {'.git', 'node_modules', 'venv', '.venv', '__pycache__', 'dist', 'build'}
        
        for root, dirs, files in os.walk(repo_path):
            # Skip unwanted directories
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            
            # Calculate current depth
            current_depth = root.count(os.sep) - repo_path.count(os.sep)
            if current_depth <= scan_depth:
                for file in files:
                    # Check if file has relevant extension
                    _, ext = os.path.splitext(file)
                    if ext.lower() in security_relevant_extensions:
                        relevant_files.append(os.path.join(root, file))
        
        self.logger.info(f"Found {len(relevant_files)} files to analyze")
        return relevant_files