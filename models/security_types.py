# security/models.py

import uuid
from datetime import datetime
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Union
from dataclasses import dataclass, field

from pydantic import BaseModel, Field, validator

class SecurityIssueCategory(str, Enum):
    """Categories of security issues based on industry standards."""
    REGULAR_EXPRESSION_DENIAL_OF_SERVICE = "REGULAR_EXPRESSION_DENIAL_OF_SERVICE"
    EXPOSED_SENSITIVE_INFORMATION = "EXPOSED_SENSITIVE_INFORMATION"
    BROKEN_ACCESS_CONTROL = "BROKEN_ACCESS_CONTROL"
    INFORMATION_EXPOSURE_THROUGH_ERROR_MESSAGES = "INFORMATION_EXPOSURE_THROUGH_ERROR_MESSAGES"
    WEAK_CRYPTOGRAPHY = "WEAK_CRYPTOGRAPHY"
    UNVALIDATED_REDIRECTS_AND_FORWARDED_REQUESTS = "UNVALIDATED_REDIRECTS_AND_FORWARDED_REQUESTS"
    BUFFER_OVERFLOW = "BUFFER_OVERFLOW"
    UNSAFE_PROPERTY_ACCESS = "UNSAFE_PROPERTY_ACCESS"
    BROKEN_AUTHENTICATION = "BROKEN_AUTHENTICATION"
    FAILURE_TO_RESTRICT_URL_ACCESS = "FAILURE_TO_RESTRICT_URL_ACCESS"
    EXPOSED_SECRET = "EXPOSED_SECRET"
    SENSITIVE_DATA_EXPOSURE = "SENSITIVE_DATA_EXPOSURE"
    USING_COMPONENTS_WITH_KNOWN_VULNERABILITIES = "USING_COMPONENTS_WITH_KNOWN_VULNERABILITIES"
    HTTP_METHOD_INJECTION = "HTTP_METHOD_INJECTION"
    INSECURE_IMPORTS = "INSECURE_IMPORTS"
    ASSERTION_FAILURE_VULNERABILITY = "ASSERTION_FAILURE_VULNERABILITY"
    EXPOSED_ADMIN_FUNCTIONALITIES = "EXPOSED_ADMIN_FUNCTIONALITIES"
    SECURE_COOKIE = "SECURE_COOKIE"
    DEPENDENCY_VULNERABILITY = "DEPENDENCY_VULNERABILITY"
    CODE_INJECTION = "CODE_INJECTION"
    INSECURE_DATA_STORAGE = "INSECURE_DATA_STORAGE"
    HARDCODED_CREDENTIALS = "HARDCODED_CREDENTIALS"
    USE_OF_WEAK_HASHING_ALGORITHM = "USE_OF_WEAK_HASHING_ALGORITHM"
    RACE_CONDITION = "RACE_CONDITION"
    FORMAT_STRING = "FORMAT_STRING"
    OS_COMMAND_INJECTION = "OS_COMMAND_INJECTION"
    EXCESSIVE_DATA_EXPOSURE = "EXCESSIVE_DATA_EXPOSURE"
    MISSING_AUTHENTICATION = "MISSING_AUTHENTICATION"
    PYTHONIC_TYPE_CHECK_VIOLATION = "PYTHONIC_TYPE_CHECK_VIOLATION"
    INFORMATION_EXPOSURE_THROUGH_QUERY_STRING = "INFORMATION_EXPOSURE_THROUGH_QUERY_STRING"
    INSECURE_DIRECT_OBJECT_REFERENCE = "INSECURE_DIRECT_OBJECT_REFERENCE_(IDOR)"
    ENVIRONMENT_VARIABLE_INJECTION = "ENVIRONMENT_VARIABLE_INJECTION"
    REMOTE_CODE_EXECUTION = "REMOTE_CODE_EXECUTION_(RCE)"
    UNHANDLED_EXCEPTION = "UNHANDLED_EXCEPTION"
    FILE_INCLUSION = "FILE_INCLUSION"
    INSECURE_FILE_READ = "INSECURE_FILE_READ"
    EXPOSED_GITHUB_URL = "EXPOSED_GITHUB_URL"
    IMPROPER_ERROR_HANDLING = "IMPROPER_ERROR_HANDLING"
    POTENTIAL_INSECURE_USE_OF_OPERATOR = "POTENTIAL_INSECURE_USE_OF_OPERATOR"
    TESTING_FLAGS_UNHANDLED = "TESTING_FLAGS_UNHANDLED"
    INSUFFICIENT_INPUT_VALIDATION = "INSUFFICIENT_INPUT_VALIDATION"
    DENIAL_OF_SERVICE = "DENIAL_OF_SERVICE"
    EXPOSED_FLASK_DEBUG = "EXPOSED_FLASK_DEBUG"
    SERVER_SIDE_REQUEST_FORGERY = "SERVER_SIDE_REQUEST_FORGERY_(SSRF)"
    INSECURE_RANDOM_SEEDING = "INSECURE_RANDOM_SEEDING"
    INSECURE_HTTP_HEADERS = "INSECURE_HTTP_HEADERS"
    INJECTION_FLAW = "INJECTION_FLAW"
    INSECURE_CONFIGURATION_SETTING = "INSECURE_CONFIGURATION_SETTING"
    CROSS_SITE_SCRIPTING = "CROSS_SITE_SCRIPTING"
    CSRF = "CROSS_SITE_REQUEST_FORGERY_(CSRF)"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    INSECURE_DESERIALIZATION = "INSECURE_DESERIALIZATION"
    XML_EXTERNAL_ENTITY = "XML_EXTERNAL_ENTITY"
    SECURITY_MISCONFIGURATION = "SECURITY_MISCONFIGURATION"
    SECURE_RANDOMNESS = "SECURE_RANDOMNESS"
    INSUFFICIENT_LOGGING = "INSUFFICIENT_LOGGING"
    INTEGER_OVERFLOW = "INTEGER_OVERFLOW"
    TYPE_COERCION_VULNERABILITY = "TYPE_COERCION_VULNERABILITY"
    INSECURE_ENVIRONMENT_VARIABLE_USAGE = "INSECURE_ENVIRONMENT_VARIABLE_USAGE"
    EXPOSED_SECURITY_HEADERS = "EXPOSED_SECURITY_HEADERS"
    INJECTION = "INJECTION"
    SQL_INJECTION = "SQL_INJECTION"
    GENERIC_SECURITY_ISSUE = "GENERIC_SECURITY_ISSUE"

    @classmethod
    def get_related_categories(cls, category: 'SecurityIssueCategory') -> List['SecurityIssueCategory']:
        """
        Get categories related to the specified security issue category.
        
        Args:
            category: The category to find related categories for
            
        Returns:
            List of related security issue categories
        """
        # Define relationships between categories
        relationships = {
            cls.SQL_INJECTION: [cls.INJECTION, cls.SENSITIVE_DATA_EXPOSURE, cls.BROKEN_ACCESS_CONTROL],
            cls.OS_COMMAND_INJECTION: [cls.INJECTION, cls.REMOTE_CODE_EXECUTION],
            cls.CODE_INJECTION: [cls.INJECTION, cls.REMOTE_CODE_EXECUTION],
            cls.CROSS_SITE_SCRIPTING: [cls.INJECTION, cls.CSRF, cls.SENSITIVE_DATA_EXPOSURE],
            cls.BROKEN_AUTHENTICATION: [cls.SENSITIVE_DATA_EXPOSURE, cls.BROKEN_ACCESS_CONTROL],
            cls.PATH_TRAVERSAL: [cls.FILE_INCLUSION, cls.SENSITIVE_DATA_EXPOSURE],
            cls.INSECURE_DESERIALIZATION: [cls.REMOTE_CODE_EXECUTION, cls.CODE_INJECTION],
            # Additional relationships can be defined here
        }
        
        return relationships.get(category, [])

class RiskSeverity(str, Enum):
    """Risk severity levels for security issues."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    
    @property
    def numerical_value(self) -> int:
        """
        Get numerical value of severity level for sorting and calculations.
        
        Returns:
            Integer representing the severity (lower is more severe)
        """
        values = {
            self.CRITICAL: 1,
            self.HIGH: 2,
            self.MEDIUM: 3,
            self.LOW: 4,
            self.INFO: 5
        }
        return values.get(self, 5)
    
    @property
    def weight(self) -> float:
        """
        Get weight factor for risk calculations.
        
        Returns:
            Float weight value
        """
        weights = {
            self.CRITICAL: 10.0,
            self.HIGH: 8.0,
            self.MEDIUM: 5.0,
            self.LOW: 2.0,
            self.INFO: 1.0
        }
        return weights.get(self, 0.0)
    
    @classmethod
    def from_cvss(cls, cvss_score: float) -> 'RiskSeverity':
        """
        Convert CVSS score to RiskSeverity.
        
        Args:
            cvss_score: CVSS score (0.0-10.0)
            
        Returns:
            Corresponding RiskSeverity enum value
        """
        if cvss_score >= 9.0:
            return cls.CRITICAL
        elif cvss_score >= 7.0:
            return cls.HIGH
        elif cvss_score >= 4.0:
            return cls.MEDIUM
        elif cvss_score >= 1.0:
            return cls.LOW
        else:
            return cls.INFO

class CodePosition(BaseModel):
    """Represents a specific position in code."""
    file_path: str
    start_line: int
    end_line: int
    start_column: Optional[int] = None
    end_column: Optional[int] = None
    code_context: Optional[str] = None
    
    def is_connected_to(self, other: 'CodePosition', proximity_threshold: int = 10) -> bool:
        """
        Check if this code position is connected to another.
        
        Args:
            other: Another code position to compare with
            proximity_threshold: Maximum line distance to consider positions connected
            
        Returns:
            True if positions are connected, False otherwise
        """
        # Different files are not connected
        if self.file_path != other.file_path:
            return False
            
        # Check if positions are within reasonable proximity
        return abs(self.start_line - other.start_line) <= proximity_threshold
    
    @property
    def location_display(self) -> str:
        """
        Get formatted display string for this location.
        
        Returns:
            String representing the location for display
        """
        if self.start_line == self.end_line:
            return f"{self.file_path}:{self.start_line}"
        return f"{self.file_path}:{self.start_line}-{self.end_line}"

class SecurityIssue(BaseModel):
    """Model representing a security issue found in code."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    category: SecurityIssueCategory
    severity: RiskSeverity
    position: CodePosition
    description: str
    impact: str
    remediation: str
    cwe_id: str
    owasp_category: str
    cvss_score: float
    references: List[str] = Field(default_factory=list)
    proof_of_concept: Optional[str] = None
    secure_alternative: str
    discovered_timestamp: datetime = Field(default_factory=datetime.now)
    
    @validator('cvss_score')
    def validate_cvss_score(cls, v):
        """Validate CVSS score is within range 0-10."""
        if not 0 <= v <= 10:
            raise ValueError('CVSS score must be between 0 and 10')
        return v
    
    def is_related_to(self, other: 'SecurityIssue') -> bool:
        """
        Check if this security issue is related to another.
        
        Args:
            other: Another security issue to compare with
            
        Returns:
            True if issues are related, False otherwise
        """
        # Check if categories are related
        category_related = (
            other.category in SecurityIssueCategory.get_related_categories(self.category) or
            self.category in SecurityIssueCategory.get_related_categories(other.category)
        )
        
        # Check if positions are connected
        position_connected = self.position.is_connected_to(other.position)
        
        # Check if they have common references
        common_references = bool(set(self.references) & set(other.references))
        
        # Consider related if any two conditions are true
        return sum([category_related, position_connected, common_references]) >= 2

class IssueChain(BaseModel):
    """Model representing a chain of related security issues."""
    issues: List[SecurityIssue]
    combined_severity: RiskSeverity
    attack_scenario: str
    exploit_likelihood: float
    prerequisites: List[str]
    mitigation_priority: int
    
    @property
    def has_critical_issues(self) -> bool:
        """
        Check if this chain contains any critical issues.
        
        Returns:
            True if chain contains CRITICAL issues, False otherwise
        """
        return any(issue.severity == RiskSeverity.CRITICAL for issue in self.issues)
    
    @property
    def most_severe_issue(self) -> Optional[SecurityIssue]:
        """
        Get the most severe issue in the chain.
        
        Returns:
            Most severe SecurityIssue or None if chain is empty
        """
        if not self.issues:
            return None
        return min(self.issues, key=lambda issue: issue.severity.numerical_value)
    
    def calculate_combined_severity(self) -> RiskSeverity:
        """
        Calculate the combined severity of issues in this chain.
        
        Returns:
            RiskSeverity representing the combined severity
        """
        if not self.issues:
            return RiskSeverity.INFO
            
        # Get the base severity from the most severe issue
        base_severity = min(issue.severity.numerical_value for issue in self.issues)
        
        # Factor in the number of issues in the chain
        chain_factor = 1 + (len(self.issues) - 1) * 0.2
        adjusted_severity = max(1, base_severity - int(chain_factor))
        
        # Map back to RiskSeverity enum
        severity_map = {
            1: RiskSeverity.CRITICAL,
            2: RiskSeverity.HIGH,
            3: RiskSeverity.MEDIUM,
            4: RiskSeverity.LOW,
            5: RiskSeverity.INFO
        }
        
        return severity_map.get(adjusted_severity, RiskSeverity.MEDIUM)

class SecurityAnalysisReport(BaseModel):
    """Model for a complete security analysis report."""
    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    generated_at: datetime = Field(default_factory=datetime.now)
    target_file: Optional[str] = None
    repository_url: Optional[str] = None
    branch_name: Optional[str] = None
    issues: List[SecurityIssue] = Field(default_factory=list)
    issue_chains: List[IssueChain] = Field(default_factory=list)
    summary_stats: Optional[Dict[str, int]] = None
    risk_rating: Optional[float] = None
    
    def calculate_stats(self) -> None:
        """Calculate and update summary statistics for the report."""
        self.summary_stats = {
            "total_issues": len(self.issues),
            "critical_count": len([i for i in self.issues if i.severity == RiskSeverity.CRITICAL]),
            "high_count": len([i for i in self.issues if i.severity == RiskSeverity.HIGH]),
            "medium_count": len([i for i in self.issues if i.severity == RiskSeverity.MEDIUM]),
            "low_count": len([i for i in self.issues if i.severity == RiskSeverity.LOW]),
            "info_count": len([i for i in self.issues if i.severity == RiskSeverity.INFO]),
            "chain_count": len(self.issue_chains)
        }
    
    def calculate_risk_rating(self) -> None:
        """Calculate and update the overall risk rating for the report."""
        if not self.issues:
            self.risk_rating = 0.0
            return
            
        # Calculate base score from individual issue severities
        base_score = sum(issue.severity.weight for issue in self.issues)
        
        # Apply multiplier based on issue chains
        chain_multiplier = 1 + (len(self.issue_chains) * 0.15)
        
        # Calculate final risk score
        self.risk_rating = round(base_score * chain_multiplier, 2)
    
    def get_prioritized_issues(self) -> List[SecurityIssue]:
        """
        Get issues sorted by priority for remediation.
        
        Returns:
            List of issues in priority order
        """
        return sorted(
            self.issues,
            key=lambda issue: (
                issue.severity.numerical_value,
                -issue.cvss_score,
                issue.category.value
            )
        )
    
    def to_dict(self) -> Dict:
        """
        Convert report to dictionary for serialization.
        
        Returns:
            Dictionary representation of report
        """
        return {
            "report_id": self.report_id,
            "generated_at": self.generated_at.isoformat(),
            "target_file": self.target_file,
            "repository_url": self.repository_url,
            "branch_name": self.branch_name,
            "issues_count": len(self.issues),
            "issue_chains_count": len(self.issue_chains),
            "summary": self.summary_stats,
            "risk_rating": self.risk_rating
        }