# security/ai_service.py

import os
import json
import re
import asyncio
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, List, Tuple
from enum import Enum
import logging

# Import AI provider SDKs
import anthropic
import openai
import google.generativeai as genai
from dotenv import load_dotenv

# Initialize environment variables
load_dotenv()

class ModelProvider(Enum):
    """Enum representing the available AI model providers."""
    GEMINI = "gemini"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"

@dataclass
class SecurityAnalysisConfig:
    """Configuration for security analysis settings."""
    temperature: float = 0.1
    max_tokens_response: int = 8192
    include_detailed_examples: bool = True
    enable_markdown_parsing: bool = True
    model_priority: List[ModelProvider] = field(default_factory=lambda: [
        ModelProvider.GEMINI, ModelProvider.OPENAI, ModelProvider.ANTHROPIC
    ])

class SecurityAnalysisService:
    """
    Service for analyzing code security using multiple AI providers,
    with configurable fallback strategies.
    """
    
    def __init__(self, config: Optional[SecurityAnalysisConfig] = None):
        """
        Initialize the Security Analysis Service with configuration.
        
        Args:
            config: Optional configuration for security analysis
        """
        self.logger = logging.getLogger(__name__)
        self.config = config or SecurityAnalysisConfig()
        
        # Initialize AI providers
        self._initialize_providers()
        
        # Define security vulnerability types for validation
        self.vulnerability_types = self._load_vulnerability_types()
    
    def _initialize_providers(self) -> None:
        """Initialize connections to AI providers."""
        # Initialize Gemini
        try:
            gemini_api_key = os.getenv("GEMINI_API_KEY")
            if gemini_api_key:
                genai.configure(api_key=gemini_api_key)
                self.gemini_model = genai.GenerativeModel('gemini-1.5-pro')
                self.logger.info("Gemini API initialized successfully")
            else:
                self.gemini_model = None
                self.logger.warning("Gemini API key not found")
        except Exception as e:
            self.gemini_model = None
            self.logger.error(f"Failed to initialize Gemini: {e}")
        
        # Initialize OpenAI
        try:
            openai_api_key = os.getenv("OPENAI_API_KEY")
            if openai_api_key:
                self.openai_client = openai.Client(api_key=openai_api_key)
                self.openai_model = "gpt-4o"
                self.logger.info("OpenAI API initialized successfully")
            else:
                self.openai_client = None
                self.logger.warning("OpenAI API key not found")
        except Exception as e:
            self.openai_client = None
            self.logger.error(f"Failed to initialize OpenAI: {e}")
        
        # Initialize Anthropic
        try:
            anthropic_api_key = os.getenv("ANTHROPIC_API_KEY")
            if anthropic_api_key:
                self.anthropic_client = anthropic.Anthropic(api_key=anthropic_api_key)
                self.anthropic_model = "claude-3-opus-20240229"
                self.logger.info("Anthropic API initialized successfully")
            else:
                self.anthropic_client = None
                self.logger.warning("Anthropic API key not found")
        except Exception as e:
            self.anthropic_client = None
            self.logger.error(f"Failed to initialize Anthropic: {e}")
    
    def _load_vulnerability_types(self) -> List[str]:
        """Load and return the list of supported vulnerability types."""
        return [
            "INJECTION", "SQL_INJECTION", "OS_COMMAND_INJECTION", "CODE_INJECTION",
            "HTTP_METHOD_INJECTION", "CROSS_SITE_SCRIPTING", "CROSS_SITE_REQUEST_FORGERY_(CSRF)",
            "PATH_TRAVERSAL", "INSECURE_DESERIALIZATION", "BROKEN_AUTHENTICATION",
            "SENSITIVE_DATA_EXPOSURE", "XML_EXTERNAL_ENTITY", "BROKEN_ACCESS_CONTROL",
            "SECURITY_MISCONFIGURATION", "SECURE_RANDOMNESS", "INSUFFICIENT_LOGGING",
            "WEAK_CRYPTOGRAPHY", "USING_COMPONENTS_WITH_KNOWN_VULNERABILITIES",
            "BUFFER_OVERFLOW", "FORMAT_STRING", "INTEGER_OVERFLOW", "RACE_CONDITION",
            "HARDCODED_CREDENTIALS", "EXPOSED_SENSITIVE_INFORMATION", "EXPOSED_SECRET",
            "FILE_INCLUSION", "INSECURE_FILE_READ", "EXPOSED_GITHUB_URL",
            "IMPROPER_ERROR_HANDLING", "DEPENDENCY_VULNERABILITY", "INSECURE_IMPORTS",
            "UNSAFE_PROPERTY_ACCESS", "POTENTIAL_INSECURE_USE_OF_OPERATOR",
            "TESTING_FLAGS_UNHANDLED", "INSUFFICIENT_INPUT_VALIDATION", "DENIAL_OF_SERVICE",
            "REGULAR_EXPRESSION_DENIAL_OF_SERVICE", "EXPOSED_FLASK_DEBUG",
            "SERVER_SIDE_REQUEST_FORGERY_(SSRF)", "ENVIRONMENT_VARIABLE_INJECTION",
            "INSECURE_RANDOM_SEEDING", "USE_OF_WEAK_HASHING_ALGORITHM", "UNHANDLED_EXCEPTION",
            "REMOTE_CODE_EXECUTION_(RCE)", "INSECURE_DIRECT_OBJECT_REFERENCE_(IDOR)",
            "MISSING_AUTHENTICATION", "EXCESSIVE_DATA_EXPOSURE",
            "INFORMATION_EXPOSURE_THROUGH_QUERY_STRING", "FAILURE_TO_RESTRICT_URL_ACCESS",
            "TYPE_COERCION_VULNERABILITY", "ASSERTION_FAILURE_VULNERABILITY",
            "PYTHONIC_TYPE_CHECK_VIOLATION", "UNVALIDATED_REDIRECTS_AND_FORWARDED_REQUESTS",
            "INSECURE_DATA_STORAGE", "EXPOSED_SECURITY_HEADERS", "EXPOSED_ADMIN_FUNCTIONALITIES",
            "INSECURE_ENVIRONMENT_VARIABLE_USAGE", "INSECURE_HTTP_HEADERS", "INJECTION_FLAW",
            "SECURE_COOKIE", "INSECURE_CONFIGURATION_SETTING",
            "INFORMATION_EXPOSURE_THROUGH_ERROR_MESSAGES", "GENERIC_SECURITY_ISSUE"
        ]
    
    async def analyze_code_security(self, code_prompt: str, provider: Optional[ModelProvider] = None) -> Dict[str, Any]:
        """
        Analyze code for security vulnerabilities using configured AI providers.
        
        Args:
            code_prompt: The code and context prompt to analyze
            provider: Optional specific provider to use
        
        Returns:
            Dict containing analysis results with vulnerabilities
        """
        # If a specific provider is requested, try only that one
        if provider:
            return await self._analyze_with_provider(provider, code_prompt)
        
        # Otherwise follow the priority order with fallbacks
        results = {"vulnerabilities": []}
        errors = []
        
        for model_provider in self.config.model_priority:
            try:
                results = await self._analyze_with_provider(model_provider, code_prompt)
                if self._is_valid_analysis(results):
                    self.logger.info(f"Successfully analyzed with {model_provider.value}")
                    return results
            except Exception as e:
                error_msg = f"Analysis with {model_provider.value} failed: {str(e)}"
                self.logger.warning(error_msg)
                errors.append(error_msg)
                continue
        
        # If we get here, all providers failed
        self.logger.error(f"All providers failed: {', '.join(errors)}")
        return {"vulnerabilities": [], "errors": errors}
    
    async def _analyze_with_provider(self, provider: ModelProvider, prompt: str) -> Dict[str, Any]:
        """
        Analyze code using a specific AI provider.
        
        Args:
            provider: The AI provider to use
            prompt: The code and context prompt to analyze
        
        Returns:
            Dict containing analysis results
        """
        security_prompt = self._build_security_prompt()
        full_prompt = f"{security_prompt}\n\nCode to analyze:\n{prompt}"
        
        if provider == ModelProvider.GEMINI:
            return await self._analyze_with_gemini(full_prompt)
        elif provider == ModelProvider.OPENAI:
            return await self._analyze_with_openai(full_prompt)
        elif provider == ModelProvider.ANTHROPIC:
            return await self._analyze_with_anthropic(full_prompt)
        else:
            raise ValueError(f"Unsupported provider: {provider}")
    
    async def _analyze_with_gemini(self, full_prompt: str) -> Dict[str, Any]:
        """
        Analyze code using Google Gemini.
        
        Args:
            full_prompt: Complete prompt with instructions and code
        
        Returns:
            Dict containing analysis results
        """
        if not self.gemini_model:
            raise ValueError("Gemini API not configured")
        
        try:
            response = self.gemini_model.generate_content(
                full_prompt,
                generation_config=genai.types.GenerationConfig(
                    candidate_count=1,
                    max_output_tokens=self.config.max_tokens_response,
                    temperature=self.config.temperature
                )
            )
            
            # Process and validate response
            return self._extract_json_from_gemini(response)
        except Exception as e:
            self.logger.error(f"Gemini analysis error: {str(e)}")
            raise
    
    async def _analyze_with_openai(self, full_prompt: str) -> Dict[str, Any]:
        """
        Analyze code using OpenAI models.
        
        Args:
            full_prompt: Complete prompt with instructions and code
        
        Returns:
            Dict containing analysis results
        """
        if not self.openai_client:
            raise ValueError("OpenAI API not configured")
        
        messages = [
            {"role": "system", "content": self._build_security_prompt()},
            {"role": "user", "content": full_prompt}
        ]
        
        response = self.openai_client.chat.completions.create(
            model=self.openai_model,
            messages=messages,
            temperature=self.config.temperature,
            max_tokens=self.config.max_tokens_response
        )
        
        # Extract and validate content
        try:
            content = response.choices[0].message.content
            return self._extract_json_from_text(content)
        except Exception as e:
            self.logger.error(f"OpenAI response processing error: {str(e)}")
            raise
    
    async def _analyze_with_anthropic(self, full_prompt: str) -> Dict[str, Any]:
        """
        Analyze code using Anthropic Claude.
        
        Args:
            full_prompt: Complete prompt with instructions and code
        
        Returns:
            Dict containing analysis results
        """
        if not self.anthropic_client:
            raise ValueError("Anthropic API not configured")
        
        try:
            response = await self.anthropic_client.messages.create(
                model=self.anthropic_model,
                max_tokens=self.config.max_tokens_response,
                temperature=self.config.temperature,
                messages=[
                    {"role": "user", "content": full_prompt}
                ]
            )
            
            # Extract and validate content
            content = response.content[0].text
            return self._extract_json_from_text(content)
        except Exception as e:
            self.logger.error(f"Anthropic response processing error: {str(e)}")
            raise
    
    def _extract_json_from_gemini(self, response) -> Dict[str, Any]:
        """
        Extract and parse JSON from Gemini response.
        
        Args:
            response: Raw Gemini response object
        
        Returns:
            Parsed JSON as dictionary
        """
        try:
            # Access the nested structure correctly
            content = response.candidates[0].content.parts[0].text
            return self._extract_json_from_text(content)
        except Exception as e:
            self.logger.error(f"Failed to parse Gemini response: {str(e)}")
            raise
    
    def _extract_json_from_text(self, content: str) -> Dict[str, Any]:
        """
        Extract and parse JSON from text content, handling various formats.
        
        Args:
            content: Text content that may contain JSON
        
        Returns:
            Parsed JSON as dictionary
        """
        # Remove markdown code blocks if present
        if self.config.enable_markdown_parsing:
            content = re.sub(r'```(?:json)?', '', content).strip()
        
        # Try direct JSON parsing first
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            # Try to extract JSON using regex
            json_match = re.search(r'\{.*\}', content, re.DOTALL)
            if json_match:
                try:
                    json_str = json_match.group(0)
                    return json.loads(json_str)
                except json.JSONDecodeError:
                    pass
            
            # If all else fails, try using eval() with safeguards
            try:
                sanitized = content.replace('null', 'None').replace('true', 'True').replace('false', 'False')
                result = eval(sanitized)
                if isinstance(result, dict):
                    return result
            except Exception:
                pass
            
            raise ValueError(f"Could not extract valid JSON from response: {content[:100]}...")
    
    def _is_valid_analysis(self, results: Dict[str, Any]) -> bool:
        """
        Validate that analysis results meet the required format.
        
        Args:
            results: Analysis results to validate
        
        Returns:
            Boolean indicating if results are valid
        """
        if not isinstance(results, dict):
            return False
        
        if "vulnerabilities" not in results:
            return False
        
        # Check if vulnerabilities is a list
        if not isinstance(results["vulnerabilities"], list):
            return False
        
        # If there are no vulnerabilities, that's valid (might be secure code)
        if not results["vulnerabilities"]:
            return True
        
        # Check that each vulnerability has the required fields
        required_fields = [
            "type", "severity", "location", "description", 
            "impact", "remediation", "cwe_id", "owasp_category", 
            "cvss_score", "references", "proof_of_concept", "secure_code_example"
        ]
        
        for vuln in results["vulnerabilities"]:
            if not all(field in vuln for field in required_fields):
                return False
                
            # Validate location field structure
            location_fields = ["file_path", "start_line", "end_line"]
            if not all(field in vuln["location"] for field in location_fields):
                return False
        
        return True
    
    def _build_security_prompt(self) -> str:
        """
        Build the security analysis prompt with detailed instructions.
        
        Returns:
            String containing the security analysis prompt
        """
        prompt = """You are a security expert performing code analysis.
        Analyze the provided code for security vulnerabilities, focusing on:
        1. OWASP Top 10 vulnerabilities (2021 version)
        2. SANS Top 25 vulnerabilities
        3. Language-specific security issues
        4. Security best practices and secure coding patterns

        IMPORTANT: Respond with ONLY the raw JSON data, without any markdown formatting or code blocks.
        Your response should be valid JSON that can be directly parsed.

        The response must follow this structure:
        {
            "vulnerabilities": [
                {
                    "type": "VULNERABILITY_TYPE_NAME_WITH_UNDERSCORES",
                    "severity": "SEVERITY_LEVEL",
                    "location": {
                        "file_path": "path/to/file",
                        "start_line": line_number,
                        "end_line": line_number,
                        "start_col": column_number,
                        "end_col": column_number,
                        "context": "code_snippet"
                    },
                    "description": "Detailed description of the vulnerability",
                    "impact": "Potential impact of exploitation",
                    "remediation": "How to fix the vulnerability",
                    "cwe_id": "CWE_ID",
                    "owasp_category": "OWASP CATEGORY (Format example: A10:2021 - Server-Side Request Forgery (SSRF))",
                    "cvss_score": "CVSS_SCORE",
                    "references": ["REFERENCE_URL_1", "REFERENCE_URL_2", etc.],
                    "proof_of_concept": "POC_CODE",
                    "secure_code_example": "SECURE_CODE_EXAMPLE"
                }
            ]
        }

        Note: The vulnerability type must use UPPERCASE with UNDERSCORES (e.g., INSECURE_DESERIALIZATION, SQL_INJECTION, XSS_VULNERABILITY). If the identified vulnerability type matches any of the predefined types, use that type instead of creating some new type. If a type doesn't match predefined types, use GENERIC_SECURITY_ISSUE.
        """

        # Append the vulnerability types
        prompt += "\n\nPredefined Vulnerability Types:\n"
        for vuln_type in self.vulnerability_types:
            prompt += f"- {vuln_type}\n"
        
        # Add example vulnerabilities if configured
        if self.config.include_detailed_examples:
            prompt += self._get_example_vulnerabilities()
        
        return prompt
    
    def _get_example_vulnerabilities(self) -> str:
        """
        Get examples of properly formatted vulnerability reports.
        
        Returns:
            String with example vulnerabilities
        """
        return """
        Example vulnerability entry:
        
        {
            "type": "SQL_INJECTION",
            "severity": "HIGH",
            "location": {
                "file_path": "app/routes.py",
                "start_line": 45,
                "end_line": 47,
                "start_col": 12,
                "end_col": 78,
                "context": "query = f\"SELECT * FROM users WHERE username = '{username}'\"\\nresult = db.execute(query)"
            },
            "description": "Raw user input is directly concatenated into an SQL query without proper sanitization or parameterization. This allows attackers to inject malicious SQL code.",
            "impact": "An attacker could bypass authentication, access, modify, or delete sensitive data, or execute administrative operations on the database.",
            "remediation": "Use parameterized queries or prepared statements instead of string concatenation. Example: db.execute('SELECT * FROM users WHERE username = ?', (username,))",
            "cwe_id": "CWE-89",
            "owasp_category": "A3:2021 - Injection",
            "cvss_score": 8.5,
            "references": ["https://owasp.org/Top10/A03_2021-Injection/", "https://cwe.mitre.org/data/definitions/89.html"],
            "proof_of_concept": "username = \"' OR 1=1 --\"",
            "secure_code_example": "query = \"SELECT * FROM users WHERE username = ?\"\\nresult = db.execute(query, (username,))"
        }
        """