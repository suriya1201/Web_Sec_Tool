# security/code_processor.py

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
import logging


class CodeProcessor:
    """
    Processes source code to extract structural information and patterns
    that may be relevant for security analysis.
    """
    
    def __init__(self):
        """Initialize code processor with language-specific settings."""
        self.logger = logging.getLogger(__name__)
        
        # Map file extensions to language names
        self.language_map = {
            '.py': 'Python',
            '.js': 'JavaScript',
            '.ts': 'TypeScript',
            '.jsx': 'React JSX',
            '.tsx': 'React TSX',
            '.java': 'Java',
            '.cpp': 'C++',
            '.cc': 'C++',
            '.c': 'C',
            '.h': 'C/C++ Header',
            '.hpp': 'C++ Header',
            '.cs': 'C#',
            '.go': 'Go',
            '.rb': 'Ruby',
            '.php': 'PHP',
            '.rs': 'Rust',
            '.swift': 'Swift',
            '.kt': 'Kotlin',
            '.scala': 'Scala',
            '.sh': 'Shell',
            '.yaml': 'YAML',
            '.yml': 'YAML',
            '.json': 'JSON',
            '.xml': 'XML',
            '.html': 'HTML',
            '.css': 'CSS',
            '.sql': 'SQL'
        }
        
        # Language-specific comment patterns
        self.comment_patterns = {
            'Python': {
                'single_line': ['#'],
                'multi_line': [('"""', '"""'), ("'''", "'''")]
            },
            'JavaScript': {
                'single_line': ['//'],
                'multi_line': [('/*', '*/')]
            },
            'TypeScript': {
                'single_line': ['//'],
                'multi_line': [('/*', '*/')]
            },
            'Java': {
                'single_line': ['//'],
                'multi_line': [('/*', '*/'), ('/**', '*/')]
            },
            'C': {
                'single_line': ['//'],
                'multi_line': [('/*', '*/')]
            },
            'C++': {
                'single_line': ['//'],
                'multi_line': [('/*', '*/')]
            },
            'C#': {
                'single_line': ['//'],
                'multi_line': [('/*', '*/'), ('///', '')]
            },
            'Go': {
                'single_line': ['//'],
                'multi_line': [('/*', '*/')]
            },
            'Ruby': {
                'single_line': ['#'],
                'multi_line': [('=begin', '=end')]
            },
            'PHP': {
                'single_line': ['//', '#'],
                'multi_line': [('/*', '*/'), ('/**', '*/')]
            },
            'SQL': {
                'single_line': ['--'],
                'multi_line': [('/*', '*/')]
            }
        }
        
        # Language-specific import patterns
        self.import_patterns = {
            'Python': [
                r'^\s*import\s+([^;]+)',
                r'^\s*from\s+([^\s]+)\s+import\s+([^;]+)'
            ],
            'JavaScript': [
                r'^\s*import\s+.*\s+from\s+[\'"]([^\'"]+)[\'"]',
                r'^\s*const\s+.*\s*=\s*require\([\'"]([^\'"]+)[\'"]\)',
                r'^\s*import\s+[\'"]([^\'"]+)[\'"]'
            ],
            'TypeScript': [
                r'^\s*import\s+.*\s+from\s+[\'"]([^\'"]+)[\'"]',
                r'^\s*import\s+[\'"]([^\'"]+)[\'"]'
            ],
            'Java': [
                r'^\s*import\s+([^;]+);'
            ],
            'C#': [
                r'^\s*using\s+([^;]+);'
            ],
            'Go': [
                r'^\s*import\s+[\(]?([^\)]+)[\)]?'
            ],
            'Ruby': [
                r'^\s*require\s+[\'"]([^\'"]+)[\'"]',
                r'^\s*require_relative\s+[\'"]([^\'"]+)[\'"]'
            ],
            'PHP': [
                r'^\s*require(_once)?\s+[\'"]([^\'"]+)[\'"]',
                r'^\s*include(_once)?\s+[\'"]([^\'"]+)[\'"]',
                r'^\s*use\s+([^;]+);'
            ]
        }
        
        # Language-specific security-sensitive patterns
        self.security_patterns = {
            'Python': {
                'sql_injection': [
                    r'execute\(.*\+.*\)',
                    r'execute\(f["\'].*{.*}',
                    r'cursor\.execute\([^,]*%[^,]*\)'
                ],
                'command_injection': [
                    r'os\.system\(',
                    r'subprocess\.call\(',
                    r'subprocess\.Popen\(',
                    r'eval\(',
                    r'exec\('
                ],
                'path_traversal': [
                    r'open\(.*\+.*\)',
                    r'open\(f["\'].*{.*}'
                ],
                'insecure_deserialization': [
                    r'pickle\.loads\(',
                    r'yaml\.load\(',
                    r'marshal\.loads\('
                ],
                'hardcoded_secrets': [
                    r'password\s*=\s*["\'][^"\']+["\']',
                    r'secret\s*=\s*["\'][^"\']+["\']',
                    r'api_key\s*=\s*["\'][^"\']+["\']'
                ]
            },
            'JavaScript': {
                'sql_injection': [
                    r'execute\(.*\+.*\)',
                    r'query\(.*\+.*\)',
                    r'executeQuery\(.*\+.*\)'
                ],
                'command_injection': [
                    r'exec\(.*\+.*\)',
                    r'spawn\(.*\+.*\)',
                    r'eval\('
                ],
                'xss': [
                    r'innerHTML\s*=',
                    r'outerHTML\s*=',
                    r'document\.write\('
                ],
                'path_traversal': [
                    r'fs\.readFile\(.*\+.*\)',
                    r'fs\.writeFile\(.*\+.*\)'
                ],
                'hardcoded_secrets': [
                    r'password\s*=\s*["\'][^"\']+["\']',
                    r'secret\s*=\s*["\'][^"\']+["\']',
                    r'apiKey\s*=\s*["\'][^"\']+["\']'
                ]
            }
        }
    
    def process(self, content: str, filename: str) -> Dict[str, Any]:
        """
        Process source code to extract information for security analysis.
        
        Args:
            content: Source code content
            filename: Name of the source file
            
        Returns:
            Dictionary with extracted code information
        """
        # Determine language from file extension
        file_extension = Path(filename).suffix.lower()
        language = self.language_map.get(file_extension, 'Unknown')
        
        # Process the code
        result = {
            'language': language,
            'file_type': file_extension,
            'file_name': filename,
            'content': content,
            'line_count': content.count('\n') + 1,
            'size_bytes': len(content),
            'metadata': self._extract_metadata(content, language),
            'imports': self._extract_imports(content, language),
            'functions': self._extract_functions(content, language),
            'classes': self._extract_classes(content, language),
            'security_patterns': self._detect_security_patterns(content, language)
        }
        
        return result
    
    def _extract_metadata(self, content: str, language: str) -> Dict[str, Any]:
        """
        Extract metadata from source code including comments, documentation.
        
        Args:
            content: Source code content
            language: Programming language
            
        Returns:
            Dictionary with metadata information
        """
        metadata = {
            'has_documentation': False,
            'comment_lines': 0,
            'todo_count': 0,
            'fixme_count': 0,
            'security_notes': []
        }
        
        # Skip if language not supported
        if language not in self.comment_patterns:
            return metadata
        
        comment_info = self.comment_patterns[language]
        lines = content.split('\n')
        in_multiline_comment = False
        current_multiline_delimiters = None
        
        for line_num, line in enumerate(lines, 1):
            stripped_line = line.strip()
            
            # Handle multi-line comments
            if in_multiline_comment:
                metadata['comment_lines'] += 1
                if current_multiline_delimiters[1] in stripped_line:
                    in_multiline_comment = False
                    current_multiline_delimiters = None
                self._check_comment_tags(stripped_line, metadata)
                continue
            
            # Check for start of multi-line comments
            for start, end in comment_info.get('multi_line', []):
                if start in stripped_line:
                    in_multiline_comment = True
                    current_multiline_delimiters = (start, end)
                    metadata['comment_lines'] += 1
                    metadata['has_documentation'] = True
                    self._check_comment_tags(stripped_line, metadata)
                    break
            
            if in_multiline_comment:
                continue
            
            # Check for single-line comments
            for marker in comment_info.get('single_line', []):
                if stripped_line.startswith(marker):
                    metadata['comment_lines'] += 1
                    self._check_comment_tags(stripped_line, metadata)
                    break
        
        # Look for security-related comment markers
        security_markers = ['security', 'vulnerability', 'risk', 'exploit', 'unsafe', 'attack']
        for marker in security_markers:
            for i, line in enumerate(lines, 1):
                if marker in line.lower():
                    metadata['security_notes'].append({
                        'line': i,
                        'content': line.strip()
                    })
        
        return metadata
    
    def _check_comment_tags(self, comment_line: str, metadata: Dict[str, Any]) -> None:
        """
        Check comment line for common tags like TODO, FIXME, etc.
        
        Args:
            comment_line: The comment line to check
            metadata: Metadata dictionary to update
        """
        lower_line = comment_line.lower()
        if 'todo' in lower_line:
            metadata['todo_count'] += 1
        if 'fixme' in lower_line:
            metadata['fixme_count'] += 1
        if any(tag in lower_line for tag in ['hack', 'workaround', 'security']):
            metadata.setdefault('tags', []).append({
                'tag': next(tag for tag in ['hack', 'workaround', 'security'] 
                           if tag in lower_line),
                'content': comment_line
            })
    
    def _extract_imports(self, content: str, language: str) -> List[str]:
        """
        Extract import statements from source code.
        
        Args:
            content: Source code content
            language: Programming language
            
        Returns:
            List of import statements
        """
        imports = []
        
        # Skip if language not supported
        if language not in self.import_patterns:
            return imports
        
        patterns = self.import_patterns[language]
        lines = content.split('\n')
        
        for line in lines:
            for pattern in patterns:
                matches = re.findall(pattern, line)
                if matches:
                    # Handle different match types
                    if isinstance(matches[0], tuple):
                        # Flatten tuple matches
                        for match_group in matches:
                            imports.extend(match_group)
                    else:
                        imports.extend(matches)
        
        # Clean and normalize imports
        cleaned_imports = []
        for imp in imports:
            imp = imp.strip()
            if imp and len(imp) < 100:  # Reasonable length check
                cleaned_imports.append(imp)
        
        return cleaned_imports
    
    def _extract_functions(self, content: str, language: str) -> List[Dict[str, Any]]:
        """
        Extract function definitions from source code.
        
        Args:
            content: Source code content
            language: Programming language
            
        Returns:
            List of function information dictionaries
        """
        functions = []
        
        if language == 'Python':
            # Python function detection
            function_pattern = r'(async\s+)?def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
            matches = re.finditer(function_pattern, content)
            
            for match in matches:
                is_async = bool(match.group(1))
                func_name = match.group(2)
                line_num = content[:match.start()].count('\n') + 1
                
                # Extract parameter information
                func_line = content.split('\n')[line_num - 1]
                params_match = re.search(r'\((.*?)\)', func_line)
                params = []
                
                if params_match:
                    params_str = params_match.group(1).strip()
                    if params_str:
                        params = [p.strip() for p in params_str.split(',')]
                
                functions.append({
                    'name': func_name,
                    'line': line_num,
                    'is_async': is_async,
                    'parameters': params
                })
        
        elif language in ['JavaScript', 'TypeScript']:
            # JS/TS function patterns - both regular and arrow functions
            patterns = [
                r'(async\s+)?function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(',  # function declarations
                r'(async\s+)?([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*function\s*\(',  # function expressions
                r'(async\s+)?([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*\(.*?\)\s*=>'  # arrow functions
            ]
            
            for pattern in patterns:
                matches = re.finditer(pattern, content)
                for match in matches:
                    is_async = bool(match.group(1))
                    func_name = match.group(2)
                    line_num = content[:match.start()].count('\n') + 1
                    
                    functions.append({
                        'name': func_name,
                        'line': line_num,
                        'is_async': is_async
                    })
        
        elif language == 'Java':
            # Java method pattern
            method_pattern = r'(?:public|protected|private|static|\s)+(?:[a-zA-Z0-9_<>]+\s+)+([a-zA-Z0-9_]+)\s*\([^)]*\)\s*(?:throws\s+[^{]+)?\s*\{'
            matches = re.finditer(method_pattern, content)
            
            for match in matches:
                method_name = match.group(1)
                line_num = content[:match.start()].count('\n') + 1
                
                functions.append({
                    'name': method_name,
                    'line': line_num,
                    'is_async': False  # Java uses different concurrency model
                })
        
        return functions
    
    def _extract_classes(self, content: str, language: str) -> List[Dict[str, Any]]:
        """
        Extract class definitions from source code.
        
        Args:
            content: Source code content
            language: Programming language
            
        Returns:
            List of class information dictionaries
        """
        classes = []
        
        if language == 'Python':
            # Python class pattern
            class_pattern = r'class\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\([^)]*\))?:'
            matches = re.finditer(class_pattern, content)
            
            for match in matches:
                class_name = match.group(1)
                line_num = content[:match.start()].count('\n') + 1
                
                # Check for inheritance
                class_line = content.split('\n')[line_num - 1]
                parents = []
                
                parents_match = re.search(r'\((.*?)\)', class_line)
                if parents_match:
                    parents_str = parents_match.group(1).strip()
                    if parents_str:
                        parents = [p.strip() for p in parents_str.split(',')]
                
                classes.append({
                    'name': class_name,
                    'line': line_num,
                    'parents': parents
                })
        
        elif language in ['JavaScript', 'TypeScript']:
            # JS/TS class pattern
            class_pattern = r'class\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*(?:extends\s+([a-zA-Z_$][a-zA-Z0-9_$]*))?'
            matches = re.finditer(class_pattern, content)
            
            for match in matches:
                class_name = match.group(1)
                parent = match.group(2)
                line_num = content[:match.start()].count('\n') + 1
                
                classes.append({
                    'name': class_name,
                    'line': line_num,
                    'parents': [parent] if parent else []
                })
        
        elif language == 'Java':
            # Java class pattern
            class_pattern = r'(?:public|protected|private|abstract|\s)*(class|interface|enum)\s+([a-zA-Z0-9_]+)(?:\s+extends\s+([a-zA-Z0-9_]+))?(?:\s+implements\s+([^{]+))?'
            matches = re.finditer(class_pattern, content)
            
            for match in matches:
                class_type = match.group(1)  # class, interface, or enum
                class_name = match.group(2)
                parent = match.group(3)
                interfaces = match.group(4)
                line_num = content[:match.start()].count('\n') + 1
                
                parents = []
                if parent:
                    parents.append(parent)
                
                if interfaces:
                    interfaces = [i.strip() for i in interfaces.split(',')]
                    parents.extend(interfaces)
                
                classes.append({
                    'name': class_name,
                    'line': line_num,
                    'type': class_type,
                    'parents': parents
                })
        
        return classes
    
    def _detect_security_patterns(self, content: str, language: str) -> Dict[str, List[Dict[str, Any]]]:
        """
        Detect potentially security-relevant patterns in code.
        
        Args:
            content: Source code content
            language: Programming language
            
        Returns:
            Dictionary mapping pattern types to locations
        """
        patterns = {}
        
        # Skip if language not supported
        if language not in self.security_patterns:
            return patterns
        
        # Get language-specific patterns
        lang_patterns = self.security_patterns[language]
        lines = content.split('\n')
        
        # Check for each pattern type
        for pattern_type, regex_patterns in lang_patterns.items():
            matches = []
            
            for pattern in regex_patterns:
                for i, line in enumerate(lines, 1):
                    if re.search(pattern, line):
                        matches.append({
                            'line': i,
                            'content': line.strip(),
                            'pattern': pattern
                        })
            
            if matches:
                patterns[pattern_type] = matches
        
        return patterns
    
    def get_complexity_metrics(self, content: str, language: str) -> Dict[str, Any]:
        """
        Calculate code complexity metrics.
        
        Args:
            content: Source code content
            language: Programming language
            
        Returns:
            Dictionary with complexity metrics
        """
        metrics = {
            'cyclomatic_complexity': 0,
            'nesting_depth': 0,
            'max_function_length': 0
        }
        
        lines = content.split('\n')
        
        # Calculate cyclomatic complexity (simplified)
        if_count = 0
        for_count = 0
        while_count = 0
        
        for line in lines:
            # Count control flow statements
            if re.search(r'\bif\b', line):
                if_count += 1
            if re.search(r'\bfor\b', line):
                for_count += 1
            if re.search(r'\bwhile\b', line):
                while_count += 1
        
        metrics['cyclomatic_complexity'] = 1 + if_count + for_count + while_count
        
        # Calculate maximum nesting depth
        current_depth = 0
        max_depth = 0
        
        for line in lines:
            stripped = line.strip()
            
            # Increase depth for opening blocks
            if re.search(r'[{:]$', stripped):
                current_depth += 1
                max_depth = max(max_depth, current_depth)
            
            # Decrease depth for closing blocks
            if re.search(r'^[}]', stripped):
                current_depth = max(0, current_depth - 1)
        
        metrics['nesting_depth'] = max_depth
        
        # Calculate maximum function length in lines
        in_function = False
        current_function_lines = 0
        max_function_lines = 0
        
        for line in lines:
            stripped = line.strip()
            
            # Detect function/method start
            if (re.search(r'\bdef\b.*:', stripped) or 
                re.search(r'\bfunction\b.*{', stripped) or
                re.search(r'=>.*{', stripped)):
                in_function = True
                current_function_lines = 1
            
            # Count function lines
            elif in_function:
                current_function_lines += 1
                
                # Detect function end
                if stripped == '}' or (language == 'Python' and not stripped and 
                                      not line.startswith(' ') and not line.startswith('\t')):
                    in_function = False
                    max_function_lines = max(max_function_lines, current_function_lines)
        
        metrics['max_function_length'] = max_function_lines
        
        return metrics