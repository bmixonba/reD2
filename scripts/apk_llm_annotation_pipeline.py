#!/usr/bin/env python3
"""
APK LLM Annotation Pipeline for generating training data from APKs.

This script provides a modular pipeline for analyzing APKs and generating
LLM training data from both Java and native (SO) code. It leverages existing
APK analysis infrastructure and pyghidra integration for comprehensive analysis.

Usage:
    python scripts/apk_llm_annotation_pipeline.py --input-apk app.apk --output corpus.jsonl
    python scripts/apk_llm_annotation_pipeline.py --input-dir apks/ --output-dir corpus/
    python scripts/apk_llm_annotation_pipeline.py --apk-list apks.txt --output training_data.jsonl
"""

import os
import sys
import json
import argparse
import logging
import tempfile
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from datetime import datetime

# Add parent directory to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from utils.apk import APKAnalyzer, analyze_apk_comprehensive
from utils.shared_library_analyzer import SharedLibraryAnalyzer
from utils.pyghidra_integration import PyGhidraAnalyzer, check_pyghidra_availability


@dataclass
class AnnotationResult:
    """Data class for storing annotation results."""
    file_path: str
    file_type: str  # 'java' or 'so'
    labels: List[str]
    confidence: float
    content_preview: str
    analysis_data: Dict[str, Any]


@dataclass
class PromptCompletionPair:
    """Data class for LLM training prompt/completion pairs."""
    prompt: str
    completion: str
    metadata: Dict[str, Any]


class JavaCodeAnnotator:
    """Annotator for Java code with security and functionality labels."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Define annotation patterns and their labels
        self.annotation_patterns = {
            'encryption_decryption': [
                r'AES|DES|RSA|Cipher|encrypt|decrypt|KeyGenerator',
                r'javax\.crypto|java\.security',
                r'SecretKey|PublicKey|PrivateKey'
            ],
            'network_communication': [
                r'HttpURLConnection|OkHttp|Retrofit|Volley',
                r'Socket|ServerSocket|URL|URI',
                r'NetworkInterface|ConnectivityManager'
            ],
            'file_operations': [
                r'FileInputStream|FileOutputStream|File\.',
                r'openFile|createFile|deleteFile',
                r'SharedPreferences|SQLiteDatabase'
            ],
            'authentication': [
                r'login|auth|password|token|session',
                r'BiometricManager|FingerprintManager',
                r'KeyStore|TrustManager'
            ],
            'web_browser': [
                r'WebView|WebSettings|WebViewClient',
                r'loadUrl|evaluateJavascript',
                r'CookieManager|WebStorage'
            ],
            'update_logic': [
                r'PackageManager|PackageInstaller',
                r'DownloadManager|updateApp',
                r'version|upgrade|download'
            ],
            'permissions': [
                r'checkPermission|requestPermission',
                r'PERMISSION_GRANTED|PERMISSION_DENIED',
                r'ActivityCompat\.checkSelfPermission'
            ],
            'location_services': [
                r'LocationManager|GPS|Location',
                r'getLatitude|getLongitude',
                r'ACCESS_FINE_LOCATION|ACCESS_COARSE_LOCATION'
            ],
            'device_info': [
                r'Build\.|TelephonyManager|DeviceId',
                r'getSystemService|IMEI|Android\.ID',
                r'Settings\.Secure\.getString'
            ],
            'anti_analysis': [
                r'debug|Debug|isDebuggerConnected',
                r'emulator|virtual|Emulator',
                r'root|Root|isRooted'
            ]
        }
    
    def annotate_java_file(self, file_path: str, content: str) -> AnnotationResult:
        """
        Annotate a Java file with high-level functionality labels.
        
        Args:
            file_path: Path to the Java file
            content: File content as string
            
        Returns:
            AnnotationResult with detected labels and metadata
        """
        labels = []
        confidence_scores = []
        analysis_data = {
            'method_count': self._count_methods(content),
            'class_count': self._count_classes(content),
            'import_count': self._count_imports(content),
            'line_count': len(content.split('\n')),
            'detected_patterns': {}
        }
        
        # Apply pattern matching for each category
        for category, patterns in self.annotation_patterns.items():
            matches = self._find_pattern_matches(content, patterns)
            if matches:
                labels.append(category)
                confidence = min(1.0, len(matches) * 0.1)  # Simple confidence calculation
                confidence_scores.append(confidence)
                analysis_data['detected_patterns'][category] = matches
        
        # Calculate overall confidence
        overall_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0.0
        
        return AnnotationResult(
            file_path=file_path,
            file_type='java',
            labels=labels,
            confidence=overall_confidence,
            content_preview=self._get_content_preview(content),
            analysis_data=analysis_data
        )
    
    def _find_pattern_matches(self, content: str, patterns: List[str]) -> List[str]:
        """Find all matches for a list of regex patterns."""
        import re
        matches = []
        for pattern in patterns:
            found = re.findall(pattern, content, re.IGNORECASE)
            matches.extend(found)
        return list(set(matches))  # Remove duplicates
    
    def _count_methods(self, content: str) -> int:
        """Count the number of methods in Java code."""
        import re
        # Simple method detection pattern
        method_pattern = r'(public|private|protected|static).*?\w+\s*\([^)]*\)\s*\{'
        return len(re.findall(method_pattern, content, re.MULTILINE))
    
    def _count_classes(self, content: str) -> int:
        """Count the number of classes in Java code."""
        import re
        class_pattern = r'(public\s+)?(class|interface|enum)\s+\w+'
        return len(re.findall(class_pattern, content))
    
    def _count_imports(self, content: str) -> int:
        """Count the number of import statements."""
        import re
        import_pattern = r'^import\s+[^;]+;'
        return len(re.findall(import_pattern, content, re.MULTILINE))
    
    def _get_content_preview(self, content: str, max_lines: int = 10) -> str:
        """Get a preview of the file content."""
        lines = content.split('\n')
        preview_lines = lines[:max_lines]
        preview = '\n'.join(preview_lines)
        if len(lines) > max_lines:
            preview += f'\n... ({len(lines) - max_lines} more lines)'
        return preview


class SOCodeAnnotator:
    """Annotator for native shared library (SO) code with security and functionality labels."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.shared_lib_analyzer = SharedLibraryAnalyzer()
        
        # Initialize PyGhidra analyzer if available
        self.ghidra_available, self.ghidra_status = check_pyghidra_availability()
        if self.ghidra_available:
            self.ghidra_analyzer = PyGhidraAnalyzer()
            self.logger.info("PyGhidra integration enabled for SO analysis")
        else:
            self.ghidra_analyzer = None
            self.logger.info(f"PyGhidra not available: {self.ghidra_status}")
        
        # Define annotation patterns for native code
        self.annotation_patterns = {
            'encryption_decryption': [
                'AES_', 'DES_', 'RSA_', 'encrypt', 'decrypt', 'cipher',
                'openssl', 'crypto', 'md5', 'sha1', 'sha256'
            ],
            'network_communication': [
                'socket', 'connect', 'bind', 'listen', 'accept',
                'send', 'recv', 'http', 'ssl', 'tls'
            ],
            'file_operations': [
                'fopen', 'fread', 'fwrite', 'fclose', 'open', 'read', 'write',
                'mkdir', 'chmod', 'chown', 'unlink'
            ],
            'memory_management': [
                'malloc', 'calloc', 'realloc', 'free', 'mmap', 'munmap',
                'memcpy', 'memset', 'strcpy', 'strncpy'
            ],
            'process_threading': [
                'fork', 'exec', 'pthread_create', 'pthread_join',
                'thread', 'process', 'signal'
            ],
            'system_calls': [
                'syscall', 'ioctl', 'ptrace', 'prctl',
                'getuid', 'setuid', 'root'
            ],
            'anti_analysis': [
                'debug', 'trace', 'anti', 'detect', 'emulator',
                'virtual', 'vm', 'frida', 'xposed'
            ],
            'compression': [
                'zip', 'gzip', 'deflate', 'inflate', 'compress',
                'decompress', 'zlib'
            ],
            'jni_interface': [
                'JNI_', 'jni', 'JavaVM', 'JNIEnv', 'jstring',
                'jclass', 'jmethodID', 'jfieldID'
            ]
        }
    
    def annotate_so_file(self, file_path: str) -> AnnotationResult:
        """
        Annotate a shared library file with high-level functionality labels.
        
        Args:
            file_path: Path to the SO file
            
        Returns:
            AnnotationResult with detected labels and metadata
        """
        labels = []
        confidence_scores = []
        analysis_data = {}
        
        try:
            # Perform standard analysis
            standard_analysis = self.shared_lib_analyzer.analyze_shared_library(file_path)
            analysis_data['standard_analysis'] = standard_analysis
            
            # Perform PyGhidra analysis if available
            if self.ghidra_available and self.ghidra_analyzer:
                ghidra_analysis = self.ghidra_analyzer.analyze_library(file_path)
                analysis_data['ghidra_analysis'] = ghidra_analysis
                decompiled_code = self._extract_decompiled_code(ghidra_analysis)
            else:
                decompiled_code = ""
            
            # Extract strings for analysis
            strings_data = standard_analysis.get('strings', {})
            all_strings = []
            if isinstance(strings_data, dict):
                all_strings.extend(strings_data.get('ascii_strings', []))
                all_strings.extend(strings_data.get('unicode_strings', []))
            
            # Extract symbols for analysis
            symbols_data = standard_analysis.get('symbols', {})
            all_symbols = []
            if isinstance(symbols_data, dict):
                all_symbols.extend(symbols_data.get('exported_symbols', []))
                all_symbols.extend(symbols_data.get('imported_symbols', []))
            
            # Combine content for pattern matching
            combined_content = ' '.join(all_strings + all_symbols + [decompiled_code])
            
            # Apply pattern matching
            for category, patterns in self.annotation_patterns.items():
                matches = self._find_string_matches(combined_content, patterns)
                if matches:
                    labels.append(category)
                    confidence = min(1.0, len(matches) * 0.1)
                    confidence_scores.append(confidence)
                    analysis_data.setdefault('detected_patterns', {})[category] = matches
            
            # Add additional analysis-based labels
            additional_labels = self._analyze_characteristics(standard_analysis)
            labels.extend(additional_labels)
            
            # Calculate overall confidence
            overall_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0.0
            
            return AnnotationResult(
                file_path=file_path,
                file_type='so',
                labels=list(set(labels)),  # Remove duplicates
                confidence=overall_confidence,
                content_preview=self._generate_so_preview(standard_analysis, decompiled_code),
                analysis_data=analysis_data
            )
            
        except Exception as e:
            self.logger.error(f"Error annotating SO file {file_path}: {e}")
            return AnnotationResult(
                file_path=file_path,
                file_type='so',
                labels=['analysis_error'],
                confidence=0.0,
                content_preview=f"Error during analysis: {str(e)}",
                analysis_data={'error': str(e)}
            )
    
    def _extract_decompiled_code(self, ghidra_analysis: Dict) -> str:
        """Extract decompiled code from Ghidra analysis results."""
        if not ghidra_analysis.get('available', False):
            return ""
        
        # Extract function information as pseudocode representation
        functions = ghidra_analysis.get('functions', {})
        function_details = functions.get('function_details', [])
        
        decompiled_parts = []
        for func in function_details[:10]:  # Limit to first 10 functions
            if not func.get('is_external', True):
                signature = func.get('signature', f"function_{func.get('name', 'unknown')}")
                decompiled_parts.append(f"// Function: {signature}")
                decompiled_parts.append(f"// Address: {func.get('address', 'unknown')}")
                decompiled_parts.append(f"// Size: {func.get('size', 'unknown')} bytes")
                decompiled_parts.append("")
        
        return '\n'.join(decompiled_parts)
    
    def _find_string_matches(self, content: str, patterns: List[str]) -> List[str]:
        """Find string matches for given patterns."""
        content_lower = content.lower()
        matches = []
        for pattern in patterns:
            if pattern.lower() in content_lower:
                matches.append(pattern)
        return matches
    
    def _analyze_characteristics(self, analysis: Dict) -> List[str]:
        """Analyze characteristics of the SO file to determine additional labels."""
        additional_labels = []
        
        # Check security features
        security_info = analysis.get('security', {})
        if security_info.get('has_canary', False):
            additional_labels.append('security_hardened')
        if security_info.get('is_pie', False):
            additional_labels.append('position_independent')
        
        # Check for suspicious characteristics
        if analysis.get('summary', {}).get('risk_score', 0) > 0.5:
            additional_labels.append('potentially_suspicious')
        
        # Check architecture
        arch_info = analysis.get('architecture', {})
        if arch_info.get('detected_abi'):
            additional_labels.append(f"arch_{arch_info['detected_abi']}")
        
        return additional_labels
    
    def _generate_so_preview(self, analysis: Dict, decompiled_code: str) -> str:
        """Generate a preview of the SO file analysis."""
        preview_parts = []
        
        # Basic file info
        file_info = analysis.get('file_info', {})
        preview_parts.append(f"File size: {file_info.get('size', 'unknown')} bytes")
        preview_parts.append(f"Architecture: {analysis.get('architecture', {}).get('detected_abi', 'unknown')}")
        
        # Function count
        symbols = analysis.get('symbols', {})
        exported_count = len(symbols.get('exported_symbols', []))
        preview_parts.append(f"Exported symbols: {exported_count}")
        
        # Sample strings
        strings_data = analysis.get('strings', {})
        sample_strings = (strings_data.get('ascii_strings', []) + 
                         strings_data.get('unicode_strings', []))[:5]
        if sample_strings:
            preview_parts.append("Sample strings:")
            for s in sample_strings:
                preview_parts.append(f"  - {s[:50]}...")
        
        # Decompiled code preview
        if decompiled_code:
            preview_parts.append("\nDecompiled code preview:")
            preview_parts.append(decompiled_code[:500] + "..." if len(decompiled_code) > 500 else decompiled_code)
        
        return '\n'.join(preview_parts)


class PromptGenerator:
    """Generate prompt/completion pairs for LLM training from annotated code."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Define prompt templates for different use cases
        self.prompt_templates = {
            'code_explanation': {
                'prompt': "Analyze the following {file_type} code and explain its functionality, particularly focusing on {labels}:\n\n{content}\n\nExplanation:",
                'weight': 1.0
            },
            'security_analysis': {
                'prompt': "Perform a security analysis of this {file_type} code. Identify potential vulnerabilities and security implications:\n\n{content}\n\nSecurity Analysis:",
                'weight': 1.5  # Higher weight for security content
            },
            'functionality_labeling': {
                'prompt': "What are the main functionalities implemented in this {file_type} code? Label the key features:\n\n{content}\n\nMain functionalities:",
                'weight': 1.0
            },
            'pattern_identification': {
                'prompt': "Identify programming patterns and architectural decisions in this {file_type} code:\n\n{content}\n\nPatterns identified:",
                'weight': 1.0
            },
            'api_usage': {
                'prompt': "Analyze the API usage and external dependencies in this {file_type} code:\n\n{content}\n\nAPI Analysis:",
                'weight': 1.2
            }
        }
    
    def generate_prompt_completion_pairs(self, annotation: AnnotationResult, 
                                       max_pairs_per_file: int = 3) -> List[PromptCompletionPair]:
        """
        Generate multiple prompt/completion pairs from an annotation result.
        
        Args:
            annotation: AnnotationResult from code analysis
            max_pairs_per_file: Maximum number of pairs to generate per file
            
        Returns:
            List of PromptCompletionPair objects
        """
        pairs = []
        
        if not annotation.labels or annotation.confidence < 0.1:
            return pairs  # Skip low-confidence or unlabeled content
        
        # Select templates based on detected labels and confidence
        selected_templates = self._select_templates(annotation.labels, annotation.confidence)
        
        for template_name in selected_templates[:max_pairs_per_file]:
            template = self.prompt_templates[template_name]
            
            # Generate prompt
            prompt = template['prompt'].format(
                file_type=annotation.file_type.upper(),
                labels=', '.join(annotation.labels),
                content=self._prepare_content_for_prompt(annotation.content_preview)
            )
            
            # Generate completion
            completion = self._generate_completion(annotation, template_name)
            
            # Create metadata
            metadata = {
                'file_path': annotation.file_path,
                'file_type': annotation.file_type,
                'labels': annotation.labels,
                'confidence': annotation.confidence,
                'template_name': template_name,
                'template_weight': template['weight'],
                'generated_at': datetime.now().isoformat(),
                'analysis_data_hash': self._hash_analysis_data(annotation.analysis_data)
            }
            
            pairs.append(PromptCompletionPair(
                prompt=prompt,
                completion=completion,
                metadata=metadata
            ))
        
        return pairs
    
    def _select_templates(self, labels: List[str], confidence: float) -> List[str]:
        """Select appropriate templates based on labels and confidence."""
        selected = []
        
        # Always include basic functionality labeling
        selected.append('functionality_labeling')
        
        # Add security analysis for security-related labels
        security_labels = {'encryption_decryption', 'authentication', 'anti_analysis', 
                          'permissions', 'system_calls', 'potentially_suspicious'}
        if any(label in security_labels for label in labels):
            selected.append('security_analysis')
        
        # Add code explanation for high-confidence annotations
        if confidence > 0.5:
            selected.append('code_explanation')
        
        # Add pattern identification for complex code
        if len(labels) > 2:
            selected.append('pattern_identification')
        
        # Add API usage analysis for relevant labels
        api_labels = {'network_communication', 'file_operations', 'jni_interface', 
                     'web_browser', 'location_services'}
        if any(label in api_labels for label in labels):
            selected.append('api_usage')
        
        return selected
    
    def _prepare_content_for_prompt(self, content: str, max_length: int = 2000) -> str:
        """Prepare content for inclusion in prompts."""
        if len(content) <= max_length:
            return content
        
        # Truncate content but try to keep it meaningful
        truncated = content[:max_length]
        last_newline = truncated.rfind('\n')
        if last_newline > max_length * 0.8:  # If we can find a good breaking point
            truncated = truncated[:last_newline]
        
        return truncated + "\n\n[Content truncated...]"
    
    def _generate_completion(self, annotation: AnnotationResult, template_name: str) -> str:
        """Generate completion text based on annotation and template type."""
        if template_name == 'functionality_labeling':
            return self._generate_functionality_completion(annotation)
        elif template_name == 'security_analysis':
            return self._generate_security_completion(annotation)
        elif template_name == 'code_explanation':
            return self._generate_explanation_completion(annotation)
        elif template_name == 'pattern_identification':
            return self._generate_pattern_completion(annotation)
        elif template_name == 'api_usage':
            return self._generate_api_completion(annotation)
        else:
            return f"This {annotation.file_type} code implements: {', '.join(annotation.labels)}"
    
    def _generate_functionality_completion(self, annotation: AnnotationResult) -> str:
        """Generate functionality-focused completion."""
        completion_parts = []
        
        completion_parts.append("Main functionalities identified:")
        for i, label in enumerate(annotation.labels, 1):
            readable_label = label.replace('_', ' ').title()
            completion_parts.append(f"{i}. {readable_label}")
        
        # Add confidence indicator
        confidence_level = "high" if annotation.confidence > 0.7 else "medium" if annotation.confidence > 0.4 else "low"
        completion_parts.append(f"\nConfidence level: {confidence_level}")
        
        return '\n'.join(completion_parts)
    
    def _generate_security_completion(self, annotation: AnnotationResult) -> str:
        """Generate security-focused completion."""
        completion_parts = []
        
        security_labels = {'encryption_decryption', 'authentication', 'anti_analysis', 
                          'permissions', 'system_calls', 'potentially_suspicious'}
        security_found = [label for label in annotation.labels if label in security_labels]
        
        if security_found:
            completion_parts.append("Security-relevant functionality detected:")
            for label in security_found:
                if label == 'encryption_decryption':
                    completion_parts.append("- Cryptographic operations: This code handles encryption/decryption, which requires careful key management.")
                elif label == 'authentication':
                    completion_parts.append("- Authentication mechanisms: Handles user authentication, sensitive credential management required.")
                elif label == 'anti_analysis':
                    completion_parts.append("- Anti-analysis techniques: Contains debugging/analysis detection, may indicate evasion attempts.")
                elif label == 'permissions':
                    completion_parts.append("- Permission handling: Manages Android permissions, ensure proper permission checks.")
                elif label == 'system_calls':
                    completion_parts.append("- System-level operations: Direct system calls, potential for privilege escalation.")
                elif label == 'potentially_suspicious':
                    completion_parts.append("- Potentially suspicious behavior: Code patterns may indicate malicious intent.")
        else:
            completion_parts.append("No immediate security concerns identified in the analyzed code.")
        
        return '\n'.join(completion_parts)
    
    def _generate_explanation_completion(self, annotation: AnnotationResult) -> str:
        """Generate code explanation completion."""
        file_type = "Java" if annotation.file_type == 'java' else "native library"
        
        explanation = f"This {file_type} code implements several key functionalities:\n\n"
        
        for label in annotation.labels:
            readable_label = label.replace('_', ' ')
            explanation += f"• {readable_label.title()}: "
            
            # Add specific explanations for common patterns
            explanations = {
                'encryption decryption': 'Handles cryptographic operations for data security',
                'network communication': 'Manages network connections and data transmission',
                'file operations': 'Performs file system operations like reading, writing, and manipulation',
                'authentication': 'Implements user authentication and authorization mechanisms',
                'web browser': 'Provides web browsing capabilities through WebView components',
                'update logic': 'Handles application updates and version management',
                'jni interface': 'Provides bridge between Java and native code execution'
            }
            
            explanation += explanations.get(readable_label, f'Implements {readable_label} functionality')
            explanation += '\n'
        
        return explanation
    
    def _generate_pattern_completion(self, annotation: AnnotationResult) -> str:
        """Generate pattern identification completion."""
        completion_parts = ["Programming patterns and architectural decisions identified:"]
        
        # Analyze patterns based on labels
        if 'network_communication' in annotation.labels:
            completion_parts.append("• Network abstraction layer: Uses standard networking APIs")
        
        if 'encryption_decryption' in annotation.labels:
            completion_parts.append("• Security pattern: Implements cryptographic operations for data protection")
        
        if 'jni_interface' in annotation.labels:
            completion_parts.append("• Hybrid architecture: Bridges Java and native code execution")
        
        if 'file_operations' in annotation.labels:
            completion_parts.append("• Data persistence pattern: Handles local data storage and retrieval")
        
        # Add complexity assessment
        complexity = "high" if len(annotation.labels) > 4 else "medium" if len(annotation.labels) > 2 else "low"
        completion_parts.append(f"\nArchitectural complexity: {complexity}")
        
        return '\n'.join(completion_parts)
    
    def _generate_api_completion(self, annotation: AnnotationResult) -> str:
        """Generate API usage analysis completion."""
        completion_parts = ["API usage and external dependencies analysis:"]
        
        # Extract API information from analysis data
        analysis_data = annotation.analysis_data
        
        if annotation.file_type == 'java':
            import_count = analysis_data.get('import_count', 0)
            completion_parts.append(f"• Import statements: {import_count} external dependencies")
        elif annotation.file_type == 'so':
            standard_analysis = analysis_data.get('standard_analysis', {})
            symbols = standard_analysis.get('symbols', {})
            imported_count = len(symbols.get('imported_symbols', []))
            completion_parts.append(f"• Imported symbols: {imported_count} external dependencies")
        
        # Categorize API usage
        api_categories = {
            'network_communication': 'Network APIs for connectivity and data transfer',
            'file_operations': 'File system APIs for data persistence',
            'location_services': 'Location APIs for geographic functionality',
            'web_browser': 'Web rendering APIs for browser capabilities',
            'jni_interface': 'JNI APIs for native code integration'
        }
        
        for label in annotation.labels:
            if label in api_categories:
                completion_parts.append(f"• {api_categories[label]}")
        
        return '\n'.join(completion_parts)
    
    def _hash_analysis_data(self, analysis_data: Dict) -> str:
        """Generate a hash of analysis data for deduplication."""
        data_str = json.dumps(analysis_data, sort_keys=True, default=str)
        return hashlib.md5(data_str.encode()).hexdigest()


class APKLLMAnnotationPipeline:
    """Main pipeline for APK LLM annotation and training data generation."""
    
    def __init__(self, output_format: str = 'jsonl', verbose: bool = False):
        """
        Initialize the pipeline.
        
        Args:
            output_format: Output format ('jsonl' or 'json')
            verbose: Enable verbose logging
        """
        self.logger = logging.getLogger(__name__)
        self.output_format = output_format
        
        # Initialize components
        self.apk_analyzer = APKAnalyzer()
        self.java_annotator = JavaCodeAnnotator()
        self.so_annotator = SOCodeAnnotator()
        self.prompt_generator = PromptGenerator()
        
        # Configuration
        self.max_java_files = 50  # Limit Java files to process
        self.max_so_files = 10    # Limit SO files to process
        self.max_pairs_per_file = 3  # Max prompt/completion pairs per file
        
        self.logger.info(f"Pipeline initialized with {output_format} output format")
    
    def process_apk(self, apk_path: str) -> List[PromptCompletionPair]:
        """
        Process a single APK and generate training data.
        
        Args:
            apk_path: Path to the APK file
            
        Returns:
            List of PromptCompletionPair objects
        """
        self.logger.info(f"Processing APK: {apk_path}")
        
        try:
            # Step 1: Extract APK information and decompile
            self.logger.info("Step 1: Extracting APK info and decompiling...")
            apk_info = self.apk_analyzer.extract_apk_info(apk_path)
            
            with tempfile.TemporaryDirectory() as temp_dir:
                decompiled_dir = self.apk_analyzer.decompile_apk(apk_path, temp_dir)
                
                if not decompiled_dir:
                    self.logger.error(f"Failed to decompile APK: {apk_path}")
                    return []
                
                # Step 2: Find and analyze interesting Java files
                self.logger.info("Step 2: Analyzing Java files...")
                java_files = self.apk_analyzer.find_interesting_files(
                    decompiled_dir, topn=self.max_java_files
                )
                
                java_pairs = []
                for java_file in java_files:
                    try:
                        with open(java_file, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        
                        annotation = self.java_annotator.annotate_java_file(java_file, content)
                        pairs = self.prompt_generator.generate_prompt_completion_pairs(
                            annotation, self.max_pairs_per_file
                        )
                        java_pairs.extend(pairs)
                        
                    except Exception as e:
                        self.logger.warning(f"Error processing Java file {java_file}: {e}")
                
                # Step 3: Extract and analyze SO files
                self.logger.info("Step 3: Analyzing SO files...")
                so_pairs = self._process_so_files(apk_path)
                
                # Combine results
                all_pairs = java_pairs + so_pairs
                
                self.logger.info(f"Generated {len(all_pairs)} prompt/completion pairs from {apk_path}")
                return all_pairs
                
        except Exception as e:
            self.logger.error(f"Error processing APK {apk_path}: {e}")
            return []
    
    def _process_so_files(self, apk_path: str) -> List[PromptCompletionPair]:
        """Extract and analyze SO files from APK."""
        so_pairs = []
        
        try:
            from androguard.core import apk
            
            app = apk.APK(apk_path)
            so_files = [f for f in app.get_files() if f.endswith('.so')]
            
            self.logger.info(f"Found {len(so_files)} SO files in APK")
            
            for so_file in so_files[:self.max_so_files]:
                try:
                    # Extract SO file to temporary location
                    so_data = app.get_file(so_file)
                    if not so_data:
                        continue
                    
                    with tempfile.NamedTemporaryFile(delete=False, suffix='.so') as temp_file:
                        temp_file.write(so_data)
                        temp_so_path = temp_file.name
                    
                    # Annotate the SO file
                    annotation = self.so_annotator.annotate_so_file(temp_so_path)
                    annotation.file_path = so_file  # Use original APK path
                    
                    # Generate prompt/completion pairs
                    pairs = self.prompt_generator.generate_prompt_completion_pairs(
                        annotation, self.max_pairs_per_file
                    )
                    so_pairs.extend(pairs)
                    
                    # Clean up
                    os.unlink(temp_so_path)
                    
                except Exception as e:
                    self.logger.warning(f"Error processing SO file {so_file}: {e}")
            
        except Exception as e:
            self.logger.error(f"Error extracting SO files from {apk_path}: {e}")
        
        return so_pairs
    
    def process_multiple_apks(self, apk_paths: List[str]) -> List[PromptCompletionPair]:
        """
        Process multiple APK files.
        
        Args:
            apk_paths: List of APK file paths
            
        Returns:
            Combined list of PromptCompletionPair objects
        """
        all_pairs = []
        
        for i, apk_path in enumerate(apk_paths, 1):
            self.logger.info(f"Processing APK {i}/{len(apk_paths)}: {os.path.basename(apk_path)}")
            pairs = self.process_apk(apk_path)
            all_pairs.extend(pairs)
        
        return all_pairs
    
    def save_training_data(self, pairs: List[PromptCompletionPair], output_path: str):
        """
        Save prompt/completion pairs to file.
        
        Args:
            pairs: List of PromptCompletionPair objects
            output_path: Output file path
        """
        self.logger.info(f"Saving {len(pairs)} training pairs to {output_path}")
        
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        if self.output_format == 'jsonl':
            with open(output_path, 'w', encoding='utf-8') as f:
                for pair in pairs:
                    json.dump(asdict(pair), f, ensure_ascii=False)
                    f.write('\n')
        else:  # json format
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump([asdict(pair) for pair in pairs], f, 
                         indent=2, ensure_ascii=False)
        
        self.logger.info(f"Training data saved to {output_path}")
    
    def generate_summary_report(self, pairs: List[PromptCompletionPair], 
                              output_path: str = None) -> Dict:
        """
        Generate a summary report of the training data generation.
        
        Args:
            pairs: List of PromptCompletionPair objects
            output_path: Optional path to save report
            
        Returns:
            Summary statistics dictionary
        """
        summary = {
            'total_pairs': len(pairs),
            'java_pairs': len([p for p in pairs if p.metadata.get('file_type') == 'java']),
            'so_pairs': len([p for p in pairs if p.metadata.get('file_type') == 'so']),
            'template_distribution': {},
            'label_distribution': {},
            'confidence_distribution': {
                'high': 0, 'medium': 0, 'low': 0
            },
            'generated_at': datetime.now().isoformat()
        }
        
        # Analyze template usage
        for pair in pairs:
            template = pair.metadata.get('template_name', 'unknown')
            summary['template_distribution'][template] = summary['template_distribution'].get(template, 0) + 1
        
        # Analyze label distribution
        for pair in pairs:
            labels = pair.metadata.get('labels', [])
            for label in labels:
                summary['label_distribution'][label] = summary['label_distribution'].get(label, 0) + 1
        
        # Analyze confidence distribution
        for pair in pairs:
            confidence = pair.metadata.get('confidence', 0)
            if confidence > 0.7:
                summary['confidence_distribution']['high'] += 1
            elif confidence > 0.4:
                summary['confidence_distribution']['medium'] += 1
            else:
                summary['confidence_distribution']['low'] += 1
        
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(summary, f, indent=2, ensure_ascii=False)
            self.logger.info(f"Summary report saved to {output_path}")
        
        return summary


def setup_logging(verbose: bool):
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def main():
    """Main entry point for the pipeline."""
    parser = argparse.ArgumentParser(
        description='APK LLM Annotation Pipeline for generating training data',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process single APK
  python scripts/apk_llm_annotation_pipeline.py --input-apk app.apk --output training_data.jsonl
  
  # Process directory of APKs
  python scripts/apk_llm_annotation_pipeline.py --input-dir apks/ --output-dir corpus/
  
  # Process APKs from list file
  python scripts/apk_llm_annotation_pipeline.py --apk-list apks.txt --output training_corpus.jsonl
  
  # Generate summary report
  python scripts/apk_llm_annotation_pipeline.py --input-apk app.apk --output data.jsonl --report
        """
    )
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('--input-apk', help='Single APK file to process')
    input_group.add_argument('--input-dir', help='Directory containing APK files')
    input_group.add_argument('--apk-list', help='File containing list of APK paths')
    
    # Output options
    parser.add_argument('--output', help='Output file path for training data')
    parser.add_argument('--output-dir', help='Output directory (used with --input-dir)')
    parser.add_argument('--output-format', choices=['jsonl', 'json'], default='jsonl',
                       help='Output format (default: jsonl)')
    
    # Processing options
    parser.add_argument('--max-java-files', type=int, default=50,
                       help='Maximum Java files to process per APK (default: 50)')
    parser.add_argument('--max-so-files', type=int, default=10,
                       help='Maximum SO files to process per APK (default: 10)')
    parser.add_argument('--max-pairs-per-file', type=int, default=3,
                       help='Maximum prompt/completion pairs per file (default: 3)')
    
    # Additional options
    parser.add_argument('--report', action='store_true',
                       help='Generate summary report')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)
    
    # Initialize pipeline
    pipeline = APKLLMAnnotationPipeline(
        output_format=args.output_format,
        verbose=args.verbose
    )
    
    # Configure processing limits
    pipeline.max_java_files = args.max_java_files
    pipeline.max_so_files = args.max_so_files
    pipeline.max_pairs_per_file = args.max_pairs_per_file
    
    # Determine APK files to process
    apk_files = []
    
    if args.input_apk:
        if not os.path.exists(args.input_apk):
            logger.error(f"APK file not found: {args.input_apk}")
            return 1
        apk_files = [args.input_apk]
        
    elif args.input_dir:
        if not os.path.exists(args.input_dir):
            logger.error(f"Input directory not found: {args.input_dir}")
            return 1
        apk_files = [str(p) for p in Path(args.input_dir).glob('*.apk')]
        if not apk_files:
            logger.error(f"No APK files found in {args.input_dir}")
            return 1
            
    elif args.apk_list:
        if not os.path.exists(args.apk_list):
            logger.error(f"APK list file not found: {args.apk_list}")
            return 1
        with open(args.apk_list, 'r') as f:
            apk_files = [line.strip() for line in f if line.strip()]
        # Validate APK files exist
        missing_files = [f for f in apk_files if not os.path.exists(f)]
        if missing_files:
            logger.warning(f"Missing APK files: {missing_files}")
            apk_files = [f for f in apk_files if os.path.exists(f)]
    
    if not apk_files:
        logger.error("No valid APK files to process")
        return 1
    
    logger.info(f"Found {len(apk_files)} APK files to process")
    
    # Process APKs
    try:
        training_pairs = pipeline.process_multiple_apks(apk_files)
        
        if not training_pairs:
            logger.warning("No training data generated")
            return 1
        
        # Determine output path
        if args.output:
            output_path = args.output
        elif args.output_dir:
            os.makedirs(args.output_dir, exist_ok=True)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"apk_training_data_{timestamp}.{args.output_format}"
            output_path = os.path.join(args.output_dir, filename)
        else:
            # Default output file
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = f"apk_training_data_{timestamp}.{args.output_format}"
        
        # Save training data
        pipeline.save_training_data(training_pairs, output_path)
        
        # Generate summary report if requested
        if args.report:
            report_path = output_path.rsplit('.', 1)[0] + '_report.json'
            summary = pipeline.generate_summary_report(training_pairs, report_path)
            
            # Print summary to console
            print("\n" + "="*50)
            print("TRAINING DATA GENERATION SUMMARY")
            print("="*50)
            print(f"Total prompt/completion pairs: {summary['total_pairs']}")
            print(f"Java code pairs: {summary['java_pairs']}")
            print(f"Native code pairs: {summary['so_pairs']}")
            print(f"Output file: {output_path}")
            if args.report:
                print(f"Report file: {report_path}")
            print("="*50)
        
        logger.info("Pipeline completed successfully")
        return 0
        
    except KeyboardInterrupt:
        logger.info("Pipeline interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Pipeline failed: {e}", exc_info=True)
        return 1


if __name__ == '__main__':
    sys.exit(main())