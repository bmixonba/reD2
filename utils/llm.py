"""
LLM utilities for MobileGPT.
Handles model selection, loading, and code analysis using various LLM backends.
"""

import os
import logging
from typing import Dict, List, Optional, Union
from enum import Enum

try:
    from transformers import pipeline, AutoTokenizer, AutoModelForCausalLM
    import torch
except ImportError as e:
    logging.warning(f"Import error: {e}. Please install dependencies: pip install -r requirements.txt")


class ModelType(Enum):
    """Supported LLM model types."""
    CODELLAMA = "codellama"
    GPT4 = "gpt4"
    OPENSOURCE = "opensource"


class LLMAnalyzer:
    """Handle LLM-based code analysis with multiple model backends."""
    
    def __init__(self, model_type: ModelType = ModelType.OPENSOURCE, model_name: Optional[str] = None):
        """
        Initialize LLM analyzer with specified model.
        
        Args:
            model_type: Type of model to use (CodeLlama, GPT-4, or open-source)
            model_name: Specific model name/path. If None, uses default for model_type
        """
        self.model_type = model_type
        self.model_name = model_name or self._get_default_model_name(model_type)
        self.logger = logging.getLogger(__name__)
        
        # Initialize model based on type
        self.model = None
        self.tokenizer = None
        self.pipeline = None
        self._load_model()
    
    def _get_default_model_name(self, model_type: ModelType) -> str:
        """Get default model name for given model type."""
        defaults = {
            ModelType.CODELLAMA: "codellama/CodeLlama-7b-Instruct-hf",
            ModelType.GPT4: "gpt-4",  # Placeholder - requires OpenAI API
            ModelType.OPENSOURCE: "microsoft/DialoGPT-medium"  # Fallback lightweight model
        }
        return defaults.get(model_type, defaults[ModelType.OPENSOURCE])
    
    def _load_model(self):
        """Load the specified model based on model_type."""
        try:
            if self.model_type == ModelType.GPT4:
                # GPT-4 requires OpenAI API - scaffold for future implementation
                self.logger.info("GPT-4 model selected - API integration not implemented yet")
                self._init_gpt4_placeholder()
            
            elif self.model_type == ModelType.CODELLAMA:
                # CodeLlama model loading
                self.logger.info(f"Loading CodeLlama model: {self.model_name}")
                self._load_codellama_model()
            
            elif self.model_type == ModelType.OPENSOURCE:
                # Open-source model loading
                self.logger.info(f"Loading open-source model: {self.model_name}")
                self._load_opensource_model()
            
        except Exception as e:
            self.logger.error(f"Error loading model: {e}")
            self.logger.info("Falling back to placeholder implementation")
            self._init_placeholder_model()
    
    def _init_gpt4_placeholder(self):
        """Initialize GPT-4 placeholder - to be implemented with OpenAI API."""
        # TODO: Implement OpenAI API integration
        # This would require:
        # 1. OpenAI API key configuration
        # 2. openai library import
        # 3. API call implementation
        self.logger.warning("GPT-4 API integration not implemented yet")
    
    def _load_codellama_model(self):
        """Load CodeLlama model using transformers."""
        try:
            # Check if CUDA is available for GPU acceleration
            device = 0 if torch.cuda.is_available() else -1
            
            # Load CodeLlama pipeline for code generation/analysis
            self.pipeline = pipeline(
                "text-generation",
                model=self.model_name,
                device=device,
                torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
                trust_remote_code=True
            )
            
            self.logger.info(f"Successfully loaded CodeLlama model: {self.model_name}")
            
        except Exception as e:
            self.logger.error(f"Failed to load CodeLlama model: {e}")
            self._init_placeholder_model()
    
    def _load_opensource_model(self):
        """Load open-source model using transformers."""
        try:
            # For open-source models, use a simpler approach
            device = 0 if torch.cuda.is_available() else -1
            
            self.pipeline = pipeline(
                "text-generation",
                model=self.model_name,
                device=device,
                trust_remote_code=True
            )
            
            self.logger.info(f"Successfully loaded open-source model: {self.model_name}")
            
        except Exception as e:
            self.logger.error(f"Failed to load open-source model: {e}")
            self._init_placeholder_model()
    
    def _init_placeholder_model(self):
        """Initialize placeholder model for development/testing."""
        self.logger.info("Initializing placeholder model for development")
        # This allows the system to work without actual model loading during development
    
    def analyze_code_file(self, file_path: str, file_content: str) -> Dict:
        """
        Analyze a single code file using the loaded LLM.
        
        Args:
            file_path: Path to the code file
            file_content: Content of the code file
            
        Returns:
            Dictionary containing analysis results
        """
        try:
            if self.model_type == ModelType.GPT4:
                return self._analyze_with_gpt4(file_path, file_content)
            elif self.model_type == ModelType.CODELLAMA:
                return self._analyze_with_codellama(file_path, file_content)
            else:
                return self._analyze_with_opensource(file_path, file_content)
                
        except Exception as e:
            self.logger.error(f"Error analyzing file {file_path}: {e}")
            return self._get_fallback_analysis(file_path, file_content)
    
    def _analyze_with_gpt4(self, file_path: str, file_content: str) -> Dict:
        """Analyze code using GPT-4 API."""
        # TODO: Implement GPT-4 analysis
        # This would involve:
        # 1. Constructing appropriate prompts
        # 2. Making API calls to OpenAI
        # 3. Parsing and structuring responses
        
        self.logger.info(f"GPT-4 analysis requested for {file_path} - not implemented yet")
        return self._get_placeholder_analysis(file_path, file_content, "GPT-4")
    
    def _analyze_with_codellama(self, file_path: str, file_content: str) -> Dict:
        """Analyze code using CodeLlama model."""
        if not self.pipeline:
            return self._get_fallback_analysis(file_path, file_content)
        
        try:
            # Construct prompt for code analysis
            prompt = f"""Analyze this Android Java code and provide insights:

File: {file_path}

Code:
{file_content[:2000]}  # Limit content for model context

Please identify:
1. Security vulnerabilities
2. Interesting functionality
3. Potential Frida hook points
4. Code patterns and structures

Analysis:"""

            # Generate analysis using CodeLlama
            response = self.pipeline(
                prompt,
                max_new_tokens=512,
                temperature=0.1,
                do_sample=True,
                pad_token_id=self.pipeline.tokenizer.eos_token_id
            )
            
            analysis_text = response[0]['generated_text'][len(prompt):].strip()
            
            return {
                'file_path': file_path,
                'model_used': f"CodeLlama ({self.model_name})",
                'analysis': analysis_text,
                'security_issues': self._extract_security_issues(analysis_text),
                'hook_suggestions': self._extract_hook_suggestions(analysis_text),
                'code_patterns': self._extract_code_patterns(analysis_text)
            }
            
        except Exception as e:
            self.logger.error(f"CodeLlama analysis failed: {e}")
            return self._get_fallback_analysis(file_path, file_content)
    
    def _analyze_with_opensource(self, file_path: str, file_content: str) -> Dict:
        """Analyze code using open-source model."""
        if not self.pipeline:
            return self._get_fallback_analysis(file_path, file_content)
        
        try:
            # Simplified analysis for open-source models
            prompt = f"Analyze this code for security and functionality:\n{file_content[:1000]}"
            
            response = self.pipeline(
                prompt,
                max_length=200,
                temperature=0.2,
                do_sample=True
            )
            
            analysis_text = response[0]['generated_text'][len(prompt):].strip()
            
            return {
                'file_path': file_path,
                'model_used': f"Open-source ({self.model_name})",
                'analysis': analysis_text,
                'security_issues': [],
                'hook_suggestions': [],
                'code_patterns': []
            }
            
        except Exception as e:
            self.logger.error(f"Open-source model analysis failed: {e}")
            return self._get_fallback_analysis(file_path, file_content)
    
    def _extract_security_issues(self, analysis_text: str) -> List[str]:
        """Extract security issues from analysis text."""
        # Simple keyword-based extraction - can be improved with more sophisticated parsing
        security_keywords = ['vulnerability', 'security', 'exploit', 'unsafe', 'risk']
        issues = []
        
        for line in analysis_text.split('\n'):
            if any(keyword in line.lower() for keyword in security_keywords):
                issues.append(line.strip())
        
        return issues
    
    def _extract_hook_suggestions(self, analysis_text: str) -> List[str]:
        """Extract Frida hook suggestions from analysis text."""
        # Simple extraction - can be improved
        hook_keywords = ['hook', 'frida', 'intercept', 'method', 'function']
        suggestions = []
        
        for line in analysis_text.split('\n'):
            if any(keyword in line.lower() for keyword in hook_keywords):
                suggestions.append(line.strip())
        
        return suggestions
    
    def _extract_code_patterns(self, analysis_text: str) -> List[str]:
        """Extract code patterns from analysis text."""
        # Simple extraction - can be improved
        pattern_keywords = ['pattern', 'structure', 'design', 'architecture']
        patterns = []
        
        for line in analysis_text.split('\n'):
            if any(keyword in line.lower() for keyword in pattern_keywords):
                patterns.append(line.strip())
        
        return patterns
    
    def _get_fallback_analysis(self, file_path: str, file_content: str) -> Dict:
        """Provide fallback analysis when models fail."""
        return {
            'file_path': file_path,
            'model_used': 'Fallback (rule-based)',
            'analysis': 'Model-based analysis unavailable. Performing basic static analysis.',
            'security_issues': self._basic_security_scan(file_content),
            'hook_suggestions': self._basic_hook_suggestions(file_content),
            'code_patterns': self._basic_pattern_detection(file_content)
        }
    
    def _get_placeholder_analysis(self, file_path: str, file_content: str, model_name: str) -> Dict:
        """Provide placeholder analysis for development."""
        return {
            'file_path': file_path,
            'model_used': f'{model_name} (placeholder)',
            'analysis': f'Placeholder analysis for {file_path} using {model_name}',
            'security_issues': ['Placeholder security issue'],
            'hook_suggestions': ['Placeholder hook suggestion'],
            'code_patterns': ['Placeholder code pattern']
        }
    
    def _basic_security_scan(self, file_content: str) -> List[str]:
        """Basic security scanning without LLM."""
        issues = []
        security_patterns = [
            ('hardcoded password', 'password'),
            ('hardcoded API key', 'api_key'),
            ('weak encryption', 'md5'),
            ('insecure connection', 'http://'),
            ('SQL injection risk', 'SELECT.*FROM'),
        ]
        
        for issue_type, pattern in security_patterns:
            if pattern.lower() in file_content.lower():
                issues.append(f"Potential {issue_type} detected")
        
        return issues
    
    def _basic_hook_suggestions(self, file_content: str) -> List[str]:
        """Basic hook suggestions without LLM."""
        suggestions = []
        
        # Look for common method patterns
        if 'onCreate' in file_content:
            suggestions.append("Hook onCreate method for activity analysis")
        if 'onResume' in file_content:
            suggestions.append("Hook onResume method for lifecycle tracking")
        if 'encrypt' in file_content.lower():
            suggestions.append("Hook encryption methods for crypto analysis")
        if 'network' in file_content.lower():
            suggestions.append("Hook network methods for traffic analysis")
        
        return suggestions
    
    def _basic_pattern_detection(self, file_content: str) -> List[str]:
        """Basic code pattern detection without LLM."""
        patterns = []
        
        if 'extends Activity' in file_content:
            patterns.append("Android Activity pattern")
        if 'extends Service' in file_content:
            patterns.append("Android Service pattern")
        if 'implements' in file_content:
            patterns.append("Interface implementation pattern")
        if 'Singleton' in file_content:
            patterns.append("Singleton design pattern")
        
        return patterns
    
    def analyze_multiple_files(self, file_analyses: List[Dict]) -> Dict:
        """
        Analyze multiple files and provide summary insights.
        
        Args:
            file_analyses: List of individual file analysis results
            
        Returns:
            Dictionary containing summary analysis
        """
        if not file_analyses:
            return {'summary': 'No files analyzed', 'recommendations': []}
        
        # Aggregate findings
        all_security_issues = []
        all_hook_suggestions = []
        all_patterns = []
        
        for analysis in file_analyses:
            all_security_issues.extend(analysis.get('security_issues', []))
            all_hook_suggestions.extend(analysis.get('hook_suggestions', []))
            all_patterns.extend(analysis.get('code_patterns', []))
        
        # Remove duplicates while preserving order
        unique_security = list(dict.fromkeys(all_security_issues))
        unique_hooks = list(dict.fromkeys(all_hook_suggestions))
        unique_patterns = list(dict.fromkeys(all_patterns))
        
        return {
            'files_analyzed': len(file_analyses),
            'model_used': file_analyses[0].get('model_used', 'Unknown'),
            'summary': f"Analyzed {len(file_analyses)} files using {self.model_type.value}",
            'security_issues': unique_security,
            'hook_suggestions': unique_hooks,
            'code_patterns': unique_patterns,
            'recommendations': self._generate_recommendations(unique_security, unique_hooks, unique_patterns)
        }
    
    def _generate_recommendations(self, security_issues: List[str], 
                                hook_suggestions: List[str], 
                                patterns: List[str]) -> List[str]:
        """Generate overall recommendations based on analysis."""
        recommendations = []
        
        if security_issues:
            recommendations.append(f"Review {len(security_issues)} potential security issues")
        
        if hook_suggestions:
            recommendations.append(f"Consider implementing {len(hook_suggestions)} Frida hooks")
        
        if patterns:
            recommendations.append(f"Analyze {len(patterns)} identified code patterns")
        
        # Add general recommendations
        recommendations.extend([
            "Perform dynamic analysis with Frida",
            "Test security controls with custom hooks",
            "Monitor network traffic and API calls",
            "Validate input sanitization and encryption"
        ])
        
        return recommendations


def get_model_analyzer(model_type: str = "opensource", model_name: Optional[str] = None) -> LLMAnalyzer:
    """
    Factory function to create LLM analyzer with specified model.
    
    Args:
        model_type: Type of model ("codellama", "gpt4", or "opensource")
        model_name: Optional specific model name
        
    Returns:
        Configured LLMAnalyzer instance
    """
    model_type_enum = ModelType(model_type.lower())
    return LLMAnalyzer(model_type_enum, model_name)