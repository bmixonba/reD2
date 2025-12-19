"""
DEX Code Explainer Utility

This module provides functionality to explain decompiled DEX code from APKs,
helping security researchers understand obfuscated or complex Android code.
"""

import re
import logging
from typing import Dict, List, Optional, Tuple
from enum import Enum


class CodeObfuscationType(Enum):
    """Types of code obfuscation detected."""
    STRING_ARRAY_OBFUSCATION = "string_array_obfuscation"
    CONTROL_FLOW_OBFUSCATION = "control_flow_obfuscation"
    REFLECTION = "reflection"
    NATIVE_METHODS = "native_methods"
    ENCRYPTION = "encryption"
    NONE = "none"


class DexCodeExplainer:
    """
    Analyzer for decompiled DEX code that provides human-readable explanations.
    """
    
    def __init__(self):
        """Initialize the DEX code explainer."""
        self.logger = logging.getLogger(__name__)
    
    def explain_code(self, code: str, package_name: Optional[str] = None) -> Dict:
        """
        Generate a comprehensive explanation of decompiled DEX code.
        
        Args:
            code: The decompiled Java/DEX code to explain
            package_name: Optional package name for context
            
        Returns:
            Dictionary containing:
                - summary: High-level summary of what the code does
                - purpose: Detailed purpose description
                - obfuscation_techniques: List of detected obfuscation methods
                - security_concerns: Potential security issues
                - key_components: Important classes, methods, and fields
                - data_structures: Important data structures used
                - recommendations: Suggestions for further analysis
        """
        self.logger.info(f"Analyzing code from package: {package_name or 'unknown'}")
        
        # Parse the code structure
        classes = self._extract_classes(code)
        methods = self._extract_methods(code)
        fields = self._extract_fields(code)
        
        # Detect obfuscation techniques
        obfuscation = self._detect_obfuscation(code)
        
        # Analyze the code purpose
        purpose = self._infer_purpose(code, classes, package_name)
        
        # Identify security concerns
        security_concerns = self._analyze_security(code)
        
        # Generate summary
        summary = self._generate_summary(classes, purpose, obfuscation)
        
        # Extract key components
        key_components = self._identify_key_components(classes, methods, fields)
        
        # Analyze data structures
        data_structures = self._analyze_data_structures(code, classes)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(obfuscation, security_concerns)
        
        return {
            'summary': summary,
            'purpose': purpose,
            'obfuscation_techniques': obfuscation,
            'security_concerns': security_concerns,
            'key_components': key_components,
            'data_structures': data_structures,
            'recommendations': recommendations,
            'package_name': package_name,
            'code_snippet_length': len(code)
        }
    
    def _extract_classes(self, code: str) -> List[Dict]:
        """Extract class definitions from code."""
        classes = []
        
        # Pattern to match class declarations
        class_pattern = r'(?:public\s+)?(?:final\s+)?class\s+(\w+)(?:\s+extends\s+(\w+))?(?:\s+implements\s+([\w\s,]+))?'
        
        for match in re.finditer(class_pattern, code):
            class_name = match.group(1)
            extends = match.group(2)
            implements = match.group(3)
            
            classes.append({
                'name': class_name,
                'extends': extends,
                'implements': implements.split(',') if implements else []
            })
        
        return classes
    
    def _extract_methods(self, code: str) -> List[Dict]:
        """Extract method definitions from code."""
        methods = []
        
        # Pattern to match method declarations
        method_pattern = r'(?:public|private|protected)?\s*(?:static\s+)?(?:final\s+)?(?:\w+\s+)?(\w+)\s*\([^)]*\)'
        
        for match in re.finditer(method_pattern, code):
            method_name = match.group(1)
            if method_name and not method_name in ['class', 'import', 'package']:
                methods.append({
                    'name': method_name,
                    'signature': match.group(0)
                })
        
        return methods
    
    def _extract_fields(self, code: str) -> List[Dict]:
        """Extract field definitions from code."""
        fields = []
        
        # Pattern to match field declarations
        field_pattern = r'(?:public|private|protected)?\s+(?:static\s+)?(?:final\s+)?(\w+(?:\[\])?)\s+(\w+)\s*[;=]'
        
        for match in re.finditer(field_pattern, code):
            field_type = match.group(1)
            field_name = match.group(2)
            
            fields.append({
                'type': field_type,
                'name': field_name
            })
        
        return fields
    
    def _detect_obfuscation(self, code: str) -> List[Dict]:
        """Detect obfuscation techniques used in the code."""
        techniques = []
        
        # Check for string array obfuscation
        if re.search(r'static\s+String\[\]\s+\w+\s*=\s*\{.*?"[^"]{20,}"', code, re.DOTALL):
            techniques.append({
                'type': CodeObfuscationType.STRING_ARRAY_OBFUSCATION.value,
                'description': 'Static string arrays with long random-looking strings detected. '
                             'These are often used to hide string constants from static analysis.',
                'severity': 'medium'
            })
        
        # Check for control flow obfuscation
        if re.search(r'if\s*\([^)]+\.charAt\(\d+\)\s*[!=]=\s*[^)]+\.charAt\(\d+\)\)', code):
            techniques.append({
                'type': CodeObfuscationType.CONTROL_FLOW_OBFUSCATION.value,
                'description': 'Control flow obfuscation detected with character comparisons. '
                             'This makes the code harder to understand and analyze.',
                'severity': 'high'
            })
        
        # Check for reflection usage
        if 'Class.forName' in code or 'getDeclaredMethod' in code or 'getMethod' in code:
            techniques.append({
                'type': CodeObfuscationType.REFLECTION.value,
                'description': 'Java reflection is used, which can hide method calls and class usage '
                             'from static analysis.',
                'severity': 'medium'
            })
        
        # Check for native methods
        if 'native ' in code:
            techniques.append({
                'type': CodeObfuscationType.NATIVE_METHODS.value,
                'description': 'Native methods detected. Implementation details are in compiled libraries '
                             'and not visible in DEX code.',
                'severity': 'high'
            })
        
        # Check for encryption/crypto usage
        if any(keyword in code for keyword in ['Cipher', 'encrypt', 'decrypt', 'MessageDigest', 'SecretKey']):
            techniques.append({
                'type': CodeObfuscationType.ENCRYPTION.value,
                'description': 'Cryptographic operations detected. Data may be encrypted or hashed.',
                'severity': 'low'
            })
        
        if not techniques:
            techniques.append({
                'type': CodeObfuscationType.NONE.value,
                'description': 'No obvious obfuscation detected.',
                'severity': 'low'
            })
        
        return techniques
    
    def _infer_purpose(self, code: str, classes: List[Dict], package_name: Optional[str]) -> str:
        """Infer the purpose of the code based on various indicators."""
        purpose_indicators = []
        
        # Check package name
        if package_name:
            if 'drm' in package_name.lower():
                purpose_indicators.append('Digital Rights Management (DRM)')
            if 'ads' in package_name.lower():
                purpose_indicators.append('Advertisement SDK')
            if 'facebook' in package_name.lower():
                purpose_indicators.append('Facebook SDK component')
            if 'exoplayer' in package_name.lower():
                purpose_indicators.append('ExoPlayer media framework')
        
        # Check class names and patterns
        for cls in classes:
            name = cls['name'].lower()
            if 'drm' in name:
                purpose_indicators.append('DRM implementation')
            if 'scheme' in name or 'license' in name:
                purpose_indicators.append('Licensing/scheme management')
            if 'parcel' in name or cls.get('implements') and any('Parcelable' in i for i in cls.get('implements', [])):
                purpose_indicators.append('Android IPC data serialization')
        
        # Check for specific patterns
        if 'UUID' in code and 'SchemeData' in code:
            purpose_indicators.append('DRM scheme data management')
        
        if 'Parcelable' in code:
            purpose_indicators.append('Android Parcelable implementation for passing data between processes')
        
        # Generate purpose description
        if purpose_indicators:
            unique_indicators = list(set(purpose_indicators))
            return f"This code appears to be for: {', '.join(unique_indicators)}"
        
        return "This code's specific purpose could not be automatically determined. Manual analysis recommended."
    
    def _analyze_security(self, code: str) -> List[Dict]:
        """Identify potential security concerns in the code."""
        concerns = []
        
        # Check for UUID usage (often used in DRM)
        if 'UUID' in code:
            concerns.append({
                'category': 'DRM/Licensing',
                'description': 'UUID usage detected, commonly used in DRM schemes to identify content protection systems',
                'severity': 'info',
                'recommendation': 'Review UUID usage to understand content protection implementation'
            })
        
        # Check for byte array manipulation
        if 'byte[]' in code and ('writeByteArray' in code or 'createByteArray' in code):
            concerns.append({
                'category': 'Data Handling',
                'description': 'Binary data (byte arrays) being processed. May contain licenses, keys, or encrypted content',
                'severity': 'medium',
                'recommendation': 'Inspect byte array contents during runtime to understand what data is being processed'
            })
        
        # Check for obfuscated string access
        if re.search(r'\w+\[\d+\]\.(?:length|charAt)\(\)', code):
            concerns.append({
                'category': 'Anti-Analysis',
                'description': 'String obfuscation patterns detected. Strings are hidden to prevent static analysis',
                'severity': 'medium',
                'recommendation': 'Use dynamic analysis or string deobfuscation tools to recover hidden strings'
            })
        
        # Check for comparison logic used in obfuscation
        if re.search(r'throw\s+new\s+RuntimeException\(\)', code):
            concerns.append({
                'category': 'Anti-Tampering',
                'description': 'RuntimeException throwing detected, possibly part of anti-tampering checks',
                'severity': 'low',
                'recommendation': 'These exceptions may be triggered if string arrays are modified or tampered with'
            })
        
        return concerns
    
    def _generate_summary(self, classes: List[Dict], purpose: str, obfuscation: List[Dict]) -> str:
        """Generate a high-level summary of the code."""
        num_classes = len(classes)
        class_names = [cls['name'] for cls in classes[:3]]
        
        obf_count = len([o for o in obfuscation if o['type'] != CodeObfuscationType.NONE.value])
        
        summary = f"This code contains {num_classes} class(es)"
        if class_names:
            summary += f" including {', '.join(class_names)}"
        summary += ". "
        
        summary += purpose + " "
        
        if obf_count > 0:
            summary += f"The code employs {obf_count} obfuscation technique(s) to protect against analysis."
        else:
            summary += "No significant obfuscation was detected."
        
        return summary
    
    def _identify_key_components(self, classes: List[Dict], methods: List[Dict], fields: List[Dict]) -> Dict:
        """Identify the most important components in the code."""
        return {
            'classes': [cls['name'] for cls in classes],
            'important_methods': [m['name'] for m in methods if m['name'] in [
                'equals', 'hashCode', 'writeToParcel', 'describeContents', 
                'compare', 'compareTo', 'initialize', '__init__'
            ]],
            'notable_fields': [f['name'] for f in fields if f['name'].startswith('A') or 
                             f['name'] in ['CREATOR', 'uuid', 'data', 'key']]
        }
    
    def _analyze_data_structures(self, code: str, classes: List[Dict]) -> List[Dict]:
        """Analyze important data structures in the code."""
        structures = []
        
        # Check for Parcelable implementation
        if 'Parcelable' in code:
            structures.append({
                'type': 'Parcelable',
                'description': 'Android Parcelable interface implementation for efficient IPC serialization',
                'purpose': 'Allows objects to be passed between Android components (Activities, Services, etc.)'
            })
        
        # Check for Comparator implementation
        if 'Comparator' in code or 'compare(' in code:
            structures.append({
                'type': 'Comparator',
                'description': 'Java Comparator implementation for custom object sorting',
                'purpose': 'Enables sorting of objects based on custom logic'
            })
        
        # Check for array usage
        if '[]' in code:
            structures.append({
                'type': 'Arrays',
                'description': 'Array data structures used for storing collections of data',
                'purpose': 'Efficient storage and access of multiple related values'
            })
        
        return structures
    
    def _generate_recommendations(self, obfuscation: List[Dict], security_concerns: List[Dict]) -> List[str]:
        """Generate recommendations for further analysis."""
        recommendations = []
        
        # Recommendations based on obfuscation
        if any(o['type'] == CodeObfuscationType.STRING_ARRAY_OBFUSCATION.value for o in obfuscation):
            recommendations.append(
                "Use a string deobfuscation tool or dynamic analysis to recover hidden string constants"
            )
        
        if any(o['type'] == CodeObfuscationType.CONTROL_FLOW_OBFUSCATION.value for o in obfuscation):
            recommendations.append(
                "Consider using a deobfuscator tool to simplify control flow before analysis"
            )
        
        if any(o['type'] == CodeObfuscationType.NATIVE_METHODS.value for o in obfuscation):
            recommendations.append(
                "Analyze native libraries (.so files) to understand implementation of native methods"
            )
        
        # Recommendations based on security concerns
        if any('DRM' in c.get('category', '') for c in security_concerns):
            recommendations.append(
                "Use Frida or Xposed to hook DRM-related methods and observe license validation at runtime"
            )
        
        if any('Data Handling' in c.get('category', '') for c in security_concerns):
            recommendations.append(
                "Monitor byte array contents during runtime to understand what data is being processed"
            )
        
        # General recommendations
        recommendations.append(
            "Consider using tools like jadx, dex2jar, or Ghidra for deeper static analysis"
        )
        
        recommendations.append(
            "Use dynamic analysis with Frida to observe actual runtime behavior"
        )
        
        return recommendations
    
    def format_explanation(self, explanation: Dict, include_technical_details: bool = True) -> str:
        """
        Format the explanation as a readable string.
        
        Args:
            explanation: The explanation dictionary from explain_code()
            include_technical_details: Whether to include technical details
            
        Returns:
            Formatted string explanation
        """
        output = []
        
        output.append("=" * 80)
        output.append("DEX CODE EXPLANATION")
        output.append("=" * 80)
        output.append("")
        
        if explanation.get('package_name'):
            output.append(f"Package: {explanation['package_name']}")
            output.append("")
        
        output.append("SUMMARY")
        output.append("-" * 80)
        output.append(explanation['summary'])
        output.append("")
        
        output.append("PURPOSE")
        output.append("-" * 80)
        output.append(explanation['purpose'])
        output.append("")
        
        if explanation['obfuscation_techniques']:
            output.append("OBFUSCATION TECHNIQUES")
            output.append("-" * 80)
            for technique in explanation['obfuscation_techniques']:
                output.append(f"• {technique['type'].upper()} (Severity: {technique['severity']})")
                output.append(f"  {technique['description']}")
                output.append("")
        
        if explanation['security_concerns']:
            output.append("SECURITY CONCERNS")
            output.append("-" * 80)
            for concern in explanation['security_concerns']:
                output.append(f"• {concern['category']} (Severity: {concern['severity']})")
                output.append(f"  {concern['description']}")
                output.append(f"  Recommendation: {concern['recommendation']}")
                output.append("")
        
        if include_technical_details:
            output.append("KEY COMPONENTS")
            output.append("-" * 80)
            components = explanation['key_components']
            if components['classes']:
                output.append(f"Classes: {', '.join(components['classes'])}")
            if components['important_methods']:
                output.append(f"Important Methods: {', '.join(components['important_methods'])}")
            if components['notable_fields']:
                output.append(f"Notable Fields: {', '.join(components['notable_fields'])}")
            output.append("")
            
            if explanation['data_structures']:
                output.append("DATA STRUCTURES")
                output.append("-" * 80)
                for structure in explanation['data_structures']:
                    output.append(f"• {structure['type']}")
                    output.append(f"  {structure['description']}")
                    output.append(f"  Purpose: {structure['purpose']}")
                    output.append("")
        
        output.append("RECOMMENDATIONS FOR FURTHER ANALYSIS")
        output.append("-" * 80)
        for i, recommendation in enumerate(explanation['recommendations'], 1):
            output.append(f"{i}. {recommendation}")
        output.append("")
        
        output.append("=" * 80)
        
        return "\n".join(output)


def explain_dex_code_snippet(code: str, package_name: Optional[str] = None) -> str:
    """
    Convenience function to explain a DEX code snippet.
    
    Args:
        code: The decompiled Java/DEX code
        package_name: Optional package name for context
        
    Returns:
        Formatted explanation string
    """
    explainer = DexCodeExplainer()
    explanation = explainer.explain_code(code, package_name)
    return explainer.format_explanation(explanation)
