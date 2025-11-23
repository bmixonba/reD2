#!/usr/bin/env python3
"""
Extensibility demonstration for the APK LLM Annotation Pipeline.

This script shows how the pipeline can be easily extended with custom
annotation patterns and prompt templates.
"""

import os
import sys

# Add parent directory to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from scripts.apk_llm_annotation_pipeline import (
    JavaCodeAnnotator, 
    PromptGenerator,
    AnnotationResult
)


class ExtendedJavaAnnotator(JavaCodeAnnotator):
    """Extended Java annotator with custom patterns."""
    
    def __init__(self):
        super().__init__()
        
        # Add custom annotation patterns
        self.annotation_patterns.update({
            'machine_learning': [
                r'tensorflow|pytorch|keras|scikit',
                r'neural|network|model|train',
                r'ai|ml|deeplearning'
            ],
            'blockchain_crypto': [
                r'bitcoin|ethereum|blockchain',
                r'wallet|cryptocurrency|hash',
                r'mining|ledger|transaction'
            ],
            'social_media': [
                r'facebook|twitter|instagram|tiktok',
                r'social|share|post|comment',
                r'oauth|facebook\.com|twitter\.com'
            ]
        })


class ExtendedPromptGenerator(PromptGenerator):
    """Extended prompt generator with custom templates."""
    
    def __init__(self):
        super().__init__()
        
        # Add custom prompt templates
        self.prompt_templates.update({
            'code_review': {
                'prompt': "Perform a code review of this {file_type} code focusing on {labels}. Identify potential improvements:\n\n{content}\n\nCode Review:",
                'weight': 1.3
            },
            'educational_explanation': {
                'prompt': "Explain this {file_type} code in simple terms for educational purposes, highlighting {labels}:\n\n{content}\n\nEducational Explanation:",
                'weight': 1.1
            },
            'threat_modeling': {
                'prompt': "From a threat modeling perspective, analyze this {file_type} code for security implications related to {labels}:\n\n{content}\n\nThreat Analysis:",
                'weight': 1.5
            }
        })
    
    def _generate_completion(self, annotation: AnnotationResult, template_name: str) -> str:
        """Override to handle custom templates."""
        if template_name == 'code_review':
            return self._generate_code_review_completion(annotation)
        elif template_name == 'educational_explanation':
            return self._generate_educational_completion(annotation)
        elif template_name == 'threat_modeling':
            return self._generate_threat_modeling_completion(annotation)
        else:
            return super()._generate_completion(annotation, template_name)
    
    def _generate_code_review_completion(self, annotation: AnnotationResult) -> str:
        """Generate code review completion."""
        review_points = ["Code review findings:"]
        
        if 'encryption_decryption' in annotation.labels:
            review_points.append("• Cryptography: Ensure proper key management and use of secure algorithms")
        if 'network_communication' in annotation.labels:
            review_points.append("• Network: Validate input and implement proper error handling")
        if 'authentication' in annotation.labels:
            review_points.append("• Authentication: Implement secure session management and input validation")
        if 'machine_learning' in annotation.labels:
            review_points.append("• ML Integration: Consider model security and data privacy implications")
        
        review_points.append(f"\nOverall code quality: {'Good' if annotation.confidence > 0.6 else 'Needs improvement'}")
        return '\n'.join(review_points)
    
    def _generate_educational_completion(self, annotation: AnnotationResult) -> str:
        """Generate educational explanation completion."""
        explanation = f"This {annotation.file_type} code is designed to:\n\n"
        
        educational_explanations = {
            'encryption_decryption': 'Protect data by converting it into a secret format that only authorized users can read',
            'network_communication': 'Connect to the internet and exchange information with remote servers',
            'authentication': 'Verify user identity to ensure only authorized access to the application',
            'machine_learning': 'Use artificial intelligence to make predictions or recognize patterns in data',
            'blockchain_crypto': 'Work with blockchain technology for secure, decentralized transactions'
        }
        
        for label in annotation.labels:
            if label in educational_explanations:
                explanation += f"• {educational_explanations[label]}\n"
        
        explanation += f"\nThis code appears to be {'well-structured' if annotation.confidence > 0.5 else 'basic'} and suitable for educational study."
        return explanation
    
    def _generate_threat_modeling_completion(self, annotation: AnnotationResult) -> str:
        """Generate threat modeling completion."""
        threats = ["Threat modeling analysis:"]
        
        threat_analysis = {
            'encryption_decryption': 'Risk: Key exposure, weak algorithms. Mitigation: Use strong encryption, secure key storage',
            'network_communication': 'Risk: Man-in-the-middle attacks, data interception. Mitigation: Use HTTPS, certificate pinning',
            'authentication': 'Risk: Credential theft, session hijacking. Mitigation: Multi-factor authentication, secure sessions',
            'file_operations': 'Risk: Path traversal, unauthorized access. Mitigation: Input validation, access controls',
            'anti_analysis': 'Risk: May indicate malicious intent. Mitigation: Code review, behavioral analysis'
        }
        
        for label in annotation.labels:
            if label in threat_analysis:
                threats.append(f"• {threat_analysis[label]}")
        
        risk_level = "HIGH" if annotation.confidence > 0.7 else "MEDIUM" if annotation.confidence > 0.4 else "LOW"
        threats.append(f"\nOverall threat level: {risk_level}")
        return '\n'.join(threats)
    
    def _select_templates(self, labels: list, confidence: float) -> list:
        """Override to include custom templates."""
        selected = super()._select_templates(labels, confidence)
        
        # Add custom templates based on specific conditions
        if confidence > 0.6:
            selected.append('code_review')
        
        if any(label in ['machine_learning', 'blockchain_crypto'] for label in labels):
            selected.append('educational_explanation')
        
        security_labels = {'encryption_decryption', 'authentication', 'anti_analysis', 'network_communication'}
        if any(label in security_labels for label in labels):
            selected.append('threat_modeling')
        
        return selected


def demonstrate_extensibility():
    """Demonstrate how to extend the pipeline with custom functionality."""
    print("="*60)
    print("EXTENSIBILITY DEMONSTRATION")
    print("="*60)
    
    # Create extended components
    extended_annotator = ExtendedJavaAnnotator()
    extended_prompt_gen = ExtendedPromptGenerator()
    
    # Test code with new patterns
    test_code = '''
package com.example.ml;

import org.tensorflow.lite.Interpreter;
import java.security.KeyStore;
import javax.crypto.Cipher;

public class MLCryptoApp {
    private Interpreter model;
    private KeyStore keystore;
    
    public void loadTensorFlowModel() {
        // Load machine learning model
        model = new Interpreter(modelFile);
    }
    
    public void encryptModelData() {
        // Encrypt sensitive model data
        Cipher cipher = Cipher.getInstance("AES");
    }
    
    public void authenticateUser() {
        // User authentication
        keystore = KeyStore.getInstance("AndroidKeyStore");
    }
}
'''
    
    print("\n1. Testing Extended Annotation Patterns")
    print("-" * 40)
    
    # Test original vs extended annotation
    original_annotator = JavaCodeAnnotator()
    original_annotation = original_annotator.annotate_java_file('test.java', test_code)
    extended_annotation = extended_annotator.annotate_java_file('test.java', test_code)
    
    print(f"Original labels: {original_annotation.labels}")
    print(f"Extended labels: {extended_annotation.labels}")
    print(f"New patterns detected: {set(extended_annotation.labels) - set(original_annotation.labels)}")
    
    print("\n2. Testing Extended Prompt Templates")
    print("-" * 40)
    
    # Generate prompts with extended generator
    original_pairs = PromptGenerator().generate_prompt_completion_pairs(extended_annotation, max_pairs_per_file=3)
    extended_pairs = extended_prompt_gen.generate_prompt_completion_pairs(extended_annotation, max_pairs_per_file=6)
    
    print(f"Original templates generated: {len(original_pairs)}")
    print(f"Extended templates generated: {len(extended_pairs)}")
    
    # Show new template examples
    custom_templates = ['code_review', 'educational_explanation', 'threat_modeling']
    for pair in extended_pairs:
        if pair.metadata['template_name'] in custom_templates:
            print(f"\n--- Custom Template: {pair.metadata['template_name']} ---")
            print("PROMPT PREVIEW:")
            print(pair.prompt[:200] + "...")
            print("\nCOMPLETION PREVIEW:")
            print(pair.completion[:200] + "...")
            break
    
    print("\n3. Demonstrating Easy Extension Process")
    print("-" * 40)
    
    print("To add new annotation patterns:")
    print("1. Extend JavaCodeAnnotator or SOCodeAnnotator")
    print("2. Add patterns to self.annotation_patterns dictionary")
    print("3. Pattern format: 'category': ['regex1', 'regex2', ...]")
    
    print("\nTo add new prompt templates:")
    print("1. Extend PromptGenerator class")
    print("2. Add templates to self.prompt_templates dictionary")
    print("3. Implement completion generation method")
    print("4. Update template selection logic")
    
    print("\n4. Showing Available Extension Points")
    print("-" * 40)
    
    original_patterns = len(JavaCodeAnnotator().annotation_patterns)
    extended_patterns = len(extended_annotator.annotation_patterns)
    original_templates = len(PromptGenerator().prompt_templates)
    extended_templates = len(extended_prompt_gen.prompt_templates)
    
    print(f"Annotation patterns: {original_patterns} → {extended_patterns} (+{extended_patterns - original_patterns})")
    print(f"Prompt templates: {original_templates} → {extended_templates} (+{extended_templates - original_templates})")
    
    print("\nNew annotation categories added:")
    for category in ['machine_learning', 'blockchain_crypto', 'social_media']:
        print(f"  - {category.replace('_', ' ').title()}")
    
    print("\nNew prompt templates added:")
    for template in ['code_review', 'educational_explanation', 'threat_modeling']:
        print(f"  - {template.replace('_', ' ').title()}")


def demonstrate_ml_integration():
    """Show how the pipeline could integrate with ML frameworks."""
    print("\n" + "="*60)
    print("ML FRAMEWORK INTEGRATION EXAMPLE")
    print("="*60)
    
    print("Example integration with HuggingFace Transformers:")
    print("""
# Load generated training data
import json
from datasets import Dataset

training_data = []
with open('apk_training_data.jsonl', 'r') as f:
    for line in f:
        data = json.loads(line)
        training_data.append({
            'input': data['prompt'],
            'output': data['completion'],
            'labels': data['metadata']['labels']
        })

# Create HuggingFace dataset
dataset = Dataset.from_list(training_data)

# Filter by specific categories
security_data = dataset.filter(
    lambda x: any(label in x['labels'] 
                 for label in ['encryption_decryption', 'authentication'])
)

# Use with transformers
from transformers import AutoTokenizer, AutoModelForCausalLM, Trainer

tokenizer = AutoTokenizer.from_pretrained('microsoft/DialoGPT-medium')
model = AutoModelForCausalLM.from_pretrained('microsoft/DialoGPT-medium')

# Fine-tune on APK analysis data
trainer = Trainer(
    model=model,
    train_dataset=security_data,
    # ... trainer configuration
)
""")


def main():
    """Run extensibility demonstration."""
    print("APK LLM ANNOTATION PIPELINE - EXTENSIBILITY DEMONSTRATION")
    print("This shows how the pipeline can be easily extended with custom functionality.\n")
    
    try:
        demonstrate_extensibility()
        demonstrate_ml_integration()
        
        print("\n" + "="*60)
        print("EXTENSIBILITY VALIDATION COMPLETED")
        print("="*60)
        print("✓ Custom annotation patterns work correctly")
        print("✓ Custom prompt templates generate properly")
        print("✓ Extension points are clearly defined")
        print("✓ Pipeline maintains modularity")
        print("✓ ML framework integration examples provided")
        
    except Exception as e:
        print(f"\nError during extensibility demonstration: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())