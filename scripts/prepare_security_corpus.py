#!/usr/bin/env python3
"""
Prepare Security Corpus for LLM Training

This script merges and annotates PoCs from various sources for prompt/completion-based
LLM training. It processes the harvested Metasploit dataset and other security
datasets to create a comprehensive training corpus.

Usage:
    python scripts/prepare_security_corpus.py --input metasploit_dataset.jsonl --output training_corpus.jsonl
    python scripts/prepare_security_corpus.py --merge-datasets dataset1.jsonl dataset2.jsonl --output combined_corpus.jsonl
"""

import os
import sys
import json
import argparse
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
import hashlib
import random

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

def setup_logging(verbose: bool = False):
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

class SecurityCorpusPreparator:
    """
    Prepares and annotates security datasets for LLM training.
    """
    
    def __init__(self, verbose: bool = False):
        self.logger = logging.getLogger(__name__)
        self.verbose = verbose
        self.processed_samples = 0
        
        # Training prompt templates
        self.prompt_templates = {
            'code_explanation': [
                "Explain what this security code does:",
                "Analyze the following security module:",
                "Describe the functionality of this exploit code:",
                "What is the purpose of this security script?",
                "Break down this security tool for educational purposes:"
            ],
            'vulnerability_analysis': [
                "Analyze the security implications of this vulnerability:",
                "What are the risks associated with this security issue?",
                "Explain the impact of this exploit:",
                "Describe the attack vector used in this module:",
                "What defensive measures should be taken against this threat?"
            ],
            'usage_guidance': [
                "When would you use this security tool?",
                "What are the appropriate use cases for this module?",
                "How should this exploit be used responsibly?",
                "What are the ethical considerations for this tool?",
                "In what scenarios is this security technique applicable?"
            ],
            'technical_details': [
                "Explain the technical approach used in this exploit:",
                "What are the prerequisites for this attack?",
                "How does this vulnerability work technically?",
                "Describe the exploit development process for this issue:",
                "What are the technical requirements for this module?"
            ],
            'mitigation': [
                "How can this vulnerability be mitigated?",
                "What patches or fixes address this security issue?",
                "How can systems be protected against this exploit?",
                "What are the best practices to prevent this attack?",
                "How should organizations defend against this threat?"
            ]
        }
        
        # Ethical guidelines for training data
        self.ethical_guidelines = {
            'educational_only': True,
            'no_malicious_intent': True,
            'responsible_disclosure': True,
            'legal_compliance': True
        }
    
    def load_dataset(self, file_path: str) -> List[Dict]:
        """Load a dataset from JSONL or JSON file."""
        self.logger.info(f"Loading dataset from {file_path}")
        
        try:
            data = []
            with open(file_path, 'r', encoding='utf-8') as f:
                if file_path.endswith('.jsonl'):
                    for line_num, line in enumerate(f, 1):
                        line = line.strip()
                        if line:
                            try:
                                data.append(json.loads(line))
                            except json.JSONDecodeError as e:
                                self.logger.warning(f"Skipping invalid JSON on line {line_num}: {e}")
                else:  # JSON format
                    data = json.load(f)
            
            self.logger.info(f"Loaded {len(data)} samples from {file_path}")
            return data
            
        except Exception as e:
            self.logger.error(f"Failed to load dataset from {file_path}: {e}")
            return []
    
    def merge_datasets(self, dataset_paths: List[str]) -> List[Dict]:
        """Merge multiple datasets into one."""
        self.logger.info(f"Merging {len(dataset_paths)} datasets")
        
        merged_data = []
        dataset_info = {}
        
        for path in dataset_paths:
            data = self.load_dataset(path)
            if data:
                # Add source information to each sample
                for sample in data:
                    sample['source_dataset'] = os.path.basename(path)
                    sample['merged_at'] = datetime.now().isoformat()
                
                merged_data.extend(data)
                dataset_info[os.path.basename(path)] = len(data)
        
        self.logger.info(f"Merged datasets: {dataset_info}")
        self.logger.info(f"Total samples: {len(merged_data)}")
        
        return merged_data
    
    def generate_training_sample(self, data_sample: Dict, template_type: str = None) -> Dict:
        """Generate a training sample from a data sample."""
        if template_type is None:
            template_type = random.choice(list(self.prompt_templates.keys()))
        
        training_sample = {
            'id': self._generate_sample_id(data_sample),
            'created_at': datetime.now().isoformat(),
            'template_type': template_type,
            'source_metadata': {
                'category': data_sample.get('category', 'unknown'),
                'complexity': data_sample.get('complexity', 'unknown'),
                'risk_level': data_sample.get('risk_level', 'unknown'),
                'tags': data_sample.get('tags', [])
            }
        }
        
        # Generate prompt and completion based on template type
        if template_type == 'code_explanation':
            training_sample.update(self._generate_code_explanation(data_sample))
        elif template_type == 'vulnerability_analysis':
            training_sample.update(self._generate_vulnerability_analysis(data_sample))
        elif template_type == 'usage_guidance':
            training_sample.update(self._generate_usage_guidance(data_sample))
        elif template_type == 'technical_details':
            training_sample.update(self._generate_technical_details(data_sample))
        elif template_type == 'mitigation':
            training_sample.update(self._generate_mitigation_guidance(data_sample))
        
        # Add ethical context
        training_sample['ethical_context'] = self._generate_ethical_context(data_sample)
        
        return training_sample
    
    def _generate_sample_id(self, data_sample: Dict) -> str:
        """Generate a unique ID for a training sample."""
        content = json.dumps(data_sample, sort_keys=True)
        hash_obj = hashlib.md5(content.encode('utf-8'))
        return f"sec_{hash_obj.hexdigest()[:16]}"
    
    def _generate_code_explanation(self, data_sample: Dict) -> Dict:
        """Generate code explanation training pair."""
        code_preview = data_sample.get('code_preview', data_sample.get('code', ''))[:1000]
        
        prompt_template = random.choice(self.prompt_templates['code_explanation'])
        prompt = f"{prompt_template}\n\n```ruby\n{code_preview}\n```"
        
        completion_parts = []
        
        # Basic description
        name = data_sample.get('name', 'Unknown Module')
        description = data_sample.get('description', 'No description available.')
        category = data_sample.get('category', 'security module')
        
        completion_parts.append(f"This is a {category} named '{name}'. {description}")
        
        # Technical details
        if data_sample.get('security_patterns'):
            patterns = ', '.join(data_sample['security_patterns'])
            completion_parts.append(f"It implements security patterns including: {patterns}.")
        
        # Risk information
        risk_level = data_sample.get('risk_level', 'unknown')
        completion_parts.append(f"Risk level: {risk_level}.")
        
        # Platform information
        if data_sample.get('platform'):
            completion_parts.append(f"Target platform: {data_sample['platform']}.")
        
        completion = " ".join(completion_parts)
        
        return {
            'prompt': prompt,
            'completion': completion,
            'code_included': bool(code_preview)
        }
    
    def _generate_vulnerability_analysis(self, data_sample: Dict) -> Dict:
        """Generate vulnerability analysis training pair."""
        prompt_template = random.choice(self.prompt_templates['vulnerability_analysis'])
        name = data_sample.get('name', 'this vulnerability')
        prompt = f"{prompt_template.replace('this vulnerability', name)}"
        
        completion_parts = []
        
        # Basic vulnerability info
        description = data_sample.get('description', 'No description available.')
        completion_parts.append(f"This vulnerability involves {description}")
        
        # CVE information
        if data_sample.get('cves'):
            cves = ', '.join(data_sample['cves'])
            completion_parts.append(f"Associated CVEs: {cves}.")
        
        # Risk assessment
        risk_level = data_sample.get('risk_level', 'unknown')
        completion_parts.append(f"Risk level: {risk_level}.")
        
        # Attack patterns
        if data_sample.get('security_patterns'):
            patterns = ', '.join(data_sample['security_patterns'])
            completion_parts.append(f"Attack patterns: {patterns}.")
        
        # Impact assessment
        requires_admin = data_sample.get('requires_admin', False)
        network_required = data_sample.get('network_required', False)
        
        impact_factors = []
        if requires_admin:
            impact_factors.append("requires administrative privileges")
        if network_required:
            impact_factors.append("requires network access")
        
        if impact_factors:
            completion_parts.append(f"Impact factors: {', '.join(impact_factors)}.")
        
        completion = " ".join(completion_parts)
        
        return {
            'prompt': prompt,
            'completion': completion,
            'vulnerability_focused': True
        }
    
    def _generate_usage_guidance(self, data_sample: Dict) -> Dict:
        """Generate usage guidance training pair."""
        prompt_template = random.choice(self.prompt_templates['usage_guidance'])
        category = data_sample.get('category', 'security tool')
        name = data_sample.get('name', 'this tool')
        prompt = f"{prompt_template.replace('this security tool', f'the {category} \"{name}\"')}"
        
        completion_parts = []
        
        # Primary use case
        intent = data_sample.get('intent', 'security testing')
        completion_parts.append(f"This module is designed for {intent}.")
        
        # Appropriate scenarios
        description = data_sample.get('description', '')
        if description:
            completion_parts.append(f"It should be used when {description.lower()}")
        
        # Educational value
        educational_value = data_sample.get('educational_value', 'medium')
        completion_parts.append(f"Educational value: {educational_value}.")
        
        # Ethical considerations
        completion_parts.append("This tool should only be used for:")
        completion_parts.append("- Authorized penetration testing")
        completion_parts.append("- Security research and education")
        completion_parts.append("- Vulnerability assessment with proper authorization")
        completion_parts.append("- Legal security auditing activities")
        
        # Risk warnings
        risk_level = data_sample.get('risk_level', 'unknown')
        if risk_level in ['high', 'medium']:
            completion_parts.append(f"⚠️ This is a {risk_level}-risk tool that requires careful handling and appropriate authorization.")
        
        completion = " ".join(completion_parts)
        
        return {
            'prompt': prompt,
            'completion': completion,
            'ethical_guidance': True
        }
    
    def _generate_technical_details(self, data_sample: Dict) -> Dict:
        """Generate technical details training pair."""
        prompt_template = random.choice(self.prompt_templates['technical_details'])
        name = data_sample.get('name', 'this exploit')
        prompt = f"{prompt_template.replace('this exploit', name)}"
        
        completion_parts = []
        
        # Technical approach
        completion_parts.append(f"Technical approach: {data_sample.get('description', 'Not specified')}")
        
        # Prerequisites
        prereqs = []
        if data_sample.get('requires_admin'):
            prereqs.append("administrative privileges")
        if data_sample.get('network_required'):
            prereqs.append("network connectivity")
        if data_sample.get('platform'):
            prereqs.append(f"target platform: {data_sample['platform']}")
        
        if prereqs:
            completion_parts.append(f"Prerequisites: {', '.join(prereqs)}.")
        
        # Complexity
        complexity = data_sample.get('complexity', 'unknown')
        line_count = data_sample.get('line_count', 0)
        method_count = data_sample.get('method_count', 0)
        
        completion_parts.append(f"Complexity: {complexity} ({line_count} lines, {method_count} methods).")
        
        # Technical patterns
        if data_sample.get('security_patterns'):
            patterns = ', '.join(data_sample['security_patterns'])
            completion_parts.append(f"Implements: {patterns}.")
        
        # Payload information
        if data_sample.get('default_payload'):
            completion_parts.append(f"Default payload: {data_sample['default_payload']}.")
        
        completion = " ".join(completion_parts)
        
        return {
            'prompt': prompt,
            'completion': completion,
            'technical_focused': True
        }
    
    def _generate_mitigation_guidance(self, data_sample: Dict) -> Dict:
        """Generate mitigation guidance training pair."""
        prompt_template = random.choice(self.prompt_templates['mitigation'])
        name = data_sample.get('name', 'this vulnerability')
        prompt = f"{prompt_template.replace('this vulnerability', name).replace('this exploit', name)}"
        
        completion_parts = []
        
        # General mitigation strategies
        completion_parts.append(f"To mitigate {name}:")
        
        # Specific mitigations based on patterns
        security_patterns = data_sample.get('security_patterns', [])
        
        if 'buffer_overflow' in security_patterns:
            completion_parts.append("- Implement proper input validation and bounds checking")
            completion_parts.append("- Use memory-safe programming languages where possible")
            completion_parts.append("- Enable stack canaries and ASLR")
        
        if 'sql_injection' in security_patterns:
            completion_parts.append("- Use parameterized queries or prepared statements")
            completion_parts.append("- Implement proper input sanitization")
            completion_parts.append("- Follow principle of least privilege for database access")
        
        if 'rce' in security_patterns:
            completion_parts.append("- Implement strict input validation")
            completion_parts.append("- Use sandboxing and containerization")
            completion_parts.append("- Apply principle of least privilege")
        
        if 'privilege_escalation' in security_patterns:
            completion_parts.append("- Regular privilege audits and access reviews")
            completion_parts.append("- Implement proper access controls")
            completion_parts.append("- Monitor for unusual privilege changes")
        
        # General recommendations
        completion_parts.append("- Keep systems updated with latest security patches")
        completion_parts.append("- Implement network segmentation")
        completion_parts.append("- Use intrusion detection and monitoring")
        completion_parts.append("- Regular security assessments and penetration testing")
        
        # References
        if data_sample.get('references'):
            completion_parts.append(f"References available: {len(data_sample['references'])} sources.")
        
        completion = "\n".join(completion_parts)
        
        return {
            'prompt': prompt,
            'completion': completion,
            'mitigation_focused': True
        }
    
    def _generate_ethical_context(self, data_sample: Dict) -> Dict:
        """Generate ethical context for the training sample."""
        return {
            'intended_use': 'Educational and authorized security testing only',
            'restrictions': [
                'No malicious use',
                'Requires proper authorization',
                'Legal compliance mandatory',
                'Responsible disclosure principles'
            ],
            'risk_level': data_sample.get('risk_level', 'unknown'),
            'educational_value': data_sample.get('educational_value', 'medium')
        }
    
    def prepare_training_corpus(self, data: List[Dict], 
                              samples_per_item: int = 3,
                              template_distribution: Dict[str, float] = None) -> List[Dict]:
        """Prepare the complete training corpus."""
        if template_distribution is None:
            template_distribution = {
                'code_explanation': 0.3,
                'vulnerability_analysis': 0.25,
                'usage_guidance': 0.2,
                'technical_details': 0.15,
                'mitigation': 0.1
            }
        
        self.logger.info(f"Preparing training corpus from {len(data)} data samples")
        self.logger.info(f"Generating {samples_per_item} training samples per data item")
        
        training_corpus = []
        
        for i, data_sample in enumerate(data):
            # Generate multiple training samples per data item
            for _ in range(samples_per_item):
                # Select template type based on distribution
                template_type = self._select_template_type(template_distribution)
                
                training_sample = self.generate_training_sample(data_sample, template_type)
                training_corpus.append(training_sample)
                
                self.processed_samples += 1
                
                if self.processed_samples % 1000 == 0:
                    self.logger.info(f"Generated {self.processed_samples} training samples...")
        
        self.logger.info(f"Generated {len(training_corpus)} total training samples")
        return training_corpus
    
    def _select_template_type(self, distribution: Dict[str, float]) -> str:
        """Select a template type based on the given distribution."""
        rand_val = random.random()
        cumulative = 0.0
        
        for template_type, prob in distribution.items():
            cumulative += prob
            if rand_val <= cumulative:
                return template_type
        
        # Fallback to first template type
        return list(distribution.keys())[0]
    
    def filter_and_validate(self, corpus: List[Dict], 
                          min_prompt_length: int = 10,
                          min_completion_length: int = 20,
                          max_prompt_length: int = 2000,
                          max_completion_length: int = 4000) -> List[Dict]:
        """Filter and validate the training corpus."""
        self.logger.info("Filtering and validating training corpus...")
        
        filtered_corpus = []
        stats = {
            'total': len(corpus),
            'too_short': 0,
            'too_long': 0,
            'invalid': 0,
            'valid': 0
        }
        
        for sample in corpus:
            try:
                prompt = sample.get('prompt', '')
                completion = sample.get('completion', '')
                
                # Length validation
                if len(prompt) < min_prompt_length or len(completion) < min_completion_length:
                    stats['too_short'] += 1
                    continue
                
                if len(prompt) > max_prompt_length or len(completion) > max_completion_length:
                    stats['too_long'] += 1
                    continue
                
                # Content validation
                if not prompt.strip() or not completion.strip():
                    stats['invalid'] += 1
                    continue
                
                # Add validation markers
                sample['validated'] = True
                sample['prompt_length'] = len(prompt)
                sample['completion_length'] = len(completion)
                
                filtered_corpus.append(sample)
                stats['valid'] += 1
                
            except Exception as e:
                self.logger.warning(f"Error validating sample: {e}")
                stats['invalid'] += 1
                continue
        
        self.logger.info(f"Validation stats: {stats}")
        return filtered_corpus
    
    def save_corpus(self, corpus: List[Dict], output_path: str, 
                   format: str = 'jsonl', shuffle: bool = True):
        """Save the training corpus to a file."""
        self.logger.info(f"Saving training corpus with {len(corpus)} samples to {output_path}")
        
        if shuffle:
            random.shuffle(corpus)
            self.logger.info("Shuffled training samples")
        
        try:
            output_dir = os.path.dirname(output_path)
            if output_dir:  # Only create directory if there is one
                os.makedirs(output_dir, exist_ok=True)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                if format == 'jsonl':
                    for sample in corpus:
                        f.write(json.dumps(sample, ensure_ascii=False) + '\n')
                else:  # json
                    json.dump(corpus, f, ensure_ascii=False, indent=2)
            
            self.logger.info(f"Training corpus saved successfully to {output_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to save training corpus: {e}")
            raise
    
    def generate_statistics(self, corpus: List[Dict]) -> Dict:
        """Generate statistics about the training corpus."""
        stats = {
            'total_samples': len(corpus),
            'template_types': {},
            'source_categories': {},
            'complexity_levels': {},
            'risk_levels': {},
            'avg_prompt_length': 0,
            'avg_completion_length': 0,
            'ethical_samples': 0
        }
        
        prompt_lengths = []
        completion_lengths = []
        
        for sample in corpus:
            # Template type distribution
            template_type = sample.get('template_type', 'unknown')
            stats['template_types'][template_type] = stats['template_types'].get(template_type, 0) + 1
            
            # Source category distribution
            category = sample.get('source_metadata', {}).get('category', 'unknown')
            stats['source_categories'][category] = stats['source_categories'].get(category, 0) + 1
            
            # Complexity distribution
            complexity = sample.get('source_metadata', {}).get('complexity', 'unknown')
            stats['complexity_levels'][complexity] = stats['complexity_levels'].get(complexity, 0) + 1
            
            # Risk level distribution
            risk_level = sample.get('source_metadata', {}).get('risk_level', 'unknown')
            stats['risk_levels'][risk_level] = stats['risk_levels'].get(risk_level, 0) + 1
            
            # Length statistics
            prompt_lengths.append(sample.get('prompt_length', 0))
            completion_lengths.append(sample.get('completion_length', 0))
            
            # Ethical content
            if sample.get('ethical_guidance') or sample.get('ethical_context'):
                stats['ethical_samples'] += 1
        
        # Calculate averages
        if prompt_lengths:
            stats['avg_prompt_length'] = sum(prompt_lengths) / len(prompt_lengths)
        if completion_lengths:
            stats['avg_completion_length'] = sum(completion_lengths) / len(completion_lengths)
        
        return stats

def main():
    """Main entry point for the security corpus preparator."""
    parser = argparse.ArgumentParser(
        description="Prepare security corpus for LLM training"
    )
    
    parser.add_argument(
        '--input', '-i',
        help='Input dataset file (JSONL or JSON)'
    )
    
    parser.add_argument(
        '--merge-datasets',
        nargs='*',
        help='Multiple dataset files to merge'
    )
    
    parser.add_argument(
        '--output', '-o',
        default='training_corpus.jsonl',
        help='Output training corpus file (default: training_corpus.jsonl)'
    )
    
    parser.add_argument(
        '--format',
        choices=['jsonl', 'json'],
        default='jsonl',
        help='Output format (default: jsonl)'
    )
    
    parser.add_argument(
        '--samples-per-item',
        type=int,
        default=3,
        help='Number of training samples to generate per data item (default: 3)'
    )
    
    parser.add_argument(
        '--min-prompt-length',
        type=int,
        default=10,
        help='Minimum prompt length (default: 10)'
    )
    
    parser.add_argument(
        '--min-completion-length',
        type=int,
        default=20,
        help='Minimum completion length (default: 20)'
    )
    
    parser.add_argument(
        '--shuffle',
        action='store_true',
        default=True,
        help='Shuffle training samples (default: True)'
    )
    
    parser.add_argument(
        '--stats-output',
        help='Output file for corpus statistics (optional)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.input and not args.merge_datasets:
        parser.error("Either --input or --merge-datasets must be specified")
    
    # Setup logging
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)
    
    # Create preparator
    preparator = SecurityCorpusPreparator(verbose=args.verbose)
    
    try:
        logger.info("Starting security corpus preparation...")
        
        # Load data
        if args.merge_datasets:
            data = preparator.merge_datasets(args.merge_datasets)
        else:
            data = preparator.load_dataset(args.input)
        
        if not data:
            logger.error("No data loaded")
            return 1
        
        # Prepare training corpus
        corpus = preparator.prepare_training_corpus(
            data, 
            samples_per_item=args.samples_per_item
        )
        
        # Filter and validate
        corpus = preparator.filter_and_validate(
            corpus,
            min_prompt_length=args.min_prompt_length,
            min_completion_length=args.min_completion_length
        )
        
        if not corpus:
            logger.error("No valid training samples generated")
            return 1
        
        # Save corpus
        preparator.save_corpus(
            corpus, 
            args.output, 
            format=args.format, 
            shuffle=args.shuffle
        )
        
        # Generate and save statistics
        stats = preparator.generate_statistics(corpus)
        
        if args.stats_output:
            with open(args.stats_output, 'w', encoding='utf-8') as f:
                json.dump(stats, f, ensure_ascii=False, indent=2)
            logger.info(f"Statistics saved to {args.stats_output}")
        
        # Print summary
        print(f"\n{'='*60}")
        print(f"Security Corpus Preparation Complete")
        print(f"{'='*60}")
        print(f"Input data samples: {len(data)}")
        print(f"Generated training samples: {stats['total_samples']}")
        print(f"Output saved to: {args.output}")
        print(f"Format: {args.format}")
        
        print(f"\nTemplate distribution:")
        for template_type, count in sorted(stats['template_types'].items()):
            percentage = (count / stats['total_samples']) * 100
            print(f"  {template_type}: {count} ({percentage:.1f}%)")
        
        print(f"\nCategory distribution:")
        for category, count in sorted(stats['source_categories'].items()):
            percentage = (count / stats['total_samples']) * 100
            print(f"  {category}: {count} ({percentage:.1f}%)")
        
        print(f"\nAverage lengths:")
        print(f"  Prompt: {stats['avg_prompt_length']:.1f} characters")
        print(f"  Completion: {stats['avg_completion_length']:.1f} characters")
        
        print(f"\nEthical samples: {stats['ethical_samples']} ({(stats['ethical_samples']/stats['total_samples'])*100:.1f}%)")
        print(f"\n{'='*60}")
        
        return 0
        
    except KeyboardInterrupt:
        logger.info("Corpus preparation interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"Corpus preparation failed: {e}")
        return 1

if __name__ == '__main__':
    sys.exit(main())