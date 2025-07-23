#!/usr/bin/env python3
"""
Harvest Metasploit Framework PoCs for LLM Training Dataset

This script clones the Metasploit Framework repository, extracts exploit module
metadata and code, annotates the data, and outputs a JSONL file suitable for
LLM training focused on security research and ethical hacking.

Usage:
    python scripts/harvest_metasploit_pocs.py --output metasploit_dataset.jsonl
    python scripts/harvest_metasploit_pocs.py --limit 100 --categories exploits auxiliary
"""

import os
import sys
import json
import argparse
import subprocess
import tempfile
import shutil
import re
from pathlib import Path
from typing import Dict, List, Optional, Set
from datetime import datetime
import logging

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

class MetasploitHarvester:
    """
    Harvests Metasploit Framework modules for security dataset creation.
    """
    
    def __init__(self, clone_dir: Optional[str] = None, verbose: bool = False):
        self.logger = logging.getLogger(__name__)
        self.clone_dir = clone_dir or tempfile.mkdtemp(prefix="metasploit_")
        self.metasploit_repo = "https://github.com/rapid7/metasploit-framework.git"
        self.modules_processed = 0
        self.verbose = verbose
        
        # Module categories to process
        self.categories = {
            'exploits': 'modules/exploits',
            'auxiliary': 'modules/auxiliary', 
            'post': 'modules/post',
            'payloads': 'modules/payloads',
            'encoders': 'modules/encoders',
            'nops': 'modules/nops'
        }
        
    def clone_metasploit(self) -> bool:
        """Clone the Metasploit Framework repository."""
        self.logger.info(f"Cloning Metasploit Framework to {self.clone_dir}")
        
        try:
            # Check if already cloned
            if os.path.exists(os.path.join(self.clone_dir, '.git')):
                self.logger.info("Repository already exists, pulling latest changes")
                result = subprocess.run(
                    ['git', 'pull'], 
                    cwd=self.clone_dir,
                    capture_output=True, 
                    text=True,
                    timeout=300
                )
            else:
                result = subprocess.run(
                    ['git', 'clone', '--depth', '1', self.metasploit_repo, self.clone_dir],
                    capture_output=True,
                    text=True,
                    timeout=600
                )
            
            if result.returncode != 0:
                self.logger.error(f"Git command failed: {result.stderr}")
                return False
                
            self.logger.info("Successfully cloned/updated Metasploit Framework")
            return True
            
        except subprocess.TimeoutExpired:
            self.logger.error("Git clone/pull timed out")
            return False
        except Exception as e:
            self.logger.error(f"Failed to clone repository: {e}")
            return False
    
    def extract_module_metadata(self, module_path: str) -> Optional[Dict]:
        """Extract metadata from a Metasploit module file."""
        try:
            with open(module_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            metadata = {
                'filepath': module_path,
                'filename': os.path.basename(module_path),
                'category': self._determine_category(module_path),
                'size_bytes': len(content.encode('utf-8')),
                'line_count': content.count('\n'),
                'extracted_at': datetime.now().isoformat()
            }
            
            # Extract module information
            metadata.update(self._parse_module_info(content))
            
            # Extract vulnerability information
            metadata.update(self._parse_vulnerability_info(content))
            
            # Extract technical details
            metadata.update(self._parse_technical_details(content))
            
            # Clean and prepare code
            metadata['code'] = self._clean_code(content)
            metadata['code_preview'] = content[:500] + "..." if len(content) > 500 else content
            
            return metadata
            
        except Exception as e:
            self.logger.error(f"Failed to extract metadata from {module_path}: {e}")
            return None
    
    def _determine_category(self, module_path: str) -> str:
        """Determine the category of a module based on its path."""
        for category, path_pattern in self.categories.items():
            if path_pattern in module_path:
                return category
        return 'unknown'
    
    def _parse_module_info(self, content: str) -> Dict:
        """Parse basic module information from the content."""
        info = {}
        
        # Extract module name
        name_match = re.search(r"Name\s*=>\s*['\"]([^'\"]+)['\"]", content, re.IGNORECASE)
        if name_match:
            info['name'] = name_match.group(1)
            
        # Extract description
        desc_match = re.search(r"Description\s*=>\s*['\"]([^'\"]+)['\"]", content, re.IGNORECASE)
        if desc_match:
            info['description'] = desc_match.group(1)
            
        # Extract author
        author_match = re.search(r"Author\s*=>\s*\[([^\]]+)\]", content, re.IGNORECASE)
        if author_match:
            authors = re.findall(r"['\"]([^'\"]+)['\"]", author_match.group(1))
            info['authors'] = authors
            
        # Extract license
        license_match = re.search(r"License\s*=>\s*['\"]([^'\"]+)['\"]", content, re.IGNORECASE)
        if license_match:
            info['license'] = license_match.group(1)
            
        # Extract platform
        platform_match = re.search(r"Platform\s*=>\s*['\"]([^'\"]+)['\"]", content, re.IGNORECASE)
        if platform_match:
            info['platform'] = platform_match.group(1)
        
        return info
    
    def _parse_vulnerability_info(self, content: str) -> Dict:
        """Parse vulnerability-related information."""
        vuln_info = {}
        
        # Extract CVE references
        cve_pattern = r'CVE-(\d{4}-\d{4,})'
        cves = re.findall(cve_pattern, content, re.IGNORECASE)
        if cves:
            vuln_info['cves'] = [f"CVE-{cve}" for cve in cves]
            
        # Extract references
        ref_pattern = r"References\s*=>\s*\[([^\]]+)\]"
        ref_match = re.search(ref_pattern, content, re.IGNORECASE | re.DOTALL)
        if ref_match:
            refs = re.findall(r"['\"]([^'\"]+)['\"]", ref_match.group(1))
            vuln_info['references'] = refs
            
        # Extract targets
        targets_pattern = r"Targets\s*=>\s*\[([^\]]+)\]"
        targets_match = re.search(targets_pattern, content, re.IGNORECASE | re.DOTALL)
        if targets_match:
            vuln_info['targets'] = targets_match.group(1)
            
        # Extract rank
        rank_match = re.search(r"Rank\s*=>\s*(\w+)", content, re.IGNORECASE)
        if rank_match:
            vuln_info['rank'] = rank_match.group(1)
            
        return vuln_info
    
    def _parse_technical_details(self, content: str) -> Dict:
        """Parse technical implementation details."""
        tech_info = {}
        
        # Extract required privileges
        if 'admin' in content.lower() or 'administrator' in content.lower():
            tech_info['requires_admin'] = True
            
        # Extract network requirements
        if any(keyword in content.lower() for keyword in ['tcp', 'udp', 'http', 'https']):
            tech_info['network_required'] = True
            
        # Extract payload information
        payload_match = re.search(r"DefaultPayload\s*=>\s*['\"]([^'\"]+)['\"]", content, re.IGNORECASE)
        if payload_match:
            tech_info['default_payload'] = payload_match.group(1)
            
        # Count method definitions
        method_count = len(re.findall(r'def\s+\w+', content))
        tech_info['method_count'] = method_count
        
        # Check for common security patterns
        security_patterns = {
            'buffer_overflow': r'buffer.*overflow|overflow.*buffer',
            'sql_injection': r'sql.*inject|inject.*sql',
            'xss': r'cross.*site.*script|xss',
            'rce': r'remote.*code.*execut|command.*execut',
            'privilege_escalation': r'privilege.*escalat|escalat.*privilege',
            'authentication_bypass': r'auth.*bypass|bypass.*auth'
        }
        
        detected_patterns = []
        for pattern_name, pattern in security_patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                detected_patterns.append(pattern_name)
                
        if detected_patterns:
            tech_info['security_patterns'] = detected_patterns
            
        return tech_info
    
    def _clean_code(self, content: str) -> str:
        """Clean and prepare code for training."""
        # Remove excessive whitespace while preserving structure
        lines = content.split('\n')
        cleaned_lines = []
        
        for line in lines:
            # Keep indentation but remove trailing whitespace
            cleaned_line = line.rstrip()
            cleaned_lines.append(cleaned_line)
            
        # Remove excessive blank lines
        final_lines = []
        prev_blank = False
        
        for line in cleaned_lines:
            is_blank = len(line.strip()) == 0
            if not (is_blank and prev_blank):
                final_lines.append(line)
            prev_blank = is_blank
            
        return '\n'.join(final_lines)
    
    def generate_training_annotations(self, metadata: Dict) -> Dict:
        """Generate training annotations for the module."""
        annotations = {
            'intent': self._classify_intent(metadata),
            'complexity': self._assess_complexity(metadata),
            'risk_level': self._assess_risk_level(metadata),
            'educational_value': self._assess_educational_value(metadata),
            'tags': self._generate_tags(metadata)
        }
        
        # Generate prompt-completion pairs
        annotations['training_pairs'] = self._generate_training_pairs(metadata)
        
        return annotations
    
    def _classify_intent(self, metadata: Dict) -> str:
        """Classify the intent/purpose of the module."""
        category = metadata.get('category', '').lower()
        name = metadata.get('name', '').lower()
        description = metadata.get('description', '').lower()
        
        if category == 'exploits':
            return 'exploitation'
        elif category == 'auxiliary':
            if any(word in description for word in ['scan', 'discover', 'enum']):
                return 'reconnaissance'
            else:
                return 'auxiliary_attack'
        elif category == 'post':
            return 'post_exploitation'
        elif category == 'payloads':
            return 'payload_delivery'
        else:
            return 'other'
    
    def _assess_complexity(self, metadata: Dict) -> str:
        """Assess the complexity level of the module."""
        line_count = metadata.get('line_count', 0)
        method_count = metadata.get('method_count', 0)
        
        if line_count < 50 and method_count < 3:
            return 'low'
        elif line_count < 200 and method_count < 8:
            return 'medium'
        else:
            return 'high'
    
    def _assess_risk_level(self, metadata: Dict) -> str:
        """Assess the risk level of the module."""
        rank = metadata.get('rank', '').lower()
        requires_admin = metadata.get('requires_admin', False)
        security_patterns = metadata.get('security_patterns', [])
        
        high_risk_patterns = ['buffer_overflow', 'rce', 'privilege_escalation']
        
        if rank in ['excellent', 'great'] or any(p in security_patterns for p in high_risk_patterns):
            return 'high'
        elif rank in ['good', 'normal'] or requires_admin:
            return 'medium'
        else:
            return 'low'
    
    def _assess_educational_value(self, metadata: Dict) -> str:
        """Assess the educational value for security training."""
        cves = metadata.get('cves', [])
        references = metadata.get('references', [])
        description = metadata.get('description', '')
        
        if len(cves) > 0 and len(references) > 2:
            return 'high'
        elif len(description) > 100 and (cves or references):
            return 'medium'
        else:
            return 'low'
    
    def _generate_tags(self, metadata: Dict) -> List[str]:
        """Generate relevant tags for the module."""
        tags = []
        
        # Category-based tags
        category = metadata.get('category', '')
        if category:
            tags.append(category)
            
        # Platform tags
        platform = metadata.get('platform', '')
        if platform:
            tags.extend(platform.lower().split())
            
        # Security pattern tags
        security_patterns = metadata.get('security_patterns', [])
        tags.extend(security_patterns)
        
        # CVE tags
        if metadata.get('cves'):
            tags.append('cve_related')
            
        # Complexity tags
        complexity = metadata.get('complexity', '')
        if complexity:
            tags.append(f"{complexity}_complexity")
            
        return list(set(tags))  # Remove duplicates
    
    def _generate_training_pairs(self, metadata: Dict) -> List[Dict]:
        """Generate prompt-completion pairs for training."""
        pairs = []
        
        # Code explanation pair
        if metadata.get('code'):
            pairs.append({
                'prompt': f"Explain the following {metadata.get('category', 'security')} module:\n\n```ruby\n{metadata['code_preview']}\n```",
                'completion': f"This is a {metadata.get('category', 'security')} module named '{metadata.get('name', 'unknown')}'. {metadata.get('description', 'No description available.')}",
                'type': 'code_explanation'
            })
        
        # Vulnerability analysis pair
        if metadata.get('cves') or metadata.get('description'):
            pairs.append({
                'prompt': f"Analyze the security implications of the module '{metadata.get('name', 'unknown')}'",
                'completion': f"This module targets {metadata.get('description', 'various systems')}. Risk level: {metadata.get('risk_level', 'unknown')}. Security patterns involved: {', '.join(metadata.get('security_patterns', ['none detected']))}.",
                'type': 'vulnerability_analysis'
            })
        
        # Usage guidance pair
        pairs.append({
            'prompt': f"When would you use the {metadata.get('category', 'security')} module '{metadata.get('name', 'unknown')}'?",
            'completion': f"This module would be used for {metadata.get('intent', 'security testing')} purposes, particularly when {metadata.get('description', 'conducting security assessments')}. Educational value: {metadata.get('educational_value', 'medium')}.",
            'type': 'usage_guidance'
        })
        
        return pairs
    
    def harvest_modules(self, categories: Optional[List[str]] = None, limit: Optional[int] = None) -> List[Dict]:
        """Harvest modules from the specified categories."""
        if not self.clone_metasploit():
            return []
            
        categories = categories or list(self.categories.keys())
        harvested_modules = []
        
        self.logger.info(f"Harvesting modules from categories: {categories}")
        
        for category in categories:
            if category not in self.categories:
                self.logger.warning(f"Unknown category: {category}")
                continue
                
            category_path = os.path.join(self.clone_dir, self.categories[category])
            if not os.path.exists(category_path):
                self.logger.warning(f"Category path not found: {category_path}")
                continue
                
            self.logger.info(f"Processing category: {category}")
            
            # Find all Ruby files in the category
            for root, dirs, files in os.walk(category_path):
                for file in files:
                    if file.endswith('.rb'):
                        if limit and self.modules_processed >= limit:
                            self.logger.info(f"Reached limit of {limit} modules")
                            return harvested_modules
                            
                        module_path = os.path.join(root, file)
                        relative_path = os.path.relpath(module_path, self.clone_dir)
                        
                        self.logger.debug(f"Processing module: {relative_path}")
                        
                        metadata = self.extract_module_metadata(module_path)
                        if metadata:
                            # Add relative path for consistency
                            metadata['relative_path'] = relative_path
                            
                            # Generate training annotations
                            annotations = self.generate_training_annotations(metadata)
                            metadata.update(annotations)
                            
                            harvested_modules.append(metadata)
                            self.modules_processed += 1
                            
                            if self.modules_processed % 100 == 0:
                                self.logger.info(f"Processed {self.modules_processed} modules...")
        
        self.logger.info(f"Harvested {len(harvested_modules)} modules total")
        return harvested_modules
    
    def save_dataset(self, modules: List[Dict], output_path: str, format: str = 'jsonl'):
        """Save the harvested modules to a file."""
        self.logger.info(f"Saving {len(modules)} modules to {output_path}")
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                if format == 'jsonl':
                    for module in modules:
                        f.write(json.dumps(module, ensure_ascii=False) + '\n')
                else:  # json
                    json.dump(modules, f, ensure_ascii=False, indent=2)
                    
            self.logger.info(f"Dataset saved successfully to {output_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to save dataset: {e}")
            raise
    
    def cleanup(self):
        """Clean up temporary directories."""
        if os.path.exists(self.clone_dir) and self.clone_dir.startswith('/tmp'):
            self.logger.info(f"Cleaning up temporary directory: {self.clone_dir}")
            shutil.rmtree(self.clone_dir, ignore_errors=True)

def main():
    """Main entry point for the Metasploit harvester."""
    parser = argparse.ArgumentParser(
        description="Harvest Metasploit Framework PoCs for LLM training dataset"
    )
    
    parser.add_argument(
        '--output', '-o',
        default='metasploit_dataset.jsonl',
        help='Output file path (default: metasploit_dataset.jsonl)'
    )
    
    parser.add_argument(
        '--format',
        choices=['jsonl', 'json'],
        default='jsonl',
        help='Output format (default: jsonl)'
    )
    
    parser.add_argument(
        '--categories',
        nargs='*',
        choices=['exploits', 'auxiliary', 'post', 'payloads', 'encoders', 'nops'],
        default=['exploits', 'auxiliary', 'post'],
        help='Module categories to harvest (default: exploits auxiliary post)'
    )
    
    parser.add_argument(
        '--limit', '-l',
        type=int,
        help='Maximum number of modules to process'
    )
    
    parser.add_argument(
        '--clone-dir',
        help='Directory to clone Metasploit repo (default: temporary directory)'
    )
    
    parser.add_argument(
        '--keep-clone',
        action='store_true',
        help='Keep cloned repository after processing'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)
    
    # Create harvester
    harvester = MetasploitHarvester(
        clone_dir=args.clone_dir,
        verbose=args.verbose
    )
    
    try:
        logger.info("Starting Metasploit PoC harvesting...")
        
        # Harvest modules
        modules = harvester.harvest_modules(
            categories=args.categories,
            limit=args.limit
        )
        
        if not modules:
            logger.error("No modules were harvested")
            return 1
        
        # Save dataset
        harvester.save_dataset(modules, args.output, args.format)
        
        # Print summary
        print(f"\n{'='*60}")
        print(f"Metasploit PoC Harvesting Complete")
        print(f"{'='*60}")
        print(f"Modules harvested: {len(modules)}")
        print(f"Categories processed: {', '.join(args.categories)}")
        print(f"Output saved to: {args.output}")
        print(f"Format: {args.format}")
        
        # Show category breakdown
        category_counts = {}
        for module in modules:
            category = module.get('category', 'unknown')
            category_counts[category] = category_counts.get(category, 0) + 1
        
        print(f"\nCategory breakdown:")
        for category, count in sorted(category_counts.items()):
            print(f"  {category}: {count} modules")
        
        print(f"\n{'='*60}")
        
        return 0
        
    except KeyboardInterrupt:
        logger.info("Harvesting interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"Harvesting failed: {e}")
        return 1
    finally:
        if not args.keep_clone:
            harvester.cleanup()

if __name__ == '__main__':
    sys.exit(main())
