#!/usr/bin/env python3
"""
Data Enricher

Enriches security data by cross-referencing entries, adding relationships,
and enhancing data with additional context and metadata.
"""

import re
import logging
from typing import Dict, List, Set, Optional, Tuple
from collections import defaultdict
from datetime import datetime


class DataEnricher:
    """
    Enriches security data by adding cross-references, relationships,
    and additional context from multiple sources.
    """
    
    def __init__(self, verbose: bool = False):
        """
        Initialize the data enricher.
        
        Args:
            verbose: Enable verbose logging
        """
        self.logger = logging.getLogger(__name__)
        if verbose:
            self.logger.setLevel(logging.DEBUG)
        
        self.enriched_count = 0
        self.relationships_added = 0
    
    def enrich_data(self, data_entries: List[Dict]) -> List[Dict]:
        """
        Enrich a list of data entries with cross-references and relationships.
        
        Args:
            data_entries: List of data entries to enrich
            
        Returns:
            List of enriched data entries
        """
        self.logger.info(f"Starting enrichment of {len(data_entries)} entries")
        
        # Create lookup indexes for fast cross-referencing
        indexes = self._build_indexes(data_entries)
        
        enriched_entries = []
        
        for entry in data_entries:
            enriched_entry = self._enrich_single_entry(entry, indexes)
            enriched_entries.append(enriched_entry)
            self.enriched_count += 1
            
            if self.enriched_count % 100 == 0:
                self.logger.debug(f"Enriched {self.enriched_count} entries...")
        
        self.logger.info(f"Enrichment complete. Added {self.relationships_added} relationships")
        return enriched_entries
    
    def _build_indexes(self, data_entries: List[Dict]) -> Dict:
        """Build lookup indexes for cross-referencing."""
        indexes = {
            'cve_id': {},           # CVE ID -> entry
            'cwe_id': {},           # CWE ID -> entry  
            'attack_id': {},        # ATT&CK ID -> entry
            'technique_id': {},     # ATT&CK technique ID -> entry
            'keywords': defaultdict(list),  # keyword -> list of entries
            'platforms': defaultdict(list), # platform -> list of entries
            'vendors': defaultdict(list),   # vendor -> list of entries
            'references': defaultdict(list) # reference URL -> list of entries
        }
        
        for entry in data_entries:
            self._index_entry(entry, indexes)
        
        return indexes
    
    def _index_entry(self, entry: Dict, indexes: Dict):
        """Add an entry to the lookup indexes."""
        identifiers = entry.get('identifiers', {})
        content = entry.get('content', {})
        
        # Index by specific IDs
        if identifiers.get('cve_id'):
            indexes['cve_id'][identifiers['cve_id']] = entry
        
        if identifiers.get('cwe_id'):
            indexes['cwe_id'][identifiers['cwe_id']] = entry
        
        if identifiers.get('attack_id'):
            indexes['attack_id'][identifiers['attack_id']] = entry
        
        if identifiers.get('technique_id'):
            indexes['technique_id'][identifiers['technique_id']] = entry
        
        # Index by keywords
        keywords = self._extract_keywords(entry)
        for keyword in keywords:
            indexes['keywords'][keyword.lower()].append(entry)
        
        # Index by platforms
        platforms = content.get('platforms', [])
        if isinstance(platforms, list):
            for platform in platforms:
                indexes['platforms'][platform.lower()].append(entry)
        
        # Index by references
        references = content.get('references', [])
        if isinstance(references, list):
            for ref in references:
                if isinstance(ref, str):
                    indexes['references'][ref].append(entry)
                elif isinstance(ref, dict) and ref.get('url'):
                    indexes['references'][ref['url']].append(entry)
    
    def _extract_keywords(self, entry: Dict) -> Set[str]:
        """Extract keywords from an entry for indexing."""
        keywords = set()
        content = entry.get('content', {})
        
        # Extract from text fields
        text_fields = ['description', 'name', 'title', 'summary']
        for field in text_fields:
            if field in content and content[field]:
                # Simple keyword extraction (split on whitespace and punctuation)
                words = re.findall(r'\b\w+\b', str(content[field]).lower())
                keywords.update([word for word in words if len(word) > 3])
        
        # Extract technical terms
        if 'security_patterns' in content:
            keywords.update([pattern.lower() for pattern in content['security_patterns']])
        
        if 'mitigations' in content:
            for mitigation in content['mitigations']:
                if isinstance(mitigation, str):
                    words = re.findall(r'\b\w+\b', mitigation.lower())
                    keywords.update([word for word in words if len(word) > 3])
        
        return keywords
    
    def _enrich_single_entry(self, entry: Dict, indexes: Dict) -> Dict:
        """Enrich a single entry with cross-references and relationships."""
        enriched_entry = entry.copy()
        
        # Initialize enrichment section
        if 'enrichment' not in enriched_entry:
            enriched_entry['enrichment'] = {
                'cross_references': [],
                'related_entries': [],
                'extracted_entities': {},
                'enriched_at': datetime.now().isoformat()
            }
        
        # Find cross-references
        cross_refs = self._find_cross_references(entry, indexes)
        enriched_entry['enrichment']['cross_references'].extend(cross_refs)
        
        # Find related entries
        related = self._find_related_entries(entry, indexes)
        enriched_entry['enrichment']['related_entries'].extend(related)
        
        # Extract entities (CVEs, CWEs, etc.)
        entities = self._extract_entities(entry)
        enriched_entry['enrichment']['extracted_entities'].update(entities)
        
        # Add contextual information
        context = self._add_context(entry, indexes)
        enriched_entry['enrichment'].update(context)
        
        self.relationships_added += len(cross_refs) + len(related)
        
        return enriched_entry
    
    def _find_cross_references(self, entry: Dict, indexes: Dict) -> List[Dict]:
        """Find explicit cross-references mentioned in the entry."""
        cross_refs = []
        content = entry.get('content', {})
        
        # Extract CVE references from text
        for field in ['description', 'references']:
            if field in content and content[field]:
                text = str(content[field])
                cve_ids = re.findall(r'CVE-\d{4}-\d{4,}', text, re.IGNORECASE)
                for cve_id in cve_ids:
                    cve_id = cve_id.upper()
                    if cve_id in indexes['cve_id']:
                        cross_refs.append({
                            'type': 'cve_reference',
                            'target_id': cve_id,
                            'source_field': field
                        })
        
        # Extract CWE references
        for field in ['description', 'problem_types']:
            if field in content and content[field]:
                text = str(content[field])
                cwe_ids = re.findall(r'CWE-\d+', text, re.IGNORECASE)
                for cwe_id in cwe_ids:
                    cwe_id = cwe_id.upper()
                    if cwe_id in indexes['cwe_id']:
                        cross_refs.append({
                            'type': 'cwe_reference',
                            'target_id': cwe_id,
                            'source_field': field
                        })
        
        # Extract ATT&CK technique references
        for field in ['description', 'techniques_used']:
            if field in content and content[field]:
                text = str(content[field])
                technique_ids = re.findall(r'T\d{4}(?:\.\d{3})?', text)
                for technique_id in technique_ids:
                    if technique_id in indexes['technique_id']:
                        cross_refs.append({
                            'type': 'attack_technique_reference',
                            'target_id': technique_id,
                            'source_field': field
                        })
        
        return cross_refs
    
    def _find_related_entries(self, entry: Dict, indexes: Dict) -> List[Dict]:
        """Find entries related by content similarity or shared attributes."""
        related = []
        content = entry.get('content', {})
        data_type = entry.get('data_type')
        
        # Find entries with shared platforms
        platforms = content.get('platforms', [])
        if isinstance(platforms, list):
            for platform in platforms:
                related_entries = indexes['platforms'].get(platform.lower(), [])
                for related_entry in related_entries[:3]:  # Limit to avoid too many relationships
                    if related_entry != entry and related_entry.get('data_type') != data_type:
                        related.append({
                            'type': 'shared_platform',
                            'target_id': self._get_entry_id(related_entry),
                            'target_type': related_entry.get('data_type'),
                            'relationship': f"Both target {platform} platform"
                        })
        
        # Find entries with shared keywords
        keywords = self._extract_keywords(entry)
        keyword_matches = defaultdict(int)
        
        for keyword in list(keywords)[:10]:  # Limit keywords to check
            matching_entries = indexes['keywords'].get(keyword, [])
            for matching_entry in matching_entries:
                if matching_entry != entry:
                    entry_id = self._get_entry_id(matching_entry)
                    keyword_matches[entry_id] += 1
        
        # Add entries with multiple keyword matches
        for entry_id, match_count in keyword_matches.items():
            if match_count >= 3:  # Require at least 3 shared keywords
                matching_entry = self._find_entry_by_id(entry_id, indexes)
                if matching_entry:
                    related.append({
                        'type': 'content_similarity',
                        'target_id': entry_id,
                        'target_type': matching_entry.get('data_type'),
                        'relationship': f"Shares {match_count} keywords"
                    })
        
        return related[:10]  # Limit number of related entries
    
    def _extract_entities(self, entry: Dict) -> Dict:
        """Extract named entities from entry content."""
        entities = {
            'cve_ids': [],
            'cwe_ids': [],
            'attack_techniques': [],
            'vendors': [],
            'products': []
        }
        
        content = entry.get('content', {})
        
        # Extract from all text content
        all_text = ''
        for field in ['description', 'name', 'title', 'summary']:
            if field in content and content[field]:
                all_text += str(content[field]) + ' '
        
        # Extract CVE IDs
        entities['cve_ids'] = list(set(re.findall(r'CVE-\d{4}-\d{4,}', all_text, re.IGNORECASE)))
        
        # Extract CWE IDs
        entities['cwe_ids'] = list(set(re.findall(r'CWE-\d+', all_text, re.IGNORECASE)))
        
        # Extract ATT&CK techniques
        entities['attack_techniques'] = list(set(re.findall(r'T\d{4}(?:\.\d{3})?', all_text)))
        
        # Extract vendor names (simple pattern matching)
        vendor_patterns = [
            r'\b(Microsoft|Google|Apple|Adobe|Oracle|IBM|Intel|AMD|NVIDIA)\b',
            r'\b(Cisco|VMware|RedHat|Ubuntu|Debian|CentOS)\b'
        ]
        
        for pattern in vendor_patterns:
            matches = re.findall(pattern, all_text, re.IGNORECASE)
            entities['vendors'].extend([match.lower() for match in matches])
        
        entities['vendors'] = list(set(entities['vendors']))
        
        return entities
    
    def _add_context(self, entry: Dict, indexes: Dict) -> Dict:
        """Add contextual information to the entry."""
        context = {}
        data_type = entry.get('data_type')
        
        # Add statistics about related data
        if data_type == 'cve':
            # Count related CWEs
            cwe_count = len([ref for ref in entry.get('enrichment', {}).get('cross_references', []) 
                           if ref.get('type') == 'cwe_reference'])
            context['related_cwe_count'] = cwe_count
        
        elif data_type == 'cwe':
            # Count related CVEs
            cve_count = len([ref for ref in entry.get('enrichment', {}).get('cross_references', []) 
                           if ref.get('type') == 'cve_reference'])
            context['related_cve_count'] = cve_count
        
        # Add platform coverage statistics
        content = entry.get('content', {})
        platforms = content.get('platforms', [])
        if platforms:
            platform_coverage = {}
            for platform in platforms:
                related_count = len(indexes['platforms'].get(platform.lower(), []))
                platform_coverage[platform] = related_count
            context['platform_coverage'] = platform_coverage
        
        return context
    
    def _get_entry_id(self, entry: Dict) -> str:
        """Get a unique identifier for an entry."""
        identifiers = entry.get('identifiers', {})
        
        # Use primary identifier based on data type
        data_type = entry.get('data_type')
        if data_type == 'cve' and identifiers.get('cve_id'):
            return identifiers['cve_id']
        elif data_type == 'cwe' and identifiers.get('cwe_id'):
            return identifiers['cwe_id']
        elif data_type == 'mitre_attack' and identifiers.get('attack_id'):
            return identifiers['attack_id']
        else:
            # Fallback to source + name/id
            return f"{entry.get('source', 'unknown')}:{identifiers.get('name', 'unknown')}"
    
    def _find_entry_by_id(self, entry_id: str, indexes: Dict) -> Optional[Dict]:
        """Find an entry by its ID in the indexes."""
        # Check each index type
        for index_name, index_data in indexes.items():
            if index_name in ['cve_id', 'cwe_id', 'attack_id', 'technique_id']:
                if entry_id in index_data:
                    return index_data[entry_id]
        
        return None
    
    def get_statistics(self) -> Dict:
        """Get enrichment statistics."""
        return {
            'enriched_count': self.enriched_count,
            'relationships_added': self.relationships_added,
            'avg_relationships_per_entry': self.relationships_added / max(self.enriched_count, 1)
        }