#!/usr/bin/env python3
"""
Data Deduplicator

Handles deduplication and merging of security data entries from multiple sources
based on various identifiers and similarity metrics.
"""

import hashlib
import logging
from typing import Dict, List, Set, Optional, Tuple
from collections import defaultdict
from datetime import datetime


class DataDeduplicator:
    """
    Deduplicates and merges security data entries from multiple sources.
    
    Uses various strategies including exact matching on identifiers,
    content similarity, and intelligent merging of related entries.
    """
    
    def __init__(self, verbose: bool = False):
        """
        Initialize the deduplicator.
        
        Args:
            verbose: Enable verbose logging
        """
        self.logger = logging.getLogger(__name__)
        if verbose:
            self.logger.setLevel(logging.DEBUG)
        
        self.processed_count = 0
        self.duplicate_count = 0
        self.merged_count = 0
    
    def deduplicate_data(self, data_entries: List[Dict], 
                        merge_duplicates: bool = True) -> List[Dict]:
        """
        Deduplicate a list of data entries.
        
        Args:
            data_entries: List of data entries to deduplicate
            merge_duplicates: Whether to merge duplicate entries or just remove them
            
        Returns:
            List of deduplicated entries
        """
        self.logger.info(f"Starting deduplication of {len(data_entries)} entries")
        
        # Group entries by their primary identifiers
        grouped_entries = self._group_by_identifiers(data_entries)
        
        deduplicated_entries = []
        
        for identifier, entries in grouped_entries.items():
            if len(entries) == 1:
                # No duplicates for this identifier
                deduplicated_entries.append(entries[0])
                self.processed_count += 1
            else:
                # Handle duplicates
                self.duplicate_count += len(entries) - 1
                
                if merge_duplicates:
                    merged_entry = self._merge_entries(entries)
                    deduplicated_entries.append(merged_entry)
                    self.merged_count += 1
                else:
                    # Just keep the most recent entry
                    latest_entry = self._get_latest_entry(entries)
                    deduplicated_entries.append(latest_entry)
                
                self.processed_count += 1
        
        self.logger.info(f"Deduplication complete: {len(deduplicated_entries)} unique entries")
        self.logger.info(f"Removed {self.duplicate_count} duplicates, merged {self.merged_count} entries")
        
        return deduplicated_entries
    
    def _group_by_identifiers(self, data_entries: List[Dict]) -> Dict[str, List[Dict]]:
        """Group entries by their primary identifiers."""
        grouped = defaultdict(list)
        
        for entry in data_entries:
            primary_id = self._extract_primary_identifier(entry)
            grouped[primary_id].append(entry)
        
        return dict(grouped)
    
    def _extract_primary_identifier(self, entry: Dict) -> str:
        """
        Extract the primary identifier for an entry.
        
        Uses data type-specific logic to determine the best identifier.
        """
        data_type = entry.get('data_type', 'unknown')
        identifiers = entry.get('identifiers', {})
        
        if data_type == 'cve':
            # Use CVE ID as primary identifier
            return identifiers.get('cve_id', self._generate_content_hash(entry))
        
        elif data_type == 'cwe':
            # Use CWE ID as primary identifier
            return identifiers.get('cwe_id', self._generate_content_hash(entry))
        
        elif data_type == 'mitre_attack':
            # Use ATT&CK ID as primary identifier
            return identifiers.get('attack_id', identifiers.get('technique_id', self._generate_content_hash(entry)))
        
        elif data_type == 'metasploit':
            # Use module path as primary identifier
            return identifiers.get('relative_path', identifiers.get('filepath', self._generate_content_hash(entry)))
        
        else:
            # Fallback to content hash
            return self._generate_content_hash(entry)
    
    def _generate_content_hash(self, entry: Dict) -> str:
        """Generate a hash based on entry content for deduplication."""
        # Create a stable hash based on key content fields
        content = entry.get('content', {})
        
        hash_content = {
            'data_type': entry.get('data_type'),
            'source': entry.get('source'),
        }
        
        # Add content-specific fields for hashing
        if 'description' in content:
            hash_content['description'] = content['description']
        if 'name' in content:
            hash_content['name'] = content['name']
        if 'title' in content:
            hash_content['title'] = content['title']
        
        # Create hash
        hash_string = str(sorted(hash_content.items()))
        return hashlib.md5(hash_string.encode('utf-8')).hexdigest()
    
    def _merge_entries(self, entries: List[Dict]) -> Dict:
        """
        Merge multiple entries with the same identifier.
        
        Combines information from all entries, preferring newer data
        and merging lists/dictionaries intelligently.
        """
        if len(entries) == 1:
            return entries[0]
        
        # Start with the most recent entry as base
        merged_entry = self._get_latest_entry(entries).copy()
        
        # Track sources
        all_sources = set()
        all_harvest_times = []
        
        for entry in entries:
            all_sources.add(entry.get('source', 'unknown'))
            if entry.get('harvested_at'):
                all_harvest_times.append(entry['harvested_at'])
        
        # Update merged entry metadata
        merged_entry['sources'] = list(all_sources)
        merged_entry['harvest_times'] = all_harvest_times
        merged_entry['merged_from_count'] = len(entries)
        merged_entry['merged_at'] = datetime.now().isoformat()
        
        # Merge content from all entries
        merged_content = merged_entry.get('content', {}).copy()
        merged_metadata = merged_entry.get('metadata', {}).copy()
        
        for entry in entries:
            # Merge content
            entry_content = entry.get('content', {})
            for key, value in entry_content.items():
                if key not in merged_content:
                    merged_content[key] = value
                elif isinstance(value, list) and isinstance(merged_content[key], list):
                    # Merge lists, avoiding duplicates
                    merged_content[key] = list(set(merged_content[key] + value))
                elif isinstance(value, dict) and isinstance(merged_content[key], dict):
                    # Merge dictionaries
                    merged_content[key].update(value)
                elif not merged_content[key] and value:
                    # Replace empty values with non-empty ones
                    merged_content[key] = value
            
            # Merge metadata
            entry_metadata = entry.get('metadata', {})
            for key, value in entry_metadata.items():
                if key not in merged_metadata:
                    merged_metadata[key] = value
                elif isinstance(value, list) and isinstance(merged_metadata[key], list):
                    merged_metadata[key] = list(set(merged_metadata[key] + value))
                elif isinstance(value, dict) and isinstance(merged_metadata[key], dict):
                    merged_metadata[key].update(value)
        
        merged_entry['content'] = merged_content
        merged_entry['metadata'] = merged_metadata
        
        return merged_entry
    
    def _get_latest_entry(self, entries: List[Dict]) -> Dict:
        """Get the most recently harvested entry from a list."""
        latest_entry = entries[0]
        latest_time = latest_entry.get('harvested_at', '')
        
        for entry in entries[1:]:
            harvest_time = entry.get('harvested_at', '')
            if harvest_time > latest_time:
                latest_entry = entry
                latest_time = harvest_time
        
        return latest_entry
    
    def find_similar_entries(self, data_entries: List[Dict], 
                           similarity_threshold: float = 0.8) -> List[Tuple[Dict, Dict, float]]:
        """
        Find pairs of entries that are similar but not exact duplicates.
        
        Args:
            data_entries: List of entries to analyze
            similarity_threshold: Minimum similarity score to consider as similar
            
        Returns:
            List of tuples (entry1, entry2, similarity_score)
        """
        similar_pairs = []
        
        for i, entry1 in enumerate(data_entries):
            for entry2 in data_entries[i+1:]:
                similarity = self._calculate_similarity(entry1, entry2)
                if similarity >= similarity_threshold:
                    similar_pairs.append((entry1, entry2, similarity))
        
        return similar_pairs
    
    def _calculate_similarity(self, entry1: Dict, entry2: Dict) -> float:
        """
        Calculate similarity score between two entries.
        
        Returns a score between 0.0 and 1.0.
        """
        # Simple similarity based on text content
        content1 = self._extract_text_content(entry1)
        content2 = self._extract_text_content(entry2)
        
        if not content1 or not content2:
            return 0.0
        
        # Use Jaccard similarity on word sets
        words1 = set(content1.lower().split())
        words2 = set(content2.lower().split())
        
        intersection = len(words1.intersection(words2))
        union = len(words1.union(words2))
        
        return intersection / union if union > 0 else 0.0
    
    def _extract_text_content(self, entry: Dict) -> str:
        """Extract text content from an entry for similarity comparison."""
        content = entry.get('content', {})
        text_parts = []
        
        # Extract various text fields
        for field in ['description', 'name', 'title', 'summary']:
            if field in content and content[field]:
                text_parts.append(str(content[field]))
        
        return ' '.join(text_parts)
    
    def get_statistics(self) -> Dict:
        """Get deduplication statistics."""
        return {
            'processed_count': self.processed_count,
            'duplicate_count': self.duplicate_count,
            'merged_count': self.merged_count,
            'deduplication_rate': (self.duplicate_count / max(self.processed_count + self.duplicate_count, 1)) * 100
        }