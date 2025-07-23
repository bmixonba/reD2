#!/usr/bin/env python3
"""
MITRE ATT&CK Data Harvester

Harvests MITRE ATT&CK framework data including tactics, techniques, procedures,
and associated metadata for threat intelligence and security training.
"""

import requests
import json
from typing import Dict, List, Optional
from .base_harvester import BaseHarvester


class MITREAttackHarvester(BaseHarvester):
    """
    Harvester for MITRE ATT&CK framework data.
    
    Collects tactics, techniques, procedures, mitigations,
    and threat group information.
    """
    
    def __init__(self, rate_limit: float = 1.0, verbose: bool = False):
        """
        Initialize MITRE ATT&CK harvester.
        
        Args:
            rate_limit: Minimum time between requests
            verbose: Enable verbose logging
        """
        super().__init__("MITRE_ATTACK", rate_limit, verbose)
        # MITRE ATT&CK data is available as STIX bundles
        self.attack_data_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        
        # Sample ATT&CK data for demonstration
        self.sample_attack_data = self._load_sample_attack_data()
    
    def get_data_type(self) -> str:
        """Return the type of data this harvester collects."""
        return "mitre_attack"
    
    def _load_sample_attack_data(self) -> List[Dict]:
        """Load sample MITRE ATT&CK data for demonstration purposes."""
        return [
            {
                'type': 'attack-pattern',
                'id': 'attack-pattern--0f20e3cb-245b-4a61-8a91-2d93f7cb0e9b',
                'name': 'Spearphishing Link',
                'technique_id': 'T1566.002',
                'tactic': 'initial-access',
                'description': 'Adversaries may send spearphishing emails with a malicious link in an attempt to gain access to victim systems.',
                'platforms': ['Linux', 'macOS', 'Windows'],
                'kill_chain_phases': [
                    {'kill_chain_name': 'mitre-attack', 'phase_name': 'initial-access'}
                ],
                'mitigations': [
                    'Anti-virus/anti-malware',
                    'User training',
                    'Email filtering'
                ],
                'detection': 'URL inspection within email, monitoring for suspicious network traffic',
                'references': [
                    'https://attack.mitre.org/techniques/T1566/002/',
                    'https://capec.mitre.org/data/definitions/163.html'
                ]
            },
            {
                'type': 'attack-pattern',
                'id': 'attack-pattern--1c4e5d32-1fe9-4116-9d9d-59e3925bd6a2',
                'name': 'PowerShell',
                'technique_id': 'T1059.001',
                'tactic': 'execution',
                'description': 'Adversaries may abuse PowerShell commands and scripts for execution.',
                'platforms': ['Windows'],
                'kill_chain_phases': [
                    {'kill_chain_name': 'mitre-attack', 'phase_name': 'execution'}
                ],
                'mitigations': [
                    'Execution Prevention',
                    'Privileged Account Management',
                    'Code Signing'
                ],
                'detection': 'PowerShell logging, command line monitoring, script block logging',
                'references': [
                    'https://attack.mitre.org/techniques/T1059/001/',
                    'https://docs.microsoft.com/en-us/powershell/scripting/security/jea/overview'
                ]
            },
            {
                'type': 'intrusion-set',
                'id': 'intrusion-set--f40eb8ce-2a74-4e56-89a1-227021410142',
                'name': 'APT29',
                'aliases': ['Cozy Bear', 'The Dukes'],
                'description': 'APT29 is threat group that has been attributed to Russia\'s Foreign Intelligence Service.',
                'country': 'Russia',
                'first_seen': '2008',
                'techniques_used': ['T1566.002', 'T1059.001', 'T1055'],
                'targets': ['Government', 'Healthcare', 'Energy'],
                'references': [
                    'https://attack.mitre.org/groups/G0016/',
                    'https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html'
                ]
            },
            {
                'type': 'course-of-action',
                'id': 'course-of-action--2a4f6c11-a4a7-4cb9-b0ef-6ae1bb3a718a',
                'name': 'User Training',
                'description': 'Train users to be aware of access or manipulation attempts by an adversary to reduce the risk of successful spearphishing, social engineering, and other techniques.',
                'mitigates': ['T1566.002', 'T1566.001', 'T1204'],
                'references': [
                    'https://attack.mitre.org/mitigations/M1017/'
                ]
            }
        ]
    
    def _extract_identifiers(self, raw_data: Dict) -> Dict:
        """Extract ATT&CK identifiers."""
        identifiers = {
            'attack_id': raw_data.get('id'),
            'name': raw_data.get('name'),
            'type': raw_data.get('type')
        }
        
        # Add technique-specific identifiers
        if raw_data.get('technique_id'):
            identifiers['technique_id'] = raw_data['technique_id']
        
        # Add tactic information
        if raw_data.get('tactic'):
            identifiers['tactic'] = raw_data['tactic']
        
        return identifiers
    
    def _extract_content(self, raw_data: Dict) -> Dict:
        """Extract main ATT&CK content."""
        content = {
            'description': raw_data.get('description', ''),
            'references': raw_data.get('references', [])
        }
        
        # Type-specific content extraction
        if raw_data.get('type') == 'attack-pattern':
            content.update({
                'platforms': raw_data.get('platforms', []),
                'kill_chain_phases': raw_data.get('kill_chain_phases', []),
                'mitigations': raw_data.get('mitigations', []),
                'detection': raw_data.get('detection', '')
            })
        elif raw_data.get('type') == 'intrusion-set':
            content.update({
                'aliases': raw_data.get('aliases', []),
                'country': raw_data.get('country'),
                'first_seen': raw_data.get('first_seen'),
                'techniques_used': raw_data.get('techniques_used', []),
                'targets': raw_data.get('targets', [])
            })
        elif raw_data.get('type') == 'course-of-action':
            content.update({
                'mitigates': raw_data.get('mitigates', [])
            })
        
        return content
    
    def _extract_metadata(self, raw_data: Dict) -> Dict:
        """Extract ATT&CK metadata."""
        metadata = {
            'object_type': raw_data.get('type'),
            'last_modified': raw_data.get('modified'),
            'created': raw_data.get('created'),
            'version': raw_data.get('x_mitre_version'),
            'deprecated': raw_data.get('x_mitre_deprecated', False)
        }
        
        # Add technique-specific metadata
        if raw_data.get('type') == 'attack-pattern':
            metadata.update({
                'data_sources': raw_data.get('x_mitre_data_sources', []),
                'defense_bypassed': raw_data.get('x_mitre_defense_bypassed', []),
                'permissions_required': raw_data.get('x_mitre_permissions_required', []),
                'system_requirements': raw_data.get('x_mitre_system_requirements', [])
            })
        
        return metadata
    
    def harvest(self, limit: Optional[int] = None, 
                object_types: Optional[List[str]] = None,
                tactics: Optional[List[str]] = None) -> List[Dict]:
        """
        Harvest MITRE ATT&CK data.
        
        Args:
            limit: Maximum number of objects to harvest
            object_types: Types of objects to harvest ('attack-pattern', 'intrusion-set', 'course-of-action')
            tactics: Specific tactics to filter by
            
        Returns:
            List of standardized ATT&CK entries
        """
        self.logger.info(f"Starting MITRE ATT&CK harvest (limit: {limit})")
        
        # TODO: In a real implementation, this would:
        # 1. Download the STIX bundle from MITRE's CTI repository
        # 2. Parse the JSON/STIX data
        # 3. Filter and convert to standardized format
        
        # For now, use sample data
        harvested_data = []
        
        source_data = self.sample_attack_data
        
        # Filter by object types
        if object_types:
            source_data = [obj for obj in source_data if obj.get('type') in object_types]
        
        # Filter by tactics
        if tactics:
            source_data = [obj for obj in source_data 
                          if obj.get('tactic') in tactics or 
                          any(phase.get('phase_name') in tactics 
                              for phase in obj.get('kill_chain_phases', []))]
        
        if limit:
            source_data = source_data[:limit]
        
        for attack_data in source_data:
            try:
                standardized_entry = self._standardize_entry(attack_data)
                harvested_data.append(standardized_entry)
                self.harvested_count += 1
                
            except Exception as e:
                self.logger.warning(f"Error processing ATT&CK object {attack_data.get('id', 'unknown')}: {e}")
                self.error_count += 1
                continue
        
        self.logger.info(f"MITRE ATT&CK harvest complete. Collected {len(harvested_data)} objects")
        return harvested_data
    
    def harvest_techniques(self, tactics: Optional[List[str]] = None, limit: Optional[int] = None) -> List[Dict]:
        """
        Harvest ATT&CK techniques.
        
        Args:
            tactics: Specific tactics to filter by
            limit: Maximum number of techniques to harvest
            
        Returns:
            List of technique entries
        """
        return self.harvest(
            limit=limit,
            object_types=['attack-pattern'],
            tactics=tactics
        )
    
    def harvest_threat_groups(self, limit: Optional[int] = None) -> List[Dict]:
        """
        Harvest ATT&CK threat groups (intrusion sets).
        
        Args:
            limit: Maximum number of groups to harvest
            
        Returns:
            List of threat group entries
        """
        return self.harvest(
            limit=limit,
            object_types=['intrusion-set']
        )
    
    def harvest_mitigations(self, limit: Optional[int] = None) -> List[Dict]:
        """
        Harvest ATT&CK mitigations.
        
        Args:
            limit: Maximum number of mitigations to harvest
            
        Returns:
            List of mitigation entries
        """
        return self.harvest(
            limit=limit,
            object_types=['course-of-action']
        )
    
    def download_attack_data(self, output_path: str = None) -> str:
        """
        Download the latest ATT&CK STIX data from MITRE's CTI repository.
        
        Args:
            output_path: Path to save the JSON file
            
        Returns:
            Path to the downloaded file
        """
        # TODO: Implement actual download functionality
        # This is a placeholder for the real implementation
        
        self.logger.info("TODO: Implement ATT&CK data download from MITRE CTI")
        self.logger.info(f"Would download from: {self.attack_data_url}")
        
        if output_path:
            self.logger.info(f"Would save to: {output_path}")
            return output_path
        else:
            return "/tmp/enterprise-attack.json"
    
    def get_technique_by_id(self, technique_id: str) -> Optional[Dict]:
        """
        Get a specific technique by its ID.
        
        Args:
            technique_id: ATT&CK technique ID (e.g., 'T1566.002')
            
        Returns:
            Technique data or None if not found
        """
        for obj in self.sample_attack_data:
            if obj.get('technique_id') == technique_id:
                return self._standardize_entry(obj)
        
        return None