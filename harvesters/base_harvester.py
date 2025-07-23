#!/usr/bin/env python3
"""
Base Harvester Class

Provides a common interface and shared functionality for all security data harvesters.
"""

import logging
import json
import time
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path


class BaseHarvester(ABC):
    """
    Abstract base class for all security data harvesters.
    
    Provides common functionality like rate limiting, error handling,
    data validation, and standardized output format.
    """
    
    def __init__(self, name: str, rate_limit: float = 1.0, verbose: bool = False):
        """
        Initialize the harvester.
        
        Args:
            name: Name of the harvester for logging
            rate_limit: Minimum time between requests (seconds)
            verbose: Enable verbose logging
        """
        self.name = name
        self.rate_limit = rate_limit
        self.last_request_time = 0
        self.harvested_count = 0
        self.error_count = 0
        
        # Setup logging
        self.logger = logging.getLogger(f"{__name__}.{name}")
        if verbose:
            self.logger.setLevel(logging.DEBUG)
        
    def _rate_limit_check(self):
        """Enforce rate limiting between requests."""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.rate_limit:
            sleep_time = self.rate_limit - time_since_last
            self.logger.debug(f"Rate limiting: sleeping for {sleep_time:.2f} seconds")
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    def _standardize_entry(self, raw_data: Dict) -> Dict:
        """
        Standardize a raw data entry into our common format.
        
        Args:
            raw_data: Raw data from the source
            
        Returns:
            Standardized data entry
        """
        entry = {
            'source': self.name,
            'harvested_at': datetime.now().isoformat(),
            'raw_data': raw_data,
            'data_type': self.get_data_type(),
            'identifiers': self._extract_identifiers(raw_data),
            'content': self._extract_content(raw_data),
            'metadata': self._extract_metadata(raw_data)
        }
        
        return entry
    
    @abstractmethod
    def get_data_type(self) -> str:
        """Return the type of data this harvester collects."""
        pass
    
    @abstractmethod
    def _extract_identifiers(self, raw_data: Dict) -> Dict:
        """Extract unique identifiers from raw data."""
        pass
    
    @abstractmethod
    def _extract_content(self, raw_data: Dict) -> Dict:
        """Extract main content from raw data."""
        pass
    
    @abstractmethod
    def _extract_metadata(self, raw_data: Dict) -> Dict:
        """Extract metadata from raw data."""
        pass
    
    @abstractmethod
    def harvest(self, limit: Optional[int] = None, **kwargs) -> List[Dict]:
        """
        Harvest data from the source.
        
        Args:
            limit: Maximum number of entries to harvest
            **kwargs: Additional parameters specific to the harvester
            
        Returns:
            List of standardized data entries
        """
        pass
    
    def save_data(self, data: List[Dict], output_path: str, format: str = 'jsonl'):
        """
        Save harvested data to file.
        
        Args:
            data: List of data entries to save
            output_path: Path to save the data
            format: Output format ('jsonl' or 'json')
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.logger.info(f"Saving {len(data)} entries to {output_path}")
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                if format == 'jsonl':
                    for entry in data:
                        f.write(json.dumps(entry, ensure_ascii=False) + '\n')
                else:  # json
                    json.dump(data, f, ensure_ascii=False, indent=2)
                    
            self.logger.info(f"Data saved successfully to {output_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to save data: {e}")
            raise
    
    def get_statistics(self) -> Dict:
        """Get harvesting statistics."""
        return {
            'harvester': self.name,
            'data_type': self.get_data_type(),
            'harvested_count': self.harvested_count,
            'error_count': self.error_count,
            'success_rate': (self.harvested_count / max(self.harvested_count + self.error_count, 1)) * 100
        }