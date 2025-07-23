#!/usr/bin/env python3
"""
CVE Data Harvester

Harvests CVE (Common Vulnerabilities and Exposures) data from the NVD (National Vulnerability Database) API.
Includes vulnerability details, CVSS scores, references, and associated metadata.
"""

import requests
import time
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from .base_harvester import BaseHarvester


class CVEHarvester(BaseHarvester):
    """
    Harvester for CVE data from NVD API.
    
    Collects CVE details including descriptions, CVSS scores, references,
    vendor advisories, and associated metadata.
    """
    
    def __init__(self, api_key: Optional[str] = None, rate_limit: float = 0.6, verbose: bool = False):
        """
        Initialize CVE harvester.
        
        Args:
            api_key: NVD API key (optional, but recommended for higher rate limits)
            rate_limit: Minimum time between requests (0.6s default for public access)
            verbose: Enable verbose logging
        """
        super().__init__("NVD_CVE", rate_limit, verbose)
        self.api_key = api_key
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        # Adjust rate limit based on API key
        if api_key:
            self.rate_limit = 0.1  # 10 requests per second with API key
        
        self.session = requests.Session()
        if api_key:
            self.session.headers.update({'apiKey': api_key})
    
    def get_data_type(self) -> str:
        """Return the type of data this harvester collects."""
        return "cve"
    
    def _extract_identifiers(self, raw_data: Dict) -> Dict:
        """Extract CVE identifiers."""
        cve_data = raw_data.get('cve', {})
        return {
            'cve_id': cve_data.get('id'),
            'source_identifier': cve_data.get('sourceIdentifier'),
            'published': cve_data.get('published'),
            'last_modified': cve_data.get('lastModified')
        }
    
    def _extract_content(self, raw_data: Dict) -> Dict:
        """Extract main CVE content."""
        cve_data = raw_data.get('cve', {})
        
        # Extract descriptions
        descriptions = {}
        for desc in cve_data.get('descriptions', []):
            lang = desc.get('lang', 'en')
            descriptions[lang] = desc.get('value', '')
        
        # Extract problem types (CWE)
        problem_types = []
        for problem_type in cve_data.get('problemTypes', []):
            for desc in problem_type.get('descriptions', []):
                problem_types.append({
                    'cwe_id': desc.get('cweId'),
                    'description': desc.get('description'),
                    'lang': desc.get('lang', 'en')
                })
        
        # Extract references
        references = []
        for ref in cve_data.get('references', []):
            references.append({
                'url': ref.get('url'),
                'source': ref.get('source'),
                'tags': ref.get('tags', [])
            })
        
        return {
            'descriptions': descriptions,
            'problem_types': problem_types,
            'references': references
        }
    
    def _extract_metadata(self, raw_data: Dict) -> Dict:
        """Extract CVE metadata including CVSS scores and impact."""
        cve_data = raw_data.get('cve', {})
        
        # Extract CVSS scores
        cvss_scores = {}
        metrics = cve_data.get('metrics', {})
        
        # CVSS v3.1
        if 'cvssMetricV31' in metrics:
            for metric in metrics['cvssMetricV31']:
                cvss_data = metric.get('cvssData', {})
                cvss_scores['v3.1'] = {
                    'baseScore': cvss_data.get('baseScore'),
                    'baseSeverity': cvss_data.get('baseSeverity'),
                    'vectorString': cvss_data.get('vectorString'),
                    'impactScore': metric.get('impactScore'),
                    'exploitabilityScore': metric.get('exploitabilityScore')
                }
        
        # CVSS v3.0
        if 'cvssMetricV30' in metrics:
            for metric in metrics['cvssMetricV30']:
                cvss_data = metric.get('cvssData', {})
                cvss_scores['v3.0'] = {
                    'baseScore': cvss_data.get('baseScore'),
                    'baseSeverity': cvss_data.get('baseSeverity'),
                    'vectorString': cvss_data.get('vectorString'),
                    'impactScore': metric.get('impactScore'),
                    'exploitabilityScore': metric.get('exploitabilityScore')
                }
        
        # CVSS v2.0
        if 'cvssMetricV2' in metrics:
            for metric in metrics['cvssMetricV2']:
                cvss_data = metric.get('cvssData', {})
                cvss_scores['v2.0'] = {
                    'baseScore': cvss_data.get('baseScore'),
                    'baseSeverity': cvss_data.get('baseSeverity'),
                    'vectorString': cvss_data.get('vectorString'),
                    'impactScore': metric.get('impactScore'),
                    'exploitabilityScore': metric.get('exploitabilityScore')
                }
        
        # Extract vendor comments
        vendor_comments = []
        for comment in cve_data.get('vendorComments', []):
            vendor_comments.append({
                'organization': comment.get('organization'),
                'comment': comment.get('comment'),
                'last_modified': comment.get('lastModified')
            })
        
        return {
            'cvss_scores': cvss_scores,
            'vendor_comments': vendor_comments,
            'vuln_status': cve_data.get('vulnStatus'),
            'evaluator_comment': cve_data.get('evaluatorComment'),
            'evaluator_solution': cve_data.get('evaluatorSolution'),
            'evaluator_impact': cve_data.get('evaluatorImpact')
        }
    
    def harvest(self, limit: Optional[int] = None, 
                start_date: Optional[str] = None,
                end_date: Optional[str] = None,
                keyword_search: Optional[str] = None,
                cwe_id: Optional[str] = None) -> List[Dict]:
        """
        Harvest CVE data from NVD API.
        
        Args:
            limit: Maximum number of CVEs to harvest
            start_date: Start date for vulnerability publication (YYYY-MM-DD)
            end_date: End date for vulnerability publication (YYYY-MM-DD)
            keyword_search: Keyword to search in CVE descriptions
            cwe_id: Filter by specific CWE ID
            
        Returns:
            List of standardized CVE entries
        """
        self.logger.info(f"Starting CVE harvest (limit: {limit})")
        
        harvested_data = []
        start_index = 0
        results_per_page = 20  # NVD API limit
        
        while True:
            if limit and len(harvested_data) >= limit:
                break
            
            # Build API parameters
            params = {
                'startIndex': start_index,
                'resultsPerPage': min(results_per_page, limit - len(harvested_data) if limit else results_per_page)
            }
            
            if start_date:
                params['pubStartDate'] = f"{start_date}T00:00:00.000"
            if end_date:
                params['pubEndDate'] = f"{end_date}T23:59:59.999"
            if keyword_search:
                params['keywordSearch'] = keyword_search
            if cwe_id:
                params['cweId'] = cwe_id
            
            try:
                self._rate_limit_check()
                
                self.logger.debug(f"Requesting CVEs starting at index {start_index}")
                response = self.session.get(self.base_url, params=params, timeout=30)
                response.raise_for_status()
                
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])
                
                if not vulnerabilities:
                    self.logger.info("No more CVEs available")
                    break
                
                # Process each CVE
                for vuln in vulnerabilities:
                    try:
                        standardized_entry = self._standardize_entry(vuln)
                        harvested_data.append(standardized_entry)
                        self.harvested_count += 1
                        
                        if self.harvested_count % 100 == 0:
                            self.logger.info(f"Harvested {self.harvested_count} CVEs...")
                            
                    except Exception as e:
                        self.logger.warning(f"Error processing CVE: {e}")
                        self.error_count += 1
                        continue
                
                # Check if we have more results
                total_results = data.get('totalResults', 0)
                if start_index + len(vulnerabilities) >= total_results:
                    self.logger.info("Reached end of available CVEs")
                    break
                
                start_index += len(vulnerabilities)
                
            except requests.RequestException as e:
                self.logger.error(f"API request failed: {e}")
                self.error_count += 1
                
                # Exponential backoff on error
                time.sleep(min(self.rate_limit * 2, 10))
                continue
            
            except Exception as e:
                self.logger.error(f"Unexpected error: {e}")
                self.error_count += 1
                break
        
        self.logger.info(f"CVE harvest complete. Collected {len(harvested_data)} CVEs")
        return harvested_data
    
    def harvest_recent_cves(self, days: int = 30, limit: Optional[int] = None) -> List[Dict]:
        """
        Harvest CVEs published in the last N days.
        
        Args:
            days: Number of days back to search
            limit: Maximum number of CVEs to harvest
            
        Returns:
            List of recent CVE entries
        """
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        return self.harvest(
            limit=limit,
            start_date=start_date.strftime('%Y-%m-%d'),
            end_date=end_date.strftime('%Y-%m-%d')
        )
    
    def harvest_by_keyword(self, keywords: List[str], limit: Optional[int] = None) -> List[Dict]:
        """
        Harvest CVEs by searching for specific keywords.
        
        Args:
            keywords: List of keywords to search for
            limit: Maximum number of CVEs per keyword
            
        Returns:
            List of CVE entries matching keywords
        """
        all_cves = []
        per_keyword_limit = limit // len(keywords) if limit else None
        
        for keyword in keywords:
            self.logger.info(f"Searching CVEs for keyword: {keyword}")
            cves = self.harvest(
                limit=per_keyword_limit,
                keyword_search=keyword
            )
            all_cves.extend(cves)
        
        return all_cves