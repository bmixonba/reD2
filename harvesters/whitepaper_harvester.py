#!/usr/bin/env python3
"""
White Papers and Security Research Harvester

Harvester for collecting security white papers, research documents, and technical
reports from various sources. Includes PDF parsing capabilities and metadata extraction.
"""

import requests
import os
import tempfile
from typing import Dict, List, Optional
from pathlib import Path
from .base_harvester import BaseHarvester

# Optional PDF parsing - graceful fallback if not available
try:
    import PyPDF2
    import pdfplumber
    PDF_PARSING_AVAILABLE = True
except ImportError:
    PDF_PARSING_AVAILABLE = False


class WhitepaperHarvester(BaseHarvester):
    """
    Harvester for security white papers and research documents.
    
    Collects and processes security research papers, technical reports,
    and vendor white papers with PDF parsing capabilities.
    """
    
    def __init__(self, rate_limit: float = 2.0, verbose: bool = False):
        """
        Initialize whitepaper harvester.
        
        Args:
            rate_limit: Minimum time between requests
            verbose: Enable verbose logging
        """
        super().__init__("SECURITY_WHITEPAPERS", rate_limit, verbose)
        
        # Common sources for security white papers
        self.sources = {
            'sans': 'https://www.sans.org/white-papers/',
            'nist': 'https://csrc.nist.gov/publications',
            'owasp': 'https://owasp.org/www-project-top-ten/',
            'mitre': 'https://www.mitre.org/publications',
            # Add more legitimate sources
        }
        
        # Sample white paper data for demonstration
        self.sample_papers = self._load_sample_papers()
    
    def get_data_type(self) -> str:
        """Return the type of data this harvester collects."""
        return "security_whitepaper"
    
    def _load_sample_papers(self) -> List[Dict]:
        """Load sample white paper data for demonstration."""
        return [
            {
                'id': 'WP-2024-001',
                'title': 'Advanced Persistent Threats: Detection and Mitigation Strategies',
                'authors': ['Dr. Security Expert', 'Jane Researcher'],
                'organization': 'Security Research Institute',
                'publication_date': '2024-01-15',
                'document_type': 'Research Paper',
                'url': 'https://example.com/papers/apt-detection-2024.pdf',
                'abstract': 'This paper presents comprehensive strategies for detecting and mitigating Advanced Persistent Threats (APTs) in enterprise environments. We analyze common APT tactics, techniques, and procedures (TTPs) and propose a multi-layered defense approach.',
                'keywords': ['APT', 'threat detection', 'cybersecurity', 'enterprise security'],
                'topics': ['Threat Intelligence', 'Incident Response', 'Network Security'],
                'pages': 45,
                'language': 'English',
                'access_level': 'Public',
                'citations': 156,
                'related_frameworks': ['MITRE ATT&CK', 'NIST Cybersecurity Framework'],
                'content_summary': 'Comprehensive analysis of APT detection methodologies with practical implementation guidance.',
                'key_findings': [
                    'Behavioral analysis is more effective than signature-based detection',
                    'Integration of threat intelligence improves detection accuracy by 40%',
                    'Multi-layer defense reduces APT dwell time significantly'
                ]
            },
            {
                'id': 'WP-2024-002',
                'title': 'Zero Trust Architecture Implementation Guide',
                'authors': ['Security Architect Team'],
                'organization': 'NIST',
                'publication_date': '2024-02-01',
                'document_type': 'Technical Guide',
                'url': 'https://example.com/nist/zero-trust-guide.pdf',
                'abstract': 'This guide provides practical implementation steps for Zero Trust Architecture in enterprise environments, including technology recommendations and migration strategies.',
                'keywords': ['zero trust', 'network security', 'identity management', 'access control'],
                'topics': ['Network Architecture', 'Identity Management', 'Access Control'],
                'pages': 89,
                'language': 'English',
                'access_level': 'Public',
                'citations': 89,
                'related_frameworks': ['NIST SP 800-207', 'NIST Cybersecurity Framework'],
                'content_summary': 'Detailed implementation guidance for Zero Trust Architecture with real-world case studies.',
                'key_findings': [
                    'Identity verification is the cornerstone of Zero Trust',
                    'Micro-segmentation reduces attack surface by 60%',
                    'Continuous monitoring is essential for Zero Trust effectiveness'
                ]
            }
        ]
    
    def _extract_identifiers(self, raw_data: Dict) -> Dict:
        """Extract whitepaper identifiers."""
        return {
            'paper_id': raw_data.get('id'),
            'title': raw_data.get('title'),
            'authors': raw_data.get('authors', []),
            'organization': raw_data.get('organization'),
            'publication_date': raw_data.get('publication_date'),
            'url': raw_data.get('url')
        }
    
    def _extract_content(self, raw_data: Dict) -> Dict:
        """Extract main whitepaper content."""
        return {
            'abstract': raw_data.get('abstract', ''),
            'content_summary': raw_data.get('content_summary', ''),
            'key_findings': raw_data.get('key_findings', []),
            'keywords': raw_data.get('keywords', []),
            'topics': raw_data.get('topics', []),
            'related_frameworks': raw_data.get('related_frameworks', []),
            'full_text': raw_data.get('full_text', ''),  # If extracted from PDF
            'sections': raw_data.get('sections', [])     # If parsed from PDF
        }
    
    def _extract_metadata(self, raw_data: Dict) -> Dict:
        """Extract whitepaper metadata."""
        return {
            'document_type': raw_data.get('document_type'),
            'pages': raw_data.get('pages'),
            'language': raw_data.get('language', 'English'),
            'access_level': raw_data.get('access_level', 'Unknown'),
            'citations': raw_data.get('citations', 0),
            'file_format': raw_data.get('file_format', 'PDF'),
            'file_size': raw_data.get('file_size'),
            'checksum': raw_data.get('checksum'),
            'download_date': raw_data.get('download_date')
        }
    
    def harvest(self, limit: Optional[int] = None, 
                topics: Optional[List[str]] = None,
                organizations: Optional[List[str]] = None) -> List[Dict]:
        """
        Harvest security white papers and research documents.
        
        Args:
            limit: Maximum number of papers to harvest
            topics: Filter by specific topics
            organizations: Filter by specific organizations
            
        Returns:
            List of standardized whitepaper entries
        """
        self.logger.info(f"Starting security whitepaper harvest (limit: {limit})")
        
        # TODO: In a real implementation, this would:
        # 1. Search various academic and industry databases
        # 2. Download and parse PDF documents
        # 3. Extract metadata and content
        # 4. Handle different document formats
        
        # For now, use sample data
        harvested_data = []
        
        source_data = self.sample_papers
        
        # Filter by topics
        if topics:
            source_data = [paper for paper in source_data 
                          if any(topic.lower() in [t.lower() for t in paper.get('topics', [])] 
                                for topic in topics)]
        
        # Filter by organizations
        if organizations:
            source_data = [paper for paper in source_data 
                          if paper.get('organization', '').lower() in [org.lower() for org in organizations]]
        
        if limit:
            source_data = source_data[:limit]
        
        for paper_data in source_data:
            try:
                standardized_entry = self._standardize_entry(paper_data)
                harvested_data.append(standardized_entry)
                self.harvested_count += 1
                
            except Exception as e:
                self.logger.warning(f"Error processing paper {paper_data.get('id', 'unknown')}: {e}")
                self.error_count += 1
                continue
        
        self.logger.info(f"Whitepaper harvest complete. Collected {len(harvested_data)} papers")
        return harvested_data
    
    def download_and_parse_pdf(self, url: str, output_dir: Optional[str] = None) -> Optional[Dict]:
        """
        Download and parse a PDF document.
        
        Args:
            url: URL of the PDF document
            output_dir: Directory to save downloaded PDFs (optional)
            
        Returns:
            Parsed document data or None if failed
        """
        if not PDF_PARSING_AVAILABLE:
            self.logger.warning("PDF parsing libraries not available. Install PyPDF2 and pdfplumber for PDF support.")
            return None
        
        try:
            self._rate_limit_check()
            
            self.logger.debug(f"Downloading PDF from {url}")
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            # Save to temporary file or specified directory
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
                filename = os.path.basename(url) or 'document.pdf'
                pdf_path = os.path.join(output_dir, filename)
            else:
                temp_file = tempfile.NamedTemporaryFile(suffix='.pdf', delete=False)
                pdf_path = temp_file.name
                temp_file.close()
            
            with open(pdf_path, 'wb') as f:
                f.write(response.content)
            
            # Parse PDF content
            parsed_data = self._parse_pdf_content(pdf_path)
            parsed_data['url'] = url
            parsed_data['local_path'] = pdf_path
            parsed_data['download_date'] = datetime.now().isoformat()
            parsed_data['file_size'] = len(response.content)
            
            return parsed_data
            
        except Exception as e:
            self.logger.error(f"Failed to download/parse PDF from {url}: {e}")
            return None
    
    def _parse_pdf_content(self, pdf_path: str) -> Dict:
        """Parse content from a PDF file."""
        if not PDF_PARSING_AVAILABLE:
            return {'error': 'PDF parsing not available'}
        
        parsed_data = {
            'full_text': '',
            'sections': [],
            'pages': 0,
            'metadata': {}
        }
        
        try:
            # Extract basic metadata and text with PyPDF2
            with open(pdf_path, 'rb') as f:
                pdf_reader = PyPDF2.PdfReader(f)
                parsed_data['pages'] = len(pdf_reader.pages)
                
                # Extract metadata
                if pdf_reader.metadata:
                    parsed_data['metadata'] = {
                        'title': pdf_reader.metadata.get('/Title', ''),
                        'author': pdf_reader.metadata.get('/Author', ''),
                        'subject': pdf_reader.metadata.get('/Subject', ''),
                        'creator': pdf_reader.metadata.get('/Creator', ''),
                        'creation_date': str(pdf_reader.metadata.get('/CreationDate', '')),
                        'modification_date': str(pdf_reader.metadata.get('/ModDate', ''))
                    }
                
                # Extract text from all pages
                text_content = []
                for page_num, page in enumerate(pdf_reader.pages):
                    try:
                        page_text = page.extract_text()
                        if page_text.strip():
                            text_content.append(page_text)
                    except Exception as e:
                        self.logger.warning(f"Failed to extract text from page {page_num}: {e}")
                
                parsed_data['full_text'] = '\n'.join(text_content)
            
            # Enhanced extraction with pdfplumber (better for structured content)
            try:
                with pdfplumber.open(pdf_path) as pdf:
                    sections = []
                    for page_num, page in enumerate(pdf.pages):
                        page_text = page.extract_text()
                        if page_text:
                            # Simple section detection based on headers
                            lines = page_text.split('\n')
                            current_section = {
                                'page': page_num + 1,
                                'content': page_text,
                                'tables': [],
                                'figures': []
                            }
                            
                            # Extract tables if present
                            tables = page.extract_tables()
                            if tables:
                                current_section['tables'] = tables
                            
                            sections.append(current_section)
                    
                    parsed_data['sections'] = sections
                    
            except Exception as e:
                self.logger.warning(f"Enhanced PDF parsing failed: {e}")
        
        except Exception as e:
            self.logger.error(f"PDF parsing failed: {e}")
            parsed_data['error'] = str(e)
        
        return parsed_data
    
    def search_academic_databases(self, query: str, databases: List[str] = None, 
                                limit: Optional[int] = None) -> List[Dict]:
        """
        Search academic databases for security research papers.
        
        Args:
            query: Search query
            databases: List of databases to search
            limit: Maximum number of results
            
        Returns:
            List of found papers (metadata only)
        """
        # TODO: Implement academic database search
        # This would integrate with APIs from:
        # - arXiv (for preprints)
        # - IEEE Xplore
        # - ACM Digital Library  
        # - Google Scholar (via unofficial APIs)
        # - DBLP
        
        self.logger.info("TODO: Implement academic database search")
        self.logger.info(f"Would search for: {query}")
        if databases:
            self.logger.info(f"In databases: {databases}")
        
        return []
    
    def harvest_vendor_papers(self, vendors: List[str], limit: Optional[int] = None) -> List[Dict]:
        """
        Harvest white papers from security vendors.
        
        Args:
            vendors: List of vendor names/domains
            limit: Maximum number of papers per vendor
            
        Returns:
            List of vendor white papers
        """
        # TODO: Implement vendor paper harvesting
        # This would scrape white paper sections from vendor websites:
        # - Palo Alto Networks Research
        # - FireEye/Mandiant Reports
        # - Symantec Security Response
        # - McAfee Labs
        # - Kaspersky Research
        
        harvested_data = []
        
        for vendor in vendors:
            self.logger.info(f"TODO: Harvest papers from {vendor}")
            # Placeholder for vendor-specific harvesting logic
        
        return harvested_data