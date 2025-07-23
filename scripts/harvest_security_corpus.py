#!/usr/bin/env python3
"""
Security Corpus Harvester - Main Orchestration Script

This script coordinates the harvesting, enrichment, and preparation of a comprehensive
security corpus for LLM training. It orchestrates multiple data sources and processing
steps to create a unified, high-quality dataset.

Usage:
    python scripts/harvest_security_corpus.py --output security_corpus.jsonl
    python scripts/harvest_security_corpus.py --sources cve,cwe,metasploit --limit 1000
    python scripts/harvest_security_corpus.py --config config.json --full-pipeline
"""

import os
import sys
import json
import argparse
import logging
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Import harvesters
from harvesters.cve_harvester import CVEHarvester
from harvesters.cwe_harvester import CWEHarvester
from harvesters.mitre_attack_harvester import MITREAttackHarvester

# Import data processors
from data_processors.deduplicator import DataDeduplicator
from data_processors.data_enricher import DataEnricher

# Import existing scripts
from scripts.harvest_metasploit_pocs import MetasploitHarvester
from scripts.prepare_security_corpus import SecurityCorpusPreparator


def setup_logging(verbose: bool = False):
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


class SecurityCorpusOrchestrator:
    """
    Main orchestrator for the security corpus harvesting pipeline.
    
    Coordinates multiple data sources, processing steps, and output generation
    to create a comprehensive security dataset for LLM training.
    """
    
    def __init__(self, config: Dict = None, verbose: bool = False):
        """
        Initialize the orchestrator.
        
        Args:
            config: Configuration dictionary
            verbose: Enable verbose logging
        """
        self.logger = logging.getLogger(__name__)
        self.verbose = verbose
        self.config = config or self._load_default_config()
        
        # Initialize components
        self.harvesters = self._initialize_harvesters()
        self.deduplicator = DataDeduplicator(verbose=verbose)
        self.enricher = DataEnricher(verbose=verbose)
        self.corpus_preparator = SecurityCorpusPreparator(verbose=verbose)
        
        # Statistics
        self.stats = {
            'start_time': datetime.now(),
            'sources_processed': 0,
            'total_entries_harvested': 0,
            'total_entries_after_dedup': 0,
            'total_training_samples': 0
        }
    
    def _load_default_config(self) -> Dict:
        """Load default configuration."""
        return {
            'sources': {
                'metasploit': {
                    'enabled': True,
                    'categories': ['exploits', 'auxiliary', 'post'],
                    'limit': 500
                },
                'cve': {
                    'enabled': True,
                    'api_key': None,  # Set via environment variable or config file
                    'days_back': 365,
                    'limit': 1000,
                    'keywords': ['remote code execution', 'sql injection', 'cross-site scripting']
                },
                'cwe': {
                    'enabled': True,
                    'limit': 100
                },
                'mitre_attack': {
                    'enabled': True,
                    'limit': 200,
                    'object_types': ['attack-pattern', 'intrusion-set']
                }
            },
            'processing': {
                'deduplicate': True,
                'enrich': True,
                'merge_duplicates': True
            },
            'corpus_preparation': {
                'samples_per_item': 3,
                'template_distribution': {
                    'code_explanation': 0.3,
                    'vulnerability_analysis': 0.25,
                    'usage_guidance': 0.2,
                    'technical_details': 0.15,
                    'mitigation': 0.1
                }
            },
            'output': {
                'format': 'jsonl',
                'include_raw_data': False,
                'shuffle': True
            }
        }
    
    def _initialize_harvesters(self) -> Dict:
        """Initialize all available harvesters."""
        harvesters = {}
        
        # CVE Harvester
        cve_config = self.config.get('sources', {}).get('cve', {})
        api_key = cve_config.get('api_key') or os.getenv('NVD_API_KEY')
        harvesters['cve'] = CVEHarvester(api_key=api_key, verbose=self.verbose)
        
        # CWE Harvester
        harvesters['cwe'] = CWEHarvester(verbose=self.verbose)
        
        # MITRE ATT&CK Harvester
        harvesters['mitre_attack'] = MITREAttackHarvester(verbose=self.verbose)
        
        # Metasploit Harvester
        harvesters['metasploit'] = MetasploitHarvester(verbose=self.verbose)
        
        # Additional harvesters (import only if enabled)
        try:
            from harvesters.bugtraq_harvester import BugtraqHarvester
            harvesters['bugtraq'] = BugtraqHarvester(verbose=self.verbose)
        except ImportError:
            self.logger.warning("BugtraqHarvester not available")
        
        try:
            from harvesters.whitepaper_harvester import WhitepaperHarvester
            harvesters['whitepapers'] = WhitepaperHarvester(verbose=self.verbose)
        except ImportError:
            self.logger.warning("WhitepaperHarvester not available")
        
        return harvesters
    
    def harvest_all_sources(self, sources: Optional[List[str]] = None, 
                          limits: Optional[Dict[str, int]] = None) -> List[Dict]:
        """
        Harvest data from all enabled sources.
        
        Args:
            sources: List of sources to harvest (if None, uses config)
            limits: Per-source limits (if None, uses config)
            
        Returns:
            List of all harvested data entries
        """
        if sources is None:
            sources = [name for name, config in self.config['sources'].items() 
                      if config.get('enabled', True)]
        
        self.logger.info(f"Starting harvest from sources: {sources}")
        
        all_data = []
        
        for source_name in sources:
            if source_name not in self.harvesters:
                self.logger.warning(f"Unknown source: {source_name}")
                continue
            
            try:
                self.logger.info(f"Harvesting from {source_name}...")
                
                harvester = self.harvesters[source_name]
                source_config = self.config['sources'].get(source_name, {})
                
                # Get source-specific limit
                limit = None
                if limits and source_name in limits:
                    limit = limits[source_name]
                elif 'limit' in source_config:
                    limit = source_config['limit']
                
                # Harvest based on source type
                source_data = self._harvest_single_source(source_name, harvester, source_config, limit)
                
                if source_data:
                    all_data.extend(source_data)
                    self.stats['sources_processed'] += 1
                    self.logger.info(f"Harvested {len(source_data)} entries from {source_name}")
                else:
                    self.logger.warning(f"No data harvested from {source_name}")
                
            except Exception as e:
                self.logger.error(f"Error harvesting from {source_name}: {e}")
                continue
        
        self.stats['total_entries_harvested'] = len(all_data)
        self.logger.info(f"Total entries harvested: {len(all_data)}")
        
        return all_data
    
    def _harvest_single_source(self, source_name: str, harvester: Any, 
                             config: Dict, limit: Optional[int]) -> List[Dict]:
        """Harvest data from a single source with source-specific logic."""
        
        if source_name == 'metasploit':
            categories = config.get('categories', ['exploits', 'auxiliary'])
            return harvester.harvest_modules(categories=categories, limit=limit)
        
        elif source_name == 'cve':
            # Harvest recent CVEs and keyword-based CVEs
            days_back = config.get('days_back', 365)
            keywords = config.get('keywords', [])
            
            data = []
            
            # Recent CVEs
            recent_limit = limit // 2 if limit and keywords else limit
            recent_data = harvester.harvest_recent_cves(days=days_back, limit=recent_limit)
            data.extend(recent_data)
            
            # Keyword-based CVEs
            if keywords and limit:
                keyword_limit = limit - len(recent_data)
                keyword_data = harvester.harvest_by_keyword(keywords, limit=keyword_limit)
                data.extend(keyword_data)
            
            return data
        
        elif source_name == 'cwe':
            return harvester.harvest(limit=limit)
        
        elif source_name == 'mitre_attack':
            object_types = config.get('object_types', ['attack-pattern'])
            return harvester.harvest(limit=limit, object_types=object_types)
        
        elif source_name == 'bugtraq':
            sources = config.get('sources', None)
            date_range = config.get('date_range', None)
            return harvester.harvest(limit=limit, sources=sources, date_range=date_range)
        
        elif source_name == 'whitepapers':
            topics = config.get('topics', None)
            organizations = config.get('organizations', None)
            return harvester.harvest(limit=limit, topics=topics, organizations=organizations)
        
        else:
            # Default harvest method
            return harvester.harvest(limit=limit)
    
    def process_data(self, raw_data: List[Dict]) -> List[Dict]:
        """
        Process raw harvested data through deduplication and enrichment.
        
        Args:
            raw_data: List of raw data entries
            
        Returns:
            List of processed data entries
        """
        self.logger.info("Starting data processing pipeline")
        
        processed_data = raw_data
        
        # Deduplication
        if self.config['processing'].get('deduplicate', True):
            self.logger.info("Deduplicating data...")
            merge_duplicates = self.config['processing'].get('merge_duplicates', True)
            processed_data = self.deduplicator.deduplicate_data(processed_data, merge_duplicates)
            self.stats['total_entries_after_dedup'] = len(processed_data)
        
        # Enrichment
        if self.config['processing'].get('enrich', True):
            self.logger.info("Enriching data with cross-references...")
            processed_data = self.enricher.enrich_data(processed_data)
        
        self.logger.info(f"Data processing complete. {len(processed_data)} entries ready for corpus preparation")
        
        return processed_data
    
    def prepare_training_corpus(self, processed_data: List[Dict], output_path: str) -> str:
        """
        Prepare the final training corpus from processed data.
        
        Args:
            processed_data: List of processed data entries
            output_path: Path for the training corpus
            
        Returns:
            Path to the prepared corpus file
        """
        self.logger.info("Preparing training corpus...")
        
        corpus_config = self.config['corpus_preparation']
        
        # Generate training samples
        training_corpus = self.corpus_preparator.prepare_training_corpus(
            processed_data,
            samples_per_item=corpus_config.get('samples_per_item', 3),
            template_distribution=corpus_config.get('template_distribution')
        )
        
        # Filter and validate
        training_corpus = self.corpus_preparator.filter_and_validate(training_corpus)
        
        # Save corpus
        output_config = self.config['output']
        self.corpus_preparator.save_corpus(
            training_corpus,
            output_path,
            format=output_config.get('format', 'jsonl'),
            shuffle=output_config.get('shuffle', True)
        )
        
        self.stats['total_training_samples'] = len(training_corpus)
        self.logger.info(f"Training corpus prepared with {len(training_corpus)} samples")
        
        return output_path
    
    def run_full_pipeline(self, output_path: str, sources: Optional[List[str]] = None,
                         limits: Optional[Dict[str, int]] = None) -> Dict:
        """
        Run the complete harvesting and preparation pipeline.
        
        Args:
            output_path: Path for the final corpus
            sources: Sources to harvest from
            limits: Per-source limits
            
        Returns:
            Pipeline execution statistics
        """
        self.logger.info("Starting full security corpus pipeline")
        
        try:
            # Phase 1: Harvest data from all sources
            self.logger.info("=== Phase 1: Data Harvesting ===")
            raw_data = self.harvest_all_sources(sources=sources, limits=limits)
            
            if not raw_data:
                self.logger.error("No data harvested. Pipeline terminated.")
                return self.get_statistics()
            
            # Phase 2: Process data (deduplicate and enrich)
            self.logger.info("=== Phase 2: Data Processing ===")
            processed_data = self.process_data(raw_data)
            
            # Phase 3: Prepare training corpus
            self.logger.info("=== Phase 3: Corpus Preparation ===")
            corpus_path = self.prepare_training_corpus(processed_data, output_path)
            
            # Phase 4: Generate reports
            self.logger.info("=== Phase 4: Report Generation ===")
            stats = self.get_statistics()
            self._save_pipeline_report(stats, output_path)
            
            self.logger.info("=== Pipeline Complete ===")
            self.logger.info(f"Final corpus saved to: {corpus_path}")
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Pipeline failed: {e}")
            raise
    
    def _save_pipeline_report(self, stats: Dict, output_path: str):
        """Save a detailed pipeline execution report."""
        report_path = output_path.replace('.jsonl', '_report.json').replace('.json', '_report.json')
        
        report = {
            'pipeline_execution': stats,
            'configuration': self.config,
            'harvester_stats': {
                name: harvester.get_statistics() if hasattr(harvester, 'get_statistics') else {
                    'harvester': name,
                    'harvested_count': getattr(harvester, 'modules_processed', 0),
                    'error_count': 0
                }
                for name, harvester in self.harvesters.items()
            },
            'processing_stats': {
                'deduplication': self.deduplicator.get_statistics(),
                'enrichment': self.enricher.get_statistics()
            },
            'corpus_preparation_stats': self.corpus_preparator.generate_statistics([]) if hasattr(self.corpus_preparator, 'generate_statistics') else {}
        }
        
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        
        self.logger.info(f"Pipeline report saved to: {report_path}")
    
    def get_statistics(self) -> Dict:
        """Get comprehensive pipeline statistics."""
        end_time = datetime.now()
        duration = end_time - self.stats['start_time']
        
        return {
            **self.stats,
            'end_time': end_time.isoformat(),
            'duration_seconds': duration.total_seconds(),
            'sources_enabled': len([s for s in self.config['sources'].values() if s.get('enabled', True)]),
            'processing_enabled': {
                'deduplication': self.config['processing'].get('deduplicate', True),
                'enrichment': self.config['processing'].get('enrich', True)
            }
        }


def load_config_file(config_path: str) -> Dict:
    """Load configuration from a JSON file."""
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"Failed to load config file {config_path}: {e}")
        raise


def main():
    """Main entry point for the security corpus harvester."""
    parser = argparse.ArgumentParser(
        description="Harvest and prepare comprehensive security corpus for LLM training"
    )
    
    parser.add_argument(
        '--output', '-o',
        default='security_corpus.jsonl',
        help='Output path for the training corpus (default: security_corpus.jsonl)'
    )
    
    parser.add_argument(
        '--config',
        help='Path to configuration JSON file'
    )
    
    parser.add_argument(
        '--sources',
        nargs='*',
        choices=['metasploit', 'cve', 'cwe', 'mitre_attack', 'bugtraq', 'whitepapers'],
        help='Sources to harvest from (default: all enabled in config)'
    )
    
    parser.add_argument(
        '--limit',
        type=int,
        help='Global limit on entries per source'
    )
    
    parser.add_argument(
        '--source-limits',
        help='JSON string with per-source limits (e.g., \'{"cve": 500, "metasploit": 200}\')'
    )
    
    parser.add_argument(
        '--full-pipeline',
        action='store_true',
        help='Run the complete pipeline (harvest, process, prepare corpus)'
    )
    
    parser.add_argument(
        '--harvest-only',
        action='store_true',
        help='Only harvest data, do not process or prepare corpus'
    )
    
    parser.add_argument(
        '--no-dedupe',
        action='store_true',
        help='Skip deduplication step'
    )
    
    parser.add_argument(
        '--no-enrich',
        action='store_true',
        help='Skip enrichment step'
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
    
    try:
        # Load configuration
        config = None
        if args.config:
            config = load_config_file(args.config)
        
        # Create orchestrator
        orchestrator = SecurityCorpusOrchestrator(config=config, verbose=args.verbose)
        
        # Override config with command line arguments
        if args.no_dedupe:
            orchestrator.config['processing']['deduplicate'] = False
        if args.no_enrich:
            orchestrator.config['processing']['enrich'] = False
        
        # Parse source limits
        source_limits = None
        if args.source_limits:
            source_limits = json.loads(args.source_limits)
        elif args.limit:
            # Apply global limit to all sources
            source_limits = {source: args.limit for source in orchestrator.config['sources'].keys()}
        
        # Run pipeline
        if args.harvest_only:
            logger.info("Running harvest-only mode")
            data = orchestrator.harvest_all_sources(sources=args.sources, limits=source_limits)
            
            # Save raw harvested data
            output_path = args.output.replace('.jsonl', '_raw.jsonl')
            with open(output_path, 'w', encoding='utf-8') as f:
                for entry in data:
                    f.write(json.dumps(entry, ensure_ascii=False) + '\n')
            
            logger.info(f"Raw harvested data saved to: {output_path}")
            stats = orchestrator.get_statistics()
            
        else:
            # Run full pipeline
            logger.info("Running full pipeline")
            stats = orchestrator.run_full_pipeline(
                output_path=args.output,
                sources=args.sources,
                limits=source_limits
            )
        
        # Print summary
        print(f"\n{'='*60}")
        print(f"Security Corpus Harvesting Complete")
        print(f"{'='*60}")
        print(f"Sources processed: {stats['sources_processed']}")
        print(f"Total entries harvested: {stats['total_entries_harvested']}")
        if 'total_entries_after_dedup' in stats:
            print(f"Entries after deduplication: {stats['total_entries_after_dedup']}")
        if 'total_training_samples' in stats:
            print(f"Final training samples: {stats['total_training_samples']}")
        print(f"Duration: {stats.get('duration_seconds', 0):.1f} seconds")
        print(f"Output saved to: {args.output}")
        print(f"{'='*60}")
        
        return 0
        
    except KeyboardInterrupt:
        logger.info("Pipeline interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"Pipeline failed: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())