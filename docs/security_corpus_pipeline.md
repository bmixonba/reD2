# Security Corpus Harvesting Pipeline Documentation

## Overview

The Security Corpus Harvesting Pipeline is a comprehensive, modular system for collecting, processing, and preparing security-related data for Large Language Model (LLM) training. It integrates multiple data sources, performs intelligent deduplication and enrichment, and outputs high-quality training datasets in standardized formats.

## Architecture

### Core Components

1. **Main Orchestrator** (`scripts/harvest_security_corpus.py`)
   - Coordinates all pipeline phases
   - Manages configuration and execution flow
   - Provides comprehensive logging and reporting

2. **Modular Harvesters** (`harvesters/`)
   - Each harvester implements the `BaseHarvester` interface
   - Standardized data extraction and processing
   - Rate limiting and error handling
   - Source-specific logic encapsulation

3. **Data Processors** (`data_processors/`)
   - Deduplication engine with intelligent merging
   - Cross-reference enrichment system
   - Relationship detection and mapping

4. **Corpus Preparation** (extends existing `scripts/prepare_security_corpus.py`)
   - Multiple prompt/completion template types
   - Validation and filtering
   - Ethical context injection

## Available Data Sources

### Currently Implemented

1. **Metasploit Framework** (`harvest_metasploit_pocs.py`)
   - Exploit modules, auxiliary tools, payloads
   - Code analysis and metadata extraction
   - Real-world security tool examples

2. **CVE Database** (`harvesters/cve_harvester.py`)
   - National Vulnerability Database (NVD) API integration
   - CVSS scores, descriptions, references
   - Vulnerability details and impact assessment

3. **Common Weakness Enumeration** (`harvesters/cwe_harvester.py`)
   - MITRE CWE database
   - Weakness categories and relationships
   - Mitigation strategies and detection methods

4. **MITRE ATT&CK Framework** (`harvesters/mitre_attack_harvester.py`)
   - Tactics, techniques, and procedures (TTPs)
   - Threat actor profiles and campaigns
   - Mitigation and detection guidance

5. **Security Reports & Advisories** (`harvesters/bugtraq_harvester.py`)
   - Placeholder for Bugtraq archives
   - Security mailing lists
   - Vendor security bulletins

6. **Security Research Papers** (`harvesters/whitepaper_harvester.py`)
   - Academic and industry white papers
   - PDF parsing capabilities
   - Research document metadata

### Extensibility

Adding new data sources is straightforward:

1. Create a new harvester class inheriting from `BaseHarvester`
2. Implement required abstract methods:
   - `get_data_type()`
   - `_extract_identifiers()`
   - `_extract_content()`
   - `_extract_metadata()`
   - `harvest()`
3. Add to the orchestrator's initialization
4. Update configuration templates

## Data Schema

### Standardized Entry Format

```json
{
  "source": "harvester_name",
  "harvested_at": "2024-01-15T10:30:00Z",
  "data_type": "cve|cwe|mitre_attack|metasploit|security_report|whitepaper",
  "identifiers": {
    "primary_id": "unique_identifier",
    "name": "human_readable_name",
    "additional_ids": "source_specific_identifiers"
  },
  "content": {
    "description": "main_content_description",
    "technical_details": "detailed_information",
    "references": ["list_of_references"],
    "mitigations": ["mitigation_strategies"]
  },
  "metadata": {
    "severity": "risk_assessment",
    "platforms": ["affected_platforms"],
    "tags": ["classification_tags"]
  },
  "enrichment": {
    "cross_references": ["related_entries"],
    "relationships": ["detected_connections"],
    "extracted_entities": {"cves": [], "cwe_ids": []}
  }
}
```

### Training Sample Format

```json
{
  "id": "unique_sample_id",
  "created_at": "2024-01-15T10:30:00Z",
  "template_type": "code_explanation|vulnerability_analysis|usage_guidance|technical_details|mitigation",
  "prompt": "training_prompt_text",
  "completion": "expected_completion_text",
  "source_metadata": {
    "category": "source_category",
    "complexity": "low|medium|high",
    "risk_level": "low|medium|high",
    "tags": ["relevant_tags"]
  },
  "ethical_context": {
    "intended_use": "Educational and authorized security testing only",
    "restrictions": ["specific_usage_restrictions"],
    "risk_level": "assessment"
  }
}
```

## Configuration

### Configuration File Structure

```json
{
  "sources": {
    "source_name": {
      "enabled": true,
      "description": "source_description",
      "source_specific_parameters": "values"
    }
  },
  "processing": {
    "deduplicate": true,
    "enrich": true,
    "merge_duplicates": true
  },
  "corpus_preparation": {
    "samples_per_item": 3,
    "template_distribution": {
      "code_explanation": 0.3,
      "vulnerability_analysis": 0.25,
      "usage_guidance": 0.2,
      "technical_details": 0.15,
      "mitigation": 0.1
    }
  },
  "output": {
    "format": "jsonl",
    "shuffle": true,
    "include_raw_data": false
  }
}
```

### Environment Variables

- `NVD_API_KEY`: API key for NVD CVE database (optional, but recommended)
- `GHIDRA_INSTALL_DIR`: Path to Ghidra installation (for enhanced binary analysis)

## Usage Examples

### Basic Usage

```bash
# Harvest from all enabled sources with default limits
python scripts/harvest_security_corpus.py --output security_corpus.jsonl

# Harvest from specific sources with custom limits
python scripts/harvest_security_corpus.py \
  --sources cve cwe mitre_attack \
  --limit 1000 \
  --output custom_corpus.jsonl

# Use configuration file
python scripts/harvest_security_corpus.py \
  --config config/production_config.json \
  --output production_corpus.jsonl
```

### Advanced Usage

```bash
# Harvest only (no processing)
python scripts/harvest_security_corpus.py \
  --harvest-only \
  --sources cve metasploit \
  --source-limits '{"cve": 500, "metasploit": 200}' \
  --output raw_data.jsonl

# Full pipeline with custom processing
python scripts/harvest_security_corpus.py \
  --full-pipeline \
  --no-enrich \
  --sources cve cwe mitre_attack \
  --verbose \
  --output processed_corpus.jsonl

# Recent CVE focus
python scripts/harvest_security_corpus.py \
  --sources cve \
  --config config/recent_cve_config.json \
  --output recent_vulnerabilities.jsonl
```

### Configuration Examples

#### High-Volume Production Config

```json
{
  "sources": {
    "cve": {"enabled": true, "limit": 5000, "days_back": 730},
    "metasploit": {"enabled": true, "limit": 2000},
    "cwe": {"enabled": true, "limit": 500},
    "mitre_attack": {"enabled": true, "limit": 1000}
  },
  "corpus_preparation": {
    "samples_per_item": 5
  }
}
```

#### Research Focus Config

```json
{
  "sources": {
    "cve": {
      "enabled": true,
      "limit": 1000,
      "keywords": ["machine learning", "AI security", "adversarial"]
    },
    "whitepapers": {
      "enabled": true,
      "limit": 200,
      "topics": ["AI security", "adversarial ML", "model security"]
    }
  }
}
```

## Pipeline Phases

### Phase 1: Data Harvesting

- Parallel execution of enabled harvesters
- Rate limiting and error handling
- Progress tracking and statistics
- Raw data standardization

### Phase 2: Data Processing

- **Deduplication**: Remove/merge duplicate entries based on identifiers and content similarity
- **Enrichment**: Add cross-references, relationships, and contextual information
- **Validation**: Ensure data quality and completeness

### Phase 3: Corpus Preparation

- Generate multiple training samples per data item
- Apply various prompt/completion templates
- Add ethical context and usage restrictions
- Filter and validate training samples

### Phase 4: Output Generation

- Save final corpus in specified format
- Generate comprehensive execution report
- Provide statistics and quality metrics

## Quality Assurance

### Data Validation

- Schema validation for all entries
- Content completeness checks
- Ethical context verification
- Deduplication effectiveness measurement

### Error Handling

- Graceful handling of API failures
- Retry mechanisms with exponential backoff
- Comprehensive error logging
- Partial failure recovery

### Rate Limiting

- Respect API rate limits
- Configurable delays between requests
- Adaptive throttling based on response codes

## Ethical Considerations

### Built-in Safeguards

1. **Educational Focus**: All samples include educational context
2. **Authorization Requirements**: Clear usage restrictions
3. **Responsible Disclosure**: Emphasis on ethical security research
4. **Legal Compliance**: Mandatory compliance with applicable laws

### Usage Restrictions

- **Authorized Use Only**: Explicit permission required for security testing
- **No Malicious Intent**: Prohibition on harmful activities
- **Educational Purpose**: Primary focus on learning and research
- **Professional Context**: Appropriate for cybersecurity education and training

## Performance Optimization

### Caching Strategies

- HTTP response caching for repeated requests
- Intermediate result caching
- Configuration-based cache management

### Parallel Processing

- Concurrent harvester execution
- Batch processing for large datasets
- Memory-efficient streaming

### Resource Management

- Memory usage monitoring
- Temporary file cleanup
- Connection pooling for HTTP requests

## Monitoring and Logging

### Comprehensive Logging

- Structured logging with configurable levels
- Progress tracking with detailed statistics
- Error categorization and reporting

### Performance Metrics

- Harvest rates per source
- Processing times and bottlenecks
- Quality metrics and validation results

### Reporting

- Execution summary reports
- Source-specific statistics
- Quality assessment metrics
- Configuration documentation

## Troubleshooting

### Common Issues

1. **API Rate Limiting**: Increase delays or obtain API keys
2. **Memory Usage**: Process data in smaller batches
3. **Network Timeouts**: Adjust timeout values and retry logic
4. **Data Quality**: Review validation rules and filters

### Debug Mode

```bash
python scripts/harvest_security_corpus.py \
  --verbose \
  --sources cve \
  --limit 10 \
  --harvest-only
```

### Log Analysis

- Check harvester-specific logs for API issues
- Monitor deduplication rates for data quality
- Review enrichment statistics for relationship detection

## Future Enhancements

### Planned Features

1. **Additional Sources**: 
   - Government security databases
   - Open source vulnerability databases
   - Industry threat intelligence feeds

2. **Enhanced Processing**:
   - ML-based similarity detection
   - Automated categorization
   - Quality scoring algorithms

3. **Advanced Output Formats**:
   - HuggingFace datasets integration
   - Direct model fine-tuning pipelines
   - Multi-format export options

4. **Real-time Capabilities**:
   - Streaming data ingestion
   - Incremental updates
   - Real-time threat intelligence integration

### Integration Opportunities

- CI/CD pipeline integration
- Cloud-native deployment options
- Enterprise security platform integration
- Academic research collaboration tools