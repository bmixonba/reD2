# reD2 Examples

This directory contains example configurations, code samples, and usage patterns for reD2's features.

## DEX Code Explanation Examples

### facebook_ads_drm_code.java
Real-world example of obfuscated DRM implementation from Facebook's Audience Network SDK. This code demonstrates:
- String array obfuscation
- Control flow obfuscation with character comparisons
- Android Parcelable implementation for IPC
- DRM scheme data management using UUIDs
- Anti-tampering checks with RuntimeException

### facebook_ads_drm_explanation.txt
Output from the DEX Code Explainer analyzing the Facebook Ads DRM code. Shows:
- Automatic detection of 2 obfuscation techniques
- Identification of 4 security concerns
- Purpose inference (DRM, ExoPlayer, Advertisement SDK)
- Data structure analysis (Parcelable, Comparator)
- Actionable recommendations for further analysis

To generate this explanation yourself:
```bash
python scripts/explain_dex_code.py \
  --file examples/facebook_ads_drm_code.java \
  --package com.facebook.ads.internal.exoplayer2.drm \
  --output my_explanation.txt
```

## PyGhidra Integration Example

### example_pyghidra_integration.py
Demonstrates integration with Ghidra for advanced binary analysis of native libraries (.so files) extracted from APKs.

## Security Corpus Pipeline Examples

## Quick Start

### Basic Multi-Source Harvest

```bash
# Harvest from all default sources with moderate limits
python scripts/harvest_security_corpus.py \
  --sources cve cwe mitre_attack \
  --limit 100 \
  --full-pipeline \
  --output example_corpus.jsonl \
  --verbose
```

### Research Focus - Recent Vulnerabilities

```bash
# Focus on recent CVEs with high-quality data
python scripts/harvest_security_corpus.py \
  --sources cve \
  --source-limits '{"cve": 500}' \
  --config examples/recent_cve_config.json \
  --full-pipeline \
  --output recent_vulns_corpus.jsonl
```

### Educational Dataset - Comprehensive Coverage

```bash
# Create comprehensive educational dataset
python scripts/harvest_security_corpus.py \
  --sources metasploit cve cwe mitre_attack \
  --config examples/educational_config.json \
  --full-pipeline \
  --output educational_security_corpus.jsonl
```

## Configuration Examples

See the following example configurations:

- `examples/educational_config.json` - Educational use case
- `examples/research_config.json` - Security research focus
- `examples/recent_cve_config.json` - Recent vulnerability focus
- `examples/minimal_config.json` - Minimal testing configuration

## Testing the Pipeline

### Minimal Test Run

```bash
# Quick test with minimal data
python scripts/harvest_security_corpus.py \
  --sources cwe mitre_attack \
  --limit 5 \
  --full-pipeline \
  --output test_pipeline.jsonl \
  --verbose
```

### Individual Component Testing

```bash
# Test individual harvesters
python scripts/harvest_security_corpus.py \
  --sources cve \
  --limit 10 \
  --harvest-only \
  --output test_cve_harvest.jsonl

# Test processing pipeline only
python scripts/prepare_security_corpus.py \
  --input test_cve_harvest.jsonl \
  --output test_processed.jsonl
```

## Environment Setup

```bash
# Set optional API keys for enhanced harvesting
export NVD_API_KEY="your_nvd_api_key_here"

# For enhanced binary analysis (optional)
export GHIDRA_INSTALL_DIR="/path/to/ghidra"
```

## Expected Outputs

After running the pipeline, you should see:

- `{output_name}.jsonl` - Final training corpus
- `{output_name}_report.json` - Execution statistics and metadata
- Log output showing harvest progress and statistics

## Quality Verification

```bash
# Check corpus quality
python -c "
import json
with open('example_corpus.jsonl', 'r') as f:
    samples = [json.loads(line) for line in f]
print(f'Total samples: {len(samples)}')
print(f'Template types: {set(s.get(\"template_type\") for s in samples)}')
print(f'Average prompt length: {sum(len(s.get(\"prompt\", \"\")) for s in samples) / len(samples):.1f}')
"
```