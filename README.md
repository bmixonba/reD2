# reD2

A tool for automated analysis of APKs to identify dependencies, de-obfuscate code, identify interesting files and their semantics, and generate suggestions for Frida hooks using Large Language Models (LLMs). Now includes a comprehensive Security LLM Training Framework for harvesting and training on security datasets.

## Features

### APK Analysis (Original Features)
- **APK Extraction & Decompilation**: Automated extraction and decompilation of APK files using jadx
- **Manifest Analysis**: Parse Android manifest files to extract app metadata, permissions, and components
- **File-Level Metadata Extraction**: Comprehensive analysis of individual files within APKs including:
  - MIME type and magic number detection
  - File size analysis and categorization
  - Base64 content detection and validation
  - Cross-reference analysis to find file usage in code and assets
  - Suspicious file identification
- **Shared Library Analysis**: Advanced analysis of native libraries (.so files) including:
  - Architecture/ABI detection (ARM, ARM64, x86, x86_64)
  - Symbol extraction and dependency mapping
  - String analysis and suspicious pattern detection
  - Security feature assessment (NX bit, stack canaries, PIE, RELRO)
  - Packer detection and entropy analysis
  - Hash calculation including fuzzy hashing (ssdeep)
  - Cross-referencing with Java native method declarations
- **Code Analysis**: Intelligent code analysis using LLMs to identify security vulnerabilities and interesting functionality
- **Multiple LLM Support**: Choose from CodeLlama, GPT-4, or open-source models for analysis
- **Dependency Detection**: Automatically identify and catalog app dependencies
- **Frida Hook Suggestions**: Generate targeted suggestions for Frida hooks based on code analysis
- **Security Assessment**: Identify potential security issues and vulnerabilities
- **Batch Processing**: Process multiple APK files in a single run

### Security LLM Training Framework (Enhanced)
- **Comprehensive Security Corpus Harvesting**: Modular pipeline for collecting data from multiple security sources
- **Multi-Source Data Integration**: CVE/NVD, CWE, MITRE ATT&CK, Metasploit, security reports, and research papers
- **Intelligent Data Processing**: Deduplication, cross-reference enrichment, and relationship mapping
- **Modular Harvester Architecture**: Easily extensible system for adding new data sources
- **Metasploit PoC Harvesting**: Automated extraction and annotation of Metasploit Framework modules
- **Dataset Preparation**: Comprehensive corpus preparation with ethical safeguards and content filtering
- **Fine-tuning Pipeline**: HuggingFace Transformers integration with PEFT/LoRA support
- **Ethical Guidelines**: Built-in ethical considerations and responsible AI practices
- **Multiple Template Types**: Diverse training templates for code explanation, vulnerability analysis, usage guidance, technical details, and mitigation strategies

## Directory Structure

```
reD2/
├── main.py              # Entry point - orchestrates APK processing
├── requirements.txt     # Python dependencies
├── README.md           # This file
├── scripts/            # Security LLM training framework
│   ├── __init__.py     # Package initialization
│   ├── harvest_security_corpus.py      # Main orchestration script for comprehensive data harvesting
│   ├── harvest_metasploit_pocs.py      # Metasploit PoC harvesting
│   ├── prepare_security_corpus.py      # Dataset preparation and annotation
│   ├── finetune_sec_llm.py            # HuggingFace fine-tuning with PEFT/LoRA
│   └── train_security_llm.py          # Training pipeline coordination
├── harvesters/         # Modular data source harvesters
│   ├── __init__.py     # Package initialization
│   ├── base_harvester.py              # Base harvester class with common functionality
│   ├── cve_harvester.py               # CVE/NVD API data collection
│   ├── cwe_harvester.py               # Common Weakness Enumeration data
│   ├── mitre_attack_harvester.py      # MITRE ATT&CK framework data
│   ├── bugtraq_harvester.py           # Security advisories and reports (placeholder)
│   └── whitepaper_harvester.py        # Security research papers and whitepapers
├── data_processors/    # Data processing and enrichment modules
│   ├── __init__.py     # Package initialization
│   ├── deduplicator.py                # Intelligent deduplication and merging
│   └── data_enricher.py               # Cross-reference detection and enrichment
├── config/             # Configuration templates and examples
│   └── default_config.json            # Default pipeline configuration
├── docs/               # Documentation
│   ├── project_structure.md           # Framework overview
│   ├── dataset_schema.md              # Dataset format documentation
│   ├── data_schema.md                 # Comprehensive data schema documentation
│   ├── security_corpus_pipeline.md    # Pipeline architecture and usage guide
│   ├── prompt_templates.md            # Example prompt templates
│   ├── ethical_guidelines.md          # Ethical and legal guidelines
│   ├── ethical_guidelines_comprehensive.md # Comprehensive ethical framework
│   └── train_security_llm_usage.md    # Training pipeline usage guide
├── examples/           # Example scripts
│   └── example_pyghidra_integration.py  # Example script demonstrating Ghidra integration
├── apks/               # Directory for APK files to analyze
│   └── README.md       # Instructions for APK placement
├── tests/              # Test suite
│   ├── __init__.py     # Test package initialization
│   ├── test_apk.py     # APK analysis tests
│   ├── test_shared_library_analyzer.py  # Shared library analysis tests
│   └── test_train_security_llm.py     # Security LLM training tests
└── utils/              # Utility modules
    ├── __init__.py     # Package initialization
    ├── apk.py          # APK extraction, decompilation, and file analysis
    ├── llm.py          # LLM integration and code analysis
    ├── shared_library_analyzer.py  # Advanced shared library (.so) analysis
    └── pyghidra_integration.py     # PyGhidra integration for enhanced analysis
```

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/bmixonba/reD2.git
   cd reD2
   ```

2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Install jadx (Java decompiler):
   ```bash
   # Ubuntu/Debian
   sudo apt-get install jadx
   
   # macOS with Homebrew
   brew install jadx
   
   # Or download from: https://github.com/skylot/jadx/releases
   ```

## Usage

### APK Analysis

#### Basic Usage

1. Place APK files in the `apks/` directory
2. Run reD2:
   ```bash
   python main.py
   ```

#### Advanced Options

```bash
# Use a specific model type
python main.py --model-type codellama

# Process a single APK file
python main.py --single-apk /path/to/app.apk

# Save results to output directory
python main.py --output-dir results/

# Enable verbose logging
python main.py --verbose

# Use a specific model name
python main.py --model-type codellama --model-name "codellama/CodeLlama-13b-Instruct-hf"
```

### Security LLM Training Framework

#### Complete Pipeline: Comprehensive Security Corpus Harvesting

```bash
# Run the complete harvesting and preparation pipeline
python scripts/harvest_security_corpus.py --output comprehensive_corpus.jsonl

# Harvest from specific sources with custom limits
python scripts/harvest_security_corpus.py \
  --sources cve cwe mitre_attack metasploit \
  --limit 1000 \
  --output security_corpus.jsonl

# Use configuration file for reproducible runs
python scripts/harvest_security_corpus.py \
  --config config/production_config.json \
  --full-pipeline \
  --output production_corpus.jsonl

# Harvest recent vulnerabilities focus
python scripts/harvest_security_corpus.py \
  --sources cve \
  --source-limits '{"cve": 2000}' \
  --output recent_vulnerabilities.jsonl
```

#### Individual Data Source Harvesting

##### 1. Harvest Metasploit PoCs

```bash
# Basic harvesting
python scripts/harvest_metasploit_pocs.py --output metasploit_dataset.jsonl

# Limited harvesting with specific categories
python scripts/harvest_metasploit_pocs.py --limit 100 --categories exploits auxiliary

# Verbose mode with custom output directory
python scripts/harvest_metasploit_pocs.py --verbose --clone-dir /tmp/msf --keep-clone
```

##### 2. Prepare Training Corpus

```bash
# Prepare training corpus from harvested data
python scripts/prepare_security_corpus.py --input metasploit_dataset.jsonl --output training_corpus.jsonl

# Merge multiple datasets
python scripts/prepare_security_corpus.py --merge-datasets dataset1.jsonl dataset2.jsonl --output combined_corpus.jsonl

# Custom configuration with statistics
python scripts/prepare_security_corpus.py --input data.jsonl --samples-per-item 5 --stats-output stats.json
```

##### 3. Fine-tune Security LLM

```bash
# Basic fine-tuning
python scripts/finetune_sec_llm.py --train-data training_corpus.jsonl --model-name microsoft/DialoGPT-medium

# Advanced fine-tuning with LoRA
python scripts/finetune_sec_llm.py --train-data corpus.jsonl --model-name codellama/CodeLlama-7b-Instruct-hf --use-lora

# Custom configuration with monitoring
python scripts/finetune_sec_llm.py --train-data corpus.jsonl --epochs 5 --batch-size 8 --use-wandb
```

#### Advanced Pipeline Configuration

```bash
# Harvest with processing customization
python scripts/harvest_security_corpus.py \
  --sources cve cwe mitre_attack \
  --no-dedupe \
  --no-enrich \
  --harvest-only \
  --output raw_security_data.jsonl

# Full pipeline with verbose logging
python scripts/harvest_security_corpus.py \
  --full-pipeline \
  --verbose \
  --sources metasploit cve \
  --source-limits '{"metasploit": 500, "cve": 1000}' \
  --output comprehensive_security_corpus.jsonl
```

#### Complete End-to-End Example

```bash
# 1. Comprehensive data harvesting from multiple sources
python scripts/harvest_security_corpus.py \
  --sources metasploit cve cwe mitre_attack \
  --limit 500 \
  --full-pipeline \
  --config config/default_config.json \
  --output security_corpus.jsonl \
  --verbose

# 2. Review generated corpus and statistics
ls -la security_corpus.jsonl security_corpus_report.json

# 3. Fine-tune model with prepared corpus
python scripts/finetune_sec_llm.py \
  --train-data security_corpus.jsonl \
  --model-name microsoft/DialoGPT-medium \
  --use-lora \
  --epochs 3 \
  --output-dir ./trained_security_model
```

#### Data Source Overview

| Source | Data Type | Description | Example Count |
|--------|-----------|-------------|---------------|
| **Metasploit** | Exploit modules, auxiliary tools | Real-world security tools and exploits | 2,000+ modules |
| **CVE/NVD** | Vulnerability data | Official vulnerability database with CVSS scores | 100,000+ CVEs |
| **CWE** | Weakness enumeration | Common weakness patterns and mitigations | 800+ CWEs |
| **MITRE ATT&CK** | Tactics & techniques | Adversary behavior framework | 600+ techniques |
| **Security Reports** | Advisories, bulletins | Vendor and researcher security reports | Varies |
| **Research Papers** | Academic/industry papers | Security research and whitepapers | Varies |

### File Metadata Analysis

reD2 now provides comprehensive file-level analysis:

```python
from utils.apk import APKAnalyzer, analyze_apk_comprehensive

# Create analyzer instance
analyzer = APKAnalyzer()

# Extract detailed file metadata
file_metadata = analyzer.extract_file_metadata('path/to/app.apk')

# Perform comprehensive analysis including file types and cross-references
comprehensive_results = analyze_apk_comprehensive('path/to/app.apk')

# Analyze file types and identify suspicious files
file_analysis = analyzer.analyze_file_types('path/to/app.apk')

# Find cross-references between files and code
cross_refs = analyzer.get_file_cross_references('path/to/app.apk', 'decompiled/dir')
```

### File Metadata Features

- **MIME Type Detection**: Identifies file types using python-magic or fallback detection
- **Base64 Content Detection**: Finds and validates base64 encoded content within files
- **File Size Analysis**: Categorizes files by size and identifies unusually large files
- **Cross-Reference Analysis**: Maps file usage across decompiled code and resources
- **Suspicious File Detection**: Flags files with potentially suspicious characteristics
- **File Categorization**: Groups files by type (code, resources, assets, libraries, etc.)

### Shared Library Analysis

MobileGPT includes advanced analysis capabilities for shared libraries (.so files) found in APKs through the `SharedLibraryAnalyzer`:

```python
from utils.shared_library_analyzer import SharedLibraryAnalyzer

# Create analyzer instance
analyzer = SharedLibraryAnalyzer()

# Analyze a single shared library
library_analysis = analyzer.analyze_shared_library('path/to/library.so')

# Analyze all libraries in an APK
apk_libraries = analyzer.analyze_apk_libraries('path/to/app.apk')

# Cross-reference native methods with library symbols
cross_refs = analyzer.cross_reference_java_natives('path/to/app.apk', 'decompiled/dir')

# Enhanced analysis with Ghidra integration (if available)
enhanced_analysis = analyzer.analyze_with_ghidra('path/to/library.so')

# Check Ghidra availability
ghidra_info = analyzer.get_ghidra_info()
print(f"Ghidra available: {analyzer.is_ghidra_available()}")
```

### PyGhidra Integration for Advanced Analysis

reD2 now includes optional integration with Ghidra through pyghidra for advanced static analysis capabilities beyond what standard tools like `nm`, `readelf`, and `strings` can provide.

#### Installation and Setup

To enable Ghidra integration:

1. **Install Ghidra**:
   ```bash
   # Download from https://ghidra-sre.org/
   # Extract to a directory (e.g., /opt/ghidra)
   ```

2. **Install pyghidra**:
   ```bash
   pip install pyghidra
   ```

3. **Set environment variable**:
   ```bash
   export GHIDRA_INSTALL_DIR=/path/to/ghidra
   ```

4. **Verify Java 17+**:
   ```bash
   java --version  # Ensure Java 17 or later is installed
   ```

#### Ghidra Integration Features

The pyghidra integration provides several advanced capabilities:

- **Function Analysis**: Accurate function boundary detection, calling conventions, and parameter analysis
- **Cross-Reference Analysis**: Comprehensive tracking of all references between functions, data, and strings
- **Advanced Symbol Analysis**: Symbol table analysis beyond standard ELF tools
- **Memory Layout Analysis**: Detailed memory segment analysis with permissions and initialization status
- **Enhanced String Analysis**: Better Unicode support and strings embedded in data structures
- **Custom Script Support**: Ability to run custom Ghidra scripts for specialized analysis

#### Usage Examples

```python
from utils.shared_library_analyzer import SharedLibraryAnalyzer
from utils.pyghidra_integration import check_pyghidra_availability

# Check if Ghidra is available
is_available, status = check_pyghidra_availability()
print(f"Ghidra available: {is_available} - {status}")

# Create analyzer
analyzer = SharedLibraryAnalyzer()

# Standard + Ghidra enhanced analysis
results = analyzer.analyze_with_ghidra(
    'path/to/library.so',
    merge_with_standard=True  # Combines both standard and Ghidra results
)

# Ghidra-only analysis
ghidra_only = analyzer.analyze_with_ghidra(
    'path/to/library.so',
    merge_with_standard=False  # Only Ghidra analysis
)

# Custom Ghidra analysis options
options = {
    'extract_functions': True,
    'extract_xrefs': True,
    'extract_strings': True,
    'custom_scripts': ['/path/to/custom_script.py']
}
custom_analysis = analyzer.analyze_with_ghidra(
    'path/to/library.so',
    ghidra_options=options
)

# Access Ghidra-specific results
if 'ghidra_analysis' in results:
    ghidra_data = results['ghidra_analysis']
    functions = ghidra_data.get('functions', {})
    xrefs = ghidra_data.get('cross_references', {})
    symbols = ghidra_data.get('symbols', {})
    memory = ghidra_data.get('memory_layout', {})
```

#### Graceful Fallback

The integration gracefully handles cases where pyghidra is not available:

```python
analyzer = SharedLibraryAnalyzer()

# This works whether or not Ghidra is available
results = analyzer.analyze_with_ghidra('library.so')

# Check if Ghidra analysis was successful
ghidra_section = results.get('ghidra_analysis', {})
if ghidra_section.get('available', False):
    print("Enhanced Ghidra analysis completed")
    # Access Ghidra-specific features
else:
    print("Falling back to standard analysis")
    print(f"Reason: {ghidra_section.get('error', 'Unknown')}")
```

#### Example Script

See `example_pyghidra_integration.py` for a comprehensive demonstration of the Ghidra integration capabilities.

### Shared Library Analysis Features

- **Architecture/ABI Detection**: Automatically detects ARM, ARM64, x86, x86_64 architectures
- **Symbol Extraction**: Extracts exported, imported, and local symbols using nm and objdump
- **String Analysis**: Finds suspicious strings, URLs, crypto references, and file paths
- **Dependency Mapping**: Maps shared library dependencies and SONAME information
- **Security Analysis**: Checks for NX bit, stack canaries, PIE, RELRO, and fortification
- **Packer Detection**: Identifies common packers and calculates file entropy
- **Hash Calculation**: Computes MD5, SHA1, SHA256, and fuzzy hashes (ssdeep)
- **ELF Analysis**: Detailed analysis of ELF file structure, sections, and program headers
- **JNI Cross-Reference**: Maps Java native method declarations to library symbols
- **Suspicious Pattern Detection**: Identifies anti-debugging, VM detection, and malware indicators
- **Comprehensive Reporting**: Generates detailed analysis summaries with risk scoring
- **PyGhidra Integration**: Advanced static analysis using Ghidra's reverse engineering capabilities (optional)
  - **Function Analysis**: Accurate function detection with calling conventions and parameters
  - **Cross-Reference Tracking**: Comprehensive reference analysis between functions, data, and strings
  - **Advanced Symbol Analysis**: Enhanced symbol table analysis beyond standard ELF tools
  - **Memory Layout Analysis**: Detailed memory segment analysis with permissions
  - **Custom Script Support**: Execute custom Ghidra scripts for specialized analysis tasks

### Command Line Options

- `--apk-dir`: Directory containing APK files (default: `apks`)
- `--model-type`: LLM model type (`codellama`, `gpt4`, `opensource`)
- `--model-name`: Specific model name (optional)
- `--output-dir`: Output directory for analysis results
- `--single-apk`: Process a single APK file instead of directory
- `--verbose`: Enable verbose logging

## Model Selection

reD2 supports multiple LLM backends for code analysis:

### CodeLlama
- **Best for**: Code understanding and security analysis
- **Requirements**: Significant GPU memory (8GB+ recommended)
- **Usage**: `--model-type codellama`
- **Models**: CodeLlama-7b, CodeLlama-13b, CodeLlama-34b variants

### GPT-4
- **Best for**: Comprehensive analysis and natural language insights
- **Requirements**: OpenAI API key (not implemented yet)
- **Usage**: `--model-type gpt4`
- **Note**: API integration pending implementation

### Open-Source Models
- **Best for**: Development, testing, and lightweight analysis
- **Requirements**: Minimal (CPU compatible)
- **Usage**: `--model-type opensource` (default)
- **Models**: Various HuggingFace transformer models

## Output

reD2 generates comprehensive analysis reports including:

- **APK Metadata**: Package name, version, permissions, components
- **File-Level Analysis**: Detailed metadata for each file including MIME types, sizes, and base64 content
- **Dependencies**: List of imported libraries and frameworks
- **Security Issues**: Potential vulnerabilities and security concerns
- **Code Patterns**: Identified architectural patterns and structures
- **Frida Hook Suggestions**: Recommended methods and functions to hook
- **File Analysis**: Detailed analysis of interesting code files
- **Cross-References**: Mapping of file usage across code and assets
- **Suspicious Files**: Identification of potentially malicious or unusual files

## Examples

### Basic APK Analysis
```bash
# Place app.apk in apks/ directory
cp /path/to/app.apk apks/
python main.py
```

### Advanced Analysis with CodeLlama
```bash
python main.py --model-type codellama --output-dir analysis_results/ --verbose
```

### Single File Analysis
```bash
python main.py --single-apk suspicious_app.apk --model-type codellama
```

## Testing

reD2 includes a comprehensive test suite to validate file metadata extraction and base64 detection:

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test file
python tests/test_apk.py

# Run tests with coverage
python -m pytest tests/ --cov=utils --cov-report=html
```

### Test Coverage

The test suite covers:
- File metadata extraction functionality
- MIME type and magic number detection
- Base64 content detection and validation
- File categorization and suspicious file identification
- Cross-reference analysis
- Binary file detection

## Requirements

### Core Dependencies

- Python 3.8+
- jadx (Java decompiler)

### Python Packages

**APK Analysis:**
- transformers (for LLM models)
- torch (PyTorch for model inference)
- sentencepiece (tokenization)
- androguard (APK parsing and analysis)
- python-magic (file type detection)
- frida-tools (dynamic analysis support)

**Security LLM Training:**
- datasets (HuggingFace datasets)
- peft (Parameter-Efficient Fine-Tuning)
- accelerate (distributed training)
- wandb (experiment tracking)

See `requirements.txt` for complete dependency list with versions.

### Optional Dependencies for Enhanced Analysis

- **pyghidra** (for advanced Ghidra integration):
  ```bash
  pip install pyghidra
  ```
- **Ghidra** (NSA's reverse engineering tool):
  - Download from: https://ghidra-sre.org/
  - Requires Java 17 or later
  - Set GHIDRA_INSTALL_DIR environment variable

## Development

### Model Selection Logic

The LLM model selection is handled in `utils/llm.py`:

```python
# Model types are defined as an enum
class ModelType(Enum):
    CODELLAMA = "codellama"
    GPT4 = "gpt4"
    OPENSOURCE = "opensource"

# Model loading logic branches based on model type
def _load_model(self):
    if self.model_type == ModelType.GPT4:
        # GPT-4 API integration (to be implemented)
        self._init_gpt4_placeholder()
    elif self.model_type == ModelType.CODELLAMA:
        # CodeLlama model loading
        self._load_codellama_model()
    else:
        # Open-source/fallback model loading
        self._load_opensource_model()
```

### Adding New Models

To add support for new models:

1. Add model type to `ModelType` enum in `utils/llm.py`
2. Implement model loading logic in `_load_model()`
3. Add analysis method (e.g., `_analyze_with_newmodel()`)
4. Update CLI options in `main.py`

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes with appropriate tests
4. Submit a pull request

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is intended for security research and educational purposes. Ensure you have proper authorization before analyzing APK files. The authors are not responsible for any misuse of this tool.

## Ethical Guidelines for Security LLM Training

**⚠️ IMPORTANT: The Security LLM Training Framework is provided STRICTLY FOR EDUCATIONAL AND AUTHORIZED SECURITY RESEARCH PURPOSES ONLY.**

### Permitted Uses
- Educational research and training
- Authorized penetration testing with written permission
- Academic research into cybersecurity
- Developing defensive security measures

### Prohibited Uses
- Malicious attacks or unauthorized access
- Criminal activities
- Privacy violations
- Any use without proper authorization

### Key Principles
- **Authorization Required**: Always obtain explicit written permission
- **Educational Focus**: Emphasize learning and defensive security
- **Responsible Disclosure**: Follow responsible vulnerability disclosure practices
- **Legal Compliance**: Ensure all activities comply with applicable laws

For complete ethical guidelines, see `docs/ethical_guidelines.md`.

## Documentation

- **Pipeline Architecture**: `docs/security_corpus_pipeline.md` - Comprehensive guide to the harvesting pipeline
- **Data Schema**: `docs/data_schema.md` - Detailed documentation of data formats and schemas
- **Configuration Guide**: `config/default_config.json` - Configuration templates and examples
- **Ethical Framework**: `docs/ethical_guidelines_comprehensive.md` - Comprehensive ethical guidelines
- **Project Structure**: `docs/project_structure.md` - Overview of the Security LLM Training Framework
- **Dataset Schema**: `docs/dataset_schema.md` - Data formats and schemas (legacy)
- **Prompt Templates**: `docs/prompt_templates.md` - Example training templates
- **Ethical Guidelines**: `docs/ethical_guidelines.md` - Comprehensive ethical and legal guidelines
