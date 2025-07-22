# MobileGPT

A tool for automated analysis of APKs to identify dependencies, de-obfuscate code, identify interesting files and their semantics, and generate suggestions for Frida hooks using Large Language Models (LLMs).

## Features

- **APK Extraction & Decompilation**: Automated extraction and decompilation of APK files using jadx
- **Manifest Analysis**: Parse Android manifest files to extract app metadata, permissions, and components
- **File-Level Metadata Extraction**: Comprehensive analysis of individual files within APKs including:
  - MIME type and magic number detection
  - File size analysis and categorization
  - Base64 content detection and validation
  - Cross-reference analysis to find file usage in code and assets
  - Suspicious file identification
- **Code Analysis**: Intelligent code analysis using LLMs to identify security vulnerabilities and interesting functionality
- **Multiple LLM Support**: Choose from CodeLlama, GPT-4, or open-source models for analysis
- **Dependency Detection**: Automatically identify and catalog app dependencies
- **Frida Hook Suggestions**: Generate targeted suggestions for Frida hooks based on code analysis
- **Security Assessment**: Identify potential security issues and vulnerabilities
- **Batch Processing**: Process multiple APK files in a single run

## Directory Structure

```
MobileGPT/
├── main.py              # Entry point - orchestrates APK processing
├── requirements.txt     # Python dependencies
├── README.md           # This file
├── apks/               # Directory for APK files to analyze
│   └── README.md       # Instructions for APK placement
├── tests/              # Test suite
│   ├── __init__.py     # Test package initialization
│   └── test_apk.py     # APK analysis tests
└── utils/              # Utility modules
    ├── __init__.py     # Package initialization
    ├── apk.py          # APK extraction, decompilation, and file analysis
    └── llm.py          # LLM integration and code analysis
```

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/bmixonba/MobileGPT.git
   cd MobileGPT
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

### Basic Usage

1. Place APK files in the `apks/` directory
2. Run MobileGPT:
   ```bash
   python main.py
   ```

### Advanced Options

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

### File Metadata Analysis

MobileGPT now provides comprehensive file-level analysis:

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

### Command Line Options

- `--apk-dir`: Directory containing APK files (default: `apks`)
- `--model-type`: LLM model type (`codellama`, `gpt4`, `opensource`)
- `--model-name`: Specific model name (optional)
- `--output-dir`: Output directory for analysis results
- `--single-apk`: Process a single APK file instead of directory
- `--verbose`: Enable verbose logging

## Model Selection

MobileGPT supports multiple LLM backends for code analysis:

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

MobileGPT generates comprehensive analysis reports including:

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

MobileGPT includes a comprehensive test suite to validate file metadata extraction and base64 detection:

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

- Python 3.8+
- jadx (Java decompiler)
- Required Python packages (see requirements.txt):
  - transformers (for LLM models)
  - torch (PyTorch for model inference)
  - sentencepiece (tokenization)
  - androguard (APK parsing and analysis)
  - python-magic (file type detection)
  - frida-tools (dynamic analysis support)

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
