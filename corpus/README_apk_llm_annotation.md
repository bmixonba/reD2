# APK LLM Annotation Pipeline Documentation

This document provides comprehensive documentation for the APK LLM Annotation Pipeline, a modular system for generating LLM training data from Android APK files by analyzing both Java and native (SO) code.

## Overview

The APK LLM Annotation Pipeline leverages existing APK analysis infrastructure to:

1. **Extract and Decompile APKs**: Uses the existing `APKAnalyzer` class to extract APK metadata, decompile Java/DEX code, and locate native libraries
2. **Analyze Native Libraries**: Uses `pyghidra_integration` to decompile .so files to C-like pseudocode for detailed analysis
3. **Apply Intelligent Annotations**: Automatically labels code with high-level functionality tags (encryption, networking, file operations, etc.)
4. **Generate Training Data**: Creates prompt/completion pairs suitable for LLM fine-tuning
5. **Export Training Corpus**: Outputs data in JSONL format compatible with popular ML frameworks

## Features

### Code Analysis Capabilities

#### Java Code Analysis
- **Pattern Recognition**: Detects encryption/decryption, network communication, file operations, authentication, web browser functionality, and more
- **Structural Analysis**: Counts methods, classes, imports, and lines of code
- **Security Assessment**: Identifies security-relevant patterns and potential vulnerabilities
- **API Usage Analysis**: Analyzes external dependencies and framework usage

#### Native Library (SO) Analysis
- **Architecture Detection**: Identifies ARM, ARM64, x86, x86_64 architectures
- **Symbol Analysis**: Extracts exported/imported symbols and function signatures
- **String Extraction**: Finds suspicious strings, URLs, crypto references
- **Security Features**: Checks for NX bit, stack canaries, PIE, RELRO
- **PyGhidra Integration**: Advanced decompilation to C-like pseudocode (when available)
- **JNI Cross-referencing**: Maps Java native methods to library symbols

### Annotation Categories

The pipeline automatically applies the following high-level labels:

#### Common Categories (Java & SO)
- `encryption_decryption` - Cryptographic operations
- `network_communication` - Network connectivity and data transfer
- `file_operations` - File system operations and data persistence
- `authentication` - User authentication and authorization
- `anti_analysis` - Anti-debugging and evasion techniques
- `web_browser` - Web rendering and browser functionality
- `update_logic` - Application update and version management

#### Java-Specific Categories
- `permissions` - Android permission handling
- `location_services` - GPS and location functionality
- `device_info` - Device identification and system information

#### SO-Specific Categories
- `memory_management` - Memory allocation and management
- `process_threading` - Process and thread operations
- `system_calls` - Direct system call usage
- `compression` - Data compression and decompression
- `jni_interface` - Java Native Interface operations
- `security_hardened` - Security hardening features detected
- `potentially_suspicious` - Suspicious behavior patterns

### Training Data Generation

The pipeline generates multiple types of prompt/completion pairs:

1. **Code Explanation**: Detailed explanations of code functionality
2. **Security Analysis**: Security assessments and vulnerability identification
3. **Functionality Labeling**: High-level functionality categorization
4. **Pattern Identification**: Programming patterns and architectural decisions
5. **API Usage Analysis**: External dependencies and API usage patterns

## Installation and Setup

### Prerequisites

1. **Python 3.8+** with required packages:
   ```bash
   pip install -r requirements.txt
   ```

2. **jadx** (Java decompiler):
   ```bash
   # Ubuntu/Debian
   sudo apt-get install jadx
   
   # macOS with Homebrew
   brew install jadx
   ```

3. **Optional: PyGhidra for Advanced SO Analysis**:
   ```bash
   # Install pyghidra
   pip install pyghidra
   
   # Download and install Ghidra
   # From: https://ghidra-sre.org/
   
   # Set environment variable
   export GHIDRA_INSTALL_DIR=/path/to/ghidra
   ```

### Verifying Installation

Check if all components are properly installed:

```bash
# Basic functionality test
python scripts/apk_llm_annotation_pipeline.py --help

# Check PyGhidra availability (optional)
python -c "from utils.pyghidra_integration import check_pyghidra_availability; print(check_pyghidra_availability())"
```

## Usage

### Basic Usage

#### Single APK Processing
```bash
# Process a single APK file
python scripts/apk_llm_annotation_pipeline.py \
  --input-apk /path/to/app.apk \
  --output training_data.jsonl
```

#### Directory Processing
```bash
# Process all APKs in a directory
python scripts/apk_llm_annotation_pipeline.py \
  --input-dir apks/ \
  --output-dir corpus/ \
  --report
```

#### Batch Processing from File List
```bash
# Create a list of APK paths
echo "/path/to/app1.apk" > apk_list.txt
echo "/path/to/app2.apk" >> apk_list.txt

# Process APKs from list
python scripts/apk_llm_annotation_pipeline.py \
  --apk-list apk_list.txt \
  --output batch_training_data.jsonl
```

### Advanced Configuration

#### Processing Limits
```bash
# Customize processing limits
python scripts/apk_llm_annotation_pipeline.py \
  --input-dir apks/ \
  --output training_data.jsonl \
  --max-java-files 100 \
  --max-so-files 20 \
  --max-pairs-per-file 5 \
  --verbose
```

#### Output Formats
```bash
# Generate JSON format (instead of JSONL)
python scripts/apk_llm_annotation_pipeline.py \
  --input-apk app.apk \
  --output training_data.json \
  --output-format json
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--input-apk` | Single APK file to process | - |
| `--input-dir` | Directory containing APK files | - |
| `--apk-list` | File containing list of APK paths | - |
| `--output` | Output file path for training data | - |
| `--output-dir` | Output directory (used with --input-dir) | - |
| `--output-format` | Output format (jsonl or json) | jsonl |
| `--max-java-files` | Maximum Java files to process per APK | 50 |
| `--max-so-files` | Maximum SO files to process per APK | 10 |
| `--max-pairs-per-file` | Maximum prompt/completion pairs per file | 3 |
| `--report` | Generate summary report | False |
| `--verbose` | Enable verbose logging | False |

## Output Format

### JSONL Training Data Format

Each line in the output JSONL file contains a prompt/completion pair:

```json
{
  "prompt": "Analyze the following JAVA code and explain its functionality, particularly focusing on encryption_decryption, network_communication:\n\n[code content]\n\nExplanation:",
  "completion": "This Java code implements several key functionalities:\n\n• Encryption Decryption: Handles cryptographic operations for data security\n• Network Communication: Manages network connections and data transmission",
  "metadata": {
    "file_path": "com/example/CryptoUtils.java",
    "file_type": "java",
    "labels": ["encryption_decryption", "network_communication"],
    "confidence": 0.85,
    "template_name": "code_explanation",
    "template_weight": 1.0,
    "generated_at": "2024-01-15T10:30:45.123456",
    "analysis_data_hash": "a1b2c3d4e5f6..."
  }
}
```

### Summary Report Format

When using the `--report` flag, a summary report is generated:

```json
{
  "total_pairs": 150,
  "java_pairs": 120,
  "so_pairs": 30,
  "template_distribution": {
    "code_explanation": 45,
    "security_analysis": 38,
    "functionality_labeling": 35,
    "pattern_identification": 20,
    "api_usage": 12
  },
  "label_distribution": {
    "encryption_decryption": 25,
    "network_communication": 40,
    "file_operations": 35,
    "authentication": 15
  },
  "confidence_distribution": {
    "high": 45,
    "medium": 80,
    "low": 25
  },
  "generated_at": "2024-01-15T10:35:20.123456"
}
```

## Pipeline Architecture

### Components

1. **APKAnalyzer Integration**: Leverages existing `utils/apk.py` functionality
2. **JavaCodeAnnotator**: Analyzes decompiled Java code for patterns and functionality
3. **SOCodeAnnotator**: Analyzes native libraries with optional PyGhidra integration
4. **PromptGenerator**: Creates diverse prompt/completion pairs for training
5. **APKLLMAnnotationPipeline**: Main orchestrator coordinating all components

### Processing Flow

```
APK File → APKAnalyzer → Decompilation
    ↓
Java Files → JavaCodeAnnotator → Annotations
    ↓
SO Files → SOCodeAnnotator → PyGhidra → Annotations
    ↓
All Annotations → PromptGenerator → Training Pairs
    ↓
JSONL Output + Summary Report
```

### Extensibility

The pipeline is designed to be modular and extensible:

#### Adding New Annotation Categories

1. **Extend Pattern Definitions**:
   ```python
   # In JavaCodeAnnotator or SOCodeAnnotator
   self.annotation_patterns['new_category'] = [
       'pattern1', 'pattern2', 'pattern3'
   ]
   ```

2. **Add Completion Generation Logic**:
   ```python
   # In PromptGenerator
   def _generate_new_category_completion(self, annotation):
       return "Custom completion for new category"
   ```

#### Adding New Prompt Templates

```python
# In PromptGenerator.__init__()
self.prompt_templates['custom_template'] = {
    'prompt': "Custom prompt template with {placeholders}",
    'weight': 1.0
}
```

#### Custom Analysis Integration

The pipeline can be extended to integrate additional analysis tools:

```python
# Create custom analyzer
class CustomAnalyzer:
    def analyze_code(self, code_content):
        # Custom analysis logic
        return analysis_results

# Integrate into pipeline
class ExtendedAPKLLMAnnotationPipeline(APKLLMAnnotationPipeline):
    def __init__(self):
        super().__init__()
        self.custom_analyzer = CustomAnalyzer()
```

## Examples

### Example 1: Basic APK Analysis

```bash
# Analyze a messaging app
python scripts/apk_llm_annotation_pipeline.py \
  --input-apk telegram.apk \
  --output telegram_training.jsonl \
  --report \
  --verbose
```

**Expected Output**:
- Training data with encryption, network, and file operation patterns
- High confidence annotations for messaging functionality
- Security analysis of cryptographic implementations

### Example 2: Batch Processing Security Apps

```bash
# Process multiple security-focused apps
python scripts/apk_llm_annotation_pipeline.py \
  --input-dir security_apps/ \
  --output-dir security_corpus/ \
  --max-java-files 75 \
  --max-so-files 15 \
  --report
```

**Expected Output**:
- Rich corpus with anti-analysis patterns
- Authentication and encryption implementations
- Network security protocols

### Example 3: Gaming Apps with Native Libraries

```bash
# Process games with native code
python scripts/apk_llm_annotation_pipeline.py \
  --input-dir games/ \
  --output games_training.jsonl \
  --max-so-files 25 \
  --verbose
```

**Expected Output**:
- JNI interface patterns
- Graphics and audio processing
- Memory management techniques
- Anti-cheat implementations

## Best Practices

### APK Selection

1. **Diverse Functionality**: Include APKs from different categories (social, games, utilities, security)
2. **Architecture Coverage**: Ensure representation of different Android architectures
3. **Size Considerations**: Balance between large feature-rich apps and processing time
4. **Legal Compliance**: Only analyze APKs you have legal rights to analyze

### Processing Configuration

1. **Resource Management**:
   ```bash
   # For large-scale processing
   --max-java-files 30 \
   --max-so-files 5 \
   --max-pairs-per-file 2
   ```

2. **Quality Focus**:
   ```bash
   # For high-quality annotations
   --max-java-files 75 \
   --max-so-files 15 \
   --max-pairs-per-file 5
   ```

### Training Data Quality

1. **Review Generated Data**: Manually review a sample of generated pairs
2. **Balance Categories**: Ensure diverse representation of functionality categories
3. **Filter Low Confidence**: Consider filtering pairs with very low confidence scores
4. **Deduplicate**: Remove duplicate or near-duplicate training examples

## Troubleshooting

### Common Issues

#### PyGhidra Not Available
```
Warning: pyghidra not available - advanced Ghidra analysis will be disabled
```
**Solution**: Install PyGhidra and Ghidra, set `GHIDRA_INSTALL_DIR` environment variable

#### JADX Decompilation Failures
```
Error: Jadx decompilation failed
```
**Solutions**:
- Ensure jadx is installed and in PATH
- Check APK file integrity
- Increase timeout for large APKs

#### Memory Issues
```
Error: Out of memory during processing
```
**Solutions**:
- Reduce `--max-java-files` and `--max-so-files`
- Process APKs individually instead of batch processing
- Increase available system memory

#### Low Training Data Quality
**Solutions**:
- Review and adjust annotation patterns
- Increase confidence thresholds
- Focus on high-quality APKs

### Performance Optimization

1. **Parallel Processing**: Process multiple APKs in parallel
2. **Selective Analysis**: Focus on specific file types or patterns
3. **Caching**: Cache expensive analysis results
4. **Resource Limits**: Set appropriate processing limits based on available resources

## Integration with ML Frameworks

### HuggingFace Transformers

```python
from datasets import Dataset

# Load training data
import json
training_data = []
with open('training_data.jsonl', 'r') as f:
    for line in f:
        training_data.append(json.loads(line))

# Create dataset
dataset = Dataset.from_list(training_data)

# Use with transformers
from transformers import AutoTokenizer, AutoModelForCausalLM
tokenizer = AutoTokenizer.from_pretrained("your-model")
model = AutoModelForCausalLM.from_pretrained("your-model")
```

### Custom Training Loops

```python
# Example training loop integration
def prepare_training_batch(pairs):
    prompts = [pair['prompt'] for pair in pairs]
    completions = [pair['completion'] for pair in pairs]
    return prompts, completions

# Load and process training data
with open('training_data.jsonl', 'r') as f:
    pairs = [json.loads(line) for line in f]

prompts, completions = prepare_training_batch(pairs)
```

## Future Enhancements

### Planned Features

1. **ML-Based Annotation**: Use pre-trained models for enhanced pattern recognition
2. **Dynamic Analysis Integration**: Incorporate runtime behavior analysis
3. **Multi-Language Support**: Extend beyond Java to Kotlin, C++, etc.
4. **Custom Labeling**: Support for user-defined annotation categories
5. **Quality Metrics**: Automated quality assessment of generated training data

### Contributing

The pipeline is designed to be extensible. Contributions are welcome for:

- New annotation patterns and categories
- Additional prompt templates
- Integration with other analysis tools
- Performance optimizations
- Quality improvements

## Legal and Ethical Considerations

### Important Disclaimers

⚠️ **LEGAL COMPLIANCE REQUIRED**: Only analyze APKs that you have legal rights to analyze. This includes:
- APKs you have developed
- APKs explicitly licensed for analysis
- APKs with explicit permission from the copyright holder

⚠️ **EDUCATIONAL PURPOSE**: This tool is intended for educational and authorized security research purposes only.

### Best Practices

1. **Obtain Proper Authorization**: Always ensure you have legal rights to analyze APKs
2. **Respect Privacy**: Do not extract or process personal or sensitive user data
3. **Responsible Disclosure**: Follow responsible disclosure practices for any vulnerabilities found
4. **Data Handling**: Securely handle and dispose of analysis results

### Compliance Guidelines

- **Corporate Use**: Ensure compliance with corporate policies and legal requirements
- **Academic Research**: Follow institutional research ethics guidelines
- **Commercial Use**: Obtain appropriate licenses and permissions
- **International Law**: Comply with applicable international and local laws

## Support and Resources

### Documentation
- **Project Repository**: Full source code and documentation
- **Issue Tracker**: Report bugs and request features
- **Wiki**: Additional examples and tutorials

### Community
- **Discussions**: Ask questions and share experiences
- **Contributing Guide**: How to contribute to the project
- **Security Policy**: Responsible disclosure guidelines

### Related Tools
- **Main reD2 Framework**: Full APK analysis capabilities
- **PyGhidra**: Advanced reverse engineering integration
- **Security LLM Training**: Complementary security corpus generation

---

*This documentation is part of the reD2 project. For the latest updates and complete documentation, visit the project repository.*