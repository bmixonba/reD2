# Security LLM Training Framework

This framework provides tools for harvesting Metasploit Framework proof-of-concepts (PoCs) and preparing them for Large Language Model (LLM) training focused on security research and ethical hacking education.

## Project Structure

```
reD2/
├── scripts/                          # Security LLM training scripts
│   ├── __init__.py                   # Package initialization
│   ├── harvest_metasploit_pocs.py    # Metasploit PoC harvesting script
│   ├── prepare_security_corpus.py    # Dataset preparation and annotation
│   └── finetune_sec_llm.py          # HuggingFace fine-tuning with PEFT/LoRA
├── docs/                             # Documentation
│   ├── project_structure.md          # This file
│   ├── dataset_schema.md             # Dataset format documentation
│   ├── prompt_templates.md           # Example prompt templates
│   └── ethical_guidelines.md         # Ethical and legal guidelines
├── main.py                           # Original APK analysis tool
├── utils/                            # Utility modules for APK analysis
└── requirements.txt                  # Python dependencies
```

## Components Overview

### 1. Metasploit PoC Harvester (`harvest_metasploit_pocs.py`)

Clones the Metasploit Framework repository and extracts exploit modules with metadata annotation.

**Features:**
- Clones/updates Metasploit Framework repository
- Extracts metadata from Ruby modules
- Parses vulnerability information (CVEs, references, targets)
- Analyzes security patterns and technical details
- Generates training annotations and prompt-completion pairs
- Outputs structured JSONL dataset

**Usage:**
```bash
# Basic harvesting
python scripts/harvest_metasploit_pocs.py --output metasploit_dataset.jsonl

# Limited harvesting with specific categories
python scripts/harvest_metasploit_pocs.py --limit 100 --categories exploits auxiliary

# Verbose mode with custom output directory
python scripts/harvest_metasploit_pocs.py --verbose --clone-dir /tmp/msf --keep-clone
```

### 2. Security Corpus Preparator (`prepare_security_corpus.py`)

Merges and annotates datasets for prompt/completion-based LLM training.

**Features:**
- Loads and merges multiple datasets
- Generates diverse prompt-completion pairs
- Applies content filtering and validation
- Creates ethical context annotations
- Supports multiple output formats

**Usage:**
```bash
# Prepare training corpus from harvested data
python scripts/prepare_security_corpus.py --input metasploit_dataset.jsonl --output training_corpus.jsonl

# Merge multiple datasets
python scripts/prepare_security_corpus.py --merge-datasets dataset1.jsonl dataset2.jsonl --output combined_corpus.jsonl

# Custom configuration with statistics
python scripts/prepare_security_corpus.py --input data.jsonl --samples-per-item 5 --stats-output stats.json
```

### 3. Security LLM Fine-tuner (`finetune_sec_llm.py`)

Fine-tunes language models using HuggingFace Transformers with PEFT/LoRA for efficient training.

**Features:**
- Supports various base models (CodeLlama, DialoGPT, etc.)
- PEFT/LoRA integration for efficient fine-tuning
- Content filtering and ethical safeguards
- Weights & Biases integration for monitoring
- Automatic evaluation and sample generation

**Usage:**
```bash
# Basic fine-tuning
python scripts/finetune_sec_llm.py --train-data training_corpus.jsonl --model-name microsoft/DialoGPT-medium

# Advanced fine-tuning with LoRA
python scripts/finetune_sec_llm.py --train-data corpus.jsonl --model-name codellama/CodeLlama-7b-Instruct-hf --use-lora

# Custom configuration
python scripts/finetune_sec_llm.py --train-data corpus.jsonl --epochs 5 --batch-size 8 --use-wandb
```

## Data Flow

1. **Harvest**: Extract Metasploit modules → Raw dataset (JSONL)
2. **Prepare**: Annotate and format → Training corpus (JSONL)
3. **Train**: Fine-tune LLM → Security-focused model
4. **Evaluate**: Test and validate → Ethical deployment

## Ethical Considerations

All components include built-in ethical safeguards:

- **Content Filtering**: Removes inappropriate or dangerous content
- **Ethical Context**: Adds educational disclaimers and usage guidelines
- **Authorization Requirements**: Emphasizes need for proper authorization
- **Legal Compliance**: Ensures adherence to applicable laws
- **Responsible Disclosure**: Promotes ethical security research practices

## Security Features

- **Risk Assessment**: Modules are classified by risk level (low/medium/high)
- **Educational Value**: Content is ranked for training effectiveness
- **Complexity Analysis**: Technical complexity is assessed and labeled
- **Pattern Recognition**: Security patterns are identified and categorized
- **CVE Integration**: Vulnerability references are extracted and preserved

## Output Formats

All scripts support both JSON and JSONL formats for maximum compatibility with various ML training frameworks.

## Integration with Existing reD2

The security LLM framework extends the existing reD2 APK analysis tool:

- **Complementary**: Adds security training capabilities to mobile analysis
- **Modular**: Can be used independently or integrated with APK workflows
- **Consistent**: Uses similar patterns and utilities as the main codebase
- **Extensible**: Framework can be expanded to other security datasets

## Future Extensions

The framework is designed for expansion:

- **Additional Sources**: CVE databases, security advisories, research papers
- **Multiple Languages**: Support for Python, C/C++, JavaScript security code
- **Specialized Models**: Domain-specific fine-tuning for different security areas
- **Interactive Training**: Reinforcement learning from human feedback (RLHF)
- **Multi-modal**: Integration with binary analysis and reverse engineering

## Dependencies

Core dependencies for full functionality:

```
transformers>=4.30.0
torch>=2.0.0
datasets>=2.0.0
peft>=0.4.0
wandb>=0.15.0
```

See `requirements.txt` for complete dependency list.