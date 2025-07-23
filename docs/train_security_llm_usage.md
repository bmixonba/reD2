# Security LLM Training Script Usage Guide

## Overview

The `scripts/train_security_llm.py` script provides a focused, streamlined implementation for training security-specialized Large Language Models using JSONL corpus data with prompt/completion pairs.

## Features

- **JSONL Corpus Loading**: Loads security corpus data from JSONL files
- **Data Preprocessing**: Tokenization and formatting for instruction-following tasks
- **Model Loading**: Support for various HuggingFace models (CodeLlama, GPT, etc.)
- **LoRA/PEFT**: Parameter-efficient fine-tuning with configurable parameters
- **HuggingFace Integration**: Full Trainer API support with comprehensive configuration
- **Reproducibility**: Saves training configuration and model artifacts
- **Error Handling**: Robust error handling and logging

## Quick Start

### 1. Prepare Your Data

Create a JSONL file with prompt/completion pairs:

```jsonl
{"prompt": "What is SQL injection?", "completion": "SQL injection is a code injection technique..."}
{"prompt": "Explain buffer overflow", "completion": "Buffer overflow occurs when a program writes more data..."}
```

### 2. Basic Training

```bash
python scripts/train_security_llm.py \
    --train_data your_security_corpus.jsonl \
    --model_name codellama/CodeLlama-7b-Instruct-hf \
    --output_dir ./trained_model \
    --use_lora
```

### 3. Advanced Configuration

```bash
python scripts/train_security_llm.py \
    --train_data security_corpus.jsonl \
    --model_name microsoft/DialoGPT-medium \
    --output_dir ./security_model \
    --num_epochs 5 \
    --batch_size 8 \
    --learning_rate 3e-4 \
    --max_length 1024 \
    --use_lora \
    --lora_rank 32 \
    --lora_alpha 64 \
    --validation_split 0.15
```

## Command Line Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--train_data` | Required | Path to JSONL training corpus |
| `--model_name` | `codellama/CodeLlama-7b-Instruct-hf` | HuggingFace model name |
| `--output_dir` | `./trained_security_model` | Output directory for trained model |
| `--num_epochs` | `3` | Number of training epochs |
| `--batch_size` | `4` | Training batch size per device |
| `--learning_rate` | `2e-4` | Learning rate for training |
| `--max_length` | `512` | Maximum sequence length |
| `--use_lora` | `False` | Enable LoRA fine-tuning |
| `--lora_rank` | `16` | LoRA rank parameter |
| `--lora_alpha` | `32` | LoRA alpha parameter |
| `--validation_split` | `0.1` | Fraction for validation set |

## Data Format

### JSONL Format
Each line should be a valid JSON object with `prompt` and `completion` fields:

```jsonl
{"prompt": "Explain what XSS is", "completion": "Cross-site scripting (XSS) is a vulnerability..."}
{"prompt": "How to prevent SQL injection?", "completion": "SQL injection can be prevented through..."}
```

### Instruction Format
The script automatically formats data as instruction-following prompts:

```
### Instruction:
{prompt}

### Response:
{completion}
```

## Output Structure

After training, the output directory contains:

```
trained_security_model/
├── pytorch_model.bin          # Model weights
├── config.json               # Model configuration
├── tokenizer.json            # Tokenizer configuration
├── training_config.json      # Training parameters
└── README.md                 # Usage instructions
```

## Example Usage Scenarios

### 1. Training on Security Datasets

```bash
# Use prepared security corpus
python scripts/train_security_llm.py \
    --train_data datasets/metasploit_corpus.jsonl \
    --model_name codellama/CodeLlama-7b-Instruct-hf \
    --output_dir ./security_codellama \
    --use_lora \
    --num_epochs 3
```

### 2. Fine-tuning for Specific Tasks

```bash
# Focus on vulnerability analysis
python scripts/train_security_llm.py \
    --train_data vulnerability_analysis.jsonl \
    --model_name microsoft/DialoGPT-medium \
    --output_dir ./vuln_analyzer \
    --learning_rate 1e-4 \
    --batch_size 2
```

### 3. Quick Prototyping

```bash
# Fast training for testing
python scripts/train_security_llm.py \
    --train_data small_corpus.jsonl \
    --model_name distilgpt2 \
    --output_dir ./prototype \
    --num_epochs 1 \
    --batch_size 8
```

## Using Trained Models

After training, load and use your model:

```python
from transformers import AutoTokenizer, AutoModelForCausalLM

# Load the trained model
tokenizer = AutoTokenizer.from_pretrained("./trained_security_model")
model = AutoModelForCausalLM.from_pretrained("./trained_security_model")

# Generate security responses
prompt = "### Instruction:\nExplain privilege escalation\n\n### Response:\n"
inputs = tokenizer(prompt, return_tensors="pt")
outputs = model.generate(**inputs, max_length=200, temperature=0.7)
response = tokenizer.decode(outputs[0], skip_special_tokens=True)
print(response)
```

## Integration with Existing Scripts

This script complements the existing security LLM framework:

1. **Data Collection**: Use `harvest_metasploit_pocs.py` to gather data
2. **Data Preparation**: Use `prepare_security_corpus.py` to format data
3. **Training**: Use `train_security_llm.py` (this script) for focused training
4. **Advanced Training**: Use `finetune_sec_llm.py` for comprehensive training

## Performance Tips

1. **GPU Memory**: Use smaller batch sizes if running out of memory
2. **LoRA Benefits**: Enable `--use_lora` for faster training and lower memory usage
3. **Sequence Length**: Adjust `--max_length` based on your data characteristics
4. **Validation**: Use appropriate `--validation_split` to monitor training progress

## Troubleshooting

### Common Issues

1. **Out of Memory**: Reduce `--batch_size` or enable `--use_lora`
2. **Slow Training**: Increase `--batch_size` or use more GPUs
3. **Poor Quality**: Increase `--num_epochs` or adjust `--learning_rate`
4. **Data Issues**: Verify JSONL format and prompt/completion fields

### Requirements

```bash
pip install transformers>=4.30.0 torch>=2.0.0 datasets>=2.0.0 peft>=0.4.0 accelerate>=0.20.0
```

## Differences from finetune_sec_llm.py

| Feature | train_security_llm.py | finetune_sec_llm.py |
|---------|----------------------|---------------------|
| Focus | Streamlined training | Comprehensive framework |
| Complexity | Simple, focused | Advanced, full-featured |
| Ethical Features | Basic | Extensive safeguards |
| Monitoring | Basic logging | WandB integration |
| Use Case | Quick training | Production systems |