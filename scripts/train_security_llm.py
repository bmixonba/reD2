#!/usr/bin/env python3
"""
Training Script for Security-Specialized LLM

This script implements a focused training pipeline for security-specialized Large Language Models
using a JSONL security corpus with prompt/completion pairs. It leverages LoRA/PEFT for 
parameter-efficient fine-tuning and HuggingFace Transformers for training.

Features:
- JSONL security corpus loading and preprocessing
- Tokenization with configurable sequence lengths
- Base LLM loading (CodeLlama-7b, other HuggingFace models)
- LoRA/PEFT parameter-efficient fine-tuning
- HuggingFace Transformers Trainer integration
- Model and tokenizer saving with reproducible configuration
- Comprehensive logging and error handling

Usage:
    python scripts/train_security_llm.py \
        --train_data security_corpus.jsonl \
        --model_name codellama/CodeLlama-7b-Instruct-hf \
        --output_dir ./trained_security_model \
        --use_lora

Requirements:
    - transformers>=4.30.0
    - torch>=2.0.0  
    - datasets>=2.0.0
    - peft>=0.4.0
    - accelerate>=0.20.0
"""

import os
import sys
import json
import argparse
import logging
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass
import torch

# Add parent directory for module imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Core ML/AI dependencies with graceful fallback
try:
    from transformers import (
        AutoTokenizer, 
        AutoModelForCausalLM, 
        TrainingArguments, 
        Trainer,
        DataCollatorForLanguageModeling
    )
    from datasets import Dataset
    HF_AVAILABLE = True
except ImportError as e:
    print(f"ERROR: HuggingFace Transformers not available: {e}")
    print("Install with: pip install transformers datasets")
    HF_AVAILABLE = False

try:
    from peft import LoraConfig, get_peft_model, TaskType
    PEFT_AVAILABLE = True
except ImportError:
    print("WARNING: PEFT not available. LoRA fine-tuning will be disabled.")
    print("Install with: pip install peft")
    PEFT_AVAILABLE = False

@dataclass
class TrainingConfig:
    """Training configuration with all necessary parameters for reproducibility."""
    
    # Data configuration
    train_data_path: str
    validation_split: float = 0.1
    max_sequence_length: int = 512
    
    # Model configuration  
    model_name: str = "codellama/CodeLlama-7b-Instruct-hf"
    output_dir: str = "./trained_security_model"
    
    # Training hyperparameters
    num_epochs: int = 3
    batch_size: int = 4
    gradient_accumulation_steps: int = 4
    learning_rate: float = 2e-4
    warmup_steps: int = 100
    weight_decay: float = 0.01
    
    # LoRA/PEFT configuration
    use_lora: bool = True
    lora_rank: int = 16
    lora_alpha: int = 32
    lora_dropout: float = 0.1
    target_modules: List[str] = None
    
    # Training configuration
    save_steps: int = 500
    eval_steps: int = 500
    logging_steps: int = 100
    fp16: bool = True
    
    def __post_init__(self):
        """Set default target modules for LoRA if not specified."""
        if self.target_modules is None:
            # Common target modules for CodeLlama and similar models
            self.target_modules = [
                "q_proj", "k_proj", "v_proj", "o_proj",
                "gate_proj", "up_proj", "down_proj"
            ]


class SecurityLLMTrainer:
    """
    Focused trainer for security-specialized LLMs using JSONL corpus data.
    
    This class provides a streamlined interface for training security-focused
    language models with proper tokenization, LoRA fine-tuning, and model persistence.
    """
    
    def __init__(self, config: TrainingConfig):
        """Initialize trainer with configuration."""
        self.config = config
        self.logger = self._setup_logging()
        
        # Validate dependencies
        if not HF_AVAILABLE:
            raise ImportError("HuggingFace Transformers required for training")
        
        if config.use_lora and not PEFT_AVAILABLE:
            self.logger.warning("PEFT not available, disabling LoRA")
            config.use_lora = False
            
        # Initialize components
        self.tokenizer = None
        self.model = None
        self.train_dataset = None
        self.eval_dataset = None
        
    def _setup_logging(self) -> logging.Logger:
        """Configure logging for reproducible training runs."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        return logging.getLogger(__name__)
    
    def load_jsonl_corpus(self) -> None:
        """
        Load and preprocess JSONL security corpus.
        
        Expected format: {"prompt": "...", "completion": "..."}
        """
        self.logger.info(f"Loading JSONL corpus from {self.config.train_data_path}")
        
        if not os.path.exists(self.config.train_data_path):
            raise FileNotFoundError(f"Training data not found: {self.config.train_data_path}")
        
        # Load JSONL data
        data = []
        with open(self.config.train_data_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                    
                try:
                    sample = json.loads(line)
                    if 'prompt' in sample and 'completion' in sample:
                        data.append(sample)
                    else:
                        self.logger.warning(f"Line {line_num}: Missing prompt/completion fields")
                except json.JSONDecodeError:
                    self.logger.warning(f"Line {line_num}: Invalid JSON")
        
        if not data:
            raise ValueError("No valid training samples found in corpus")
            
        self.logger.info(f"Loaded {len(data)} training samples")
        
        # Split into train/validation
        split_idx = int(len(data) * (1 - self.config.validation_split))
        train_data = data[:split_idx]
        eval_data = data[split_idx:] if split_idx < len(data) else []
        
        # Create datasets
        self.train_dataset = Dataset.from_list(train_data)
        if eval_data:
            self.eval_dataset = Dataset.from_list(eval_data)
            self.logger.info(f"Created validation set with {len(eval_data)} samples")
        else:
            self.eval_dataset = None
            self.logger.info("No validation set created (insufficient data)")
    
    def load_and_setup_model(self) -> None:
        """Load base model and configure for training."""
        self.logger.info(f"Loading model: {self.config.model_name}")
        
        # Load tokenizer
        self.tokenizer = AutoTokenizer.from_pretrained(self.config.model_name)
        
        # Ensure pad token exists
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token
            self.logger.info("Set pad_token to eos_token")
        
        # Load model with appropriate precision
        device_map = "auto" if torch.cuda.is_available() else None
        torch_dtype = torch.float16 if torch.cuda.is_available() else torch.float32
        
        self.model = AutoModelForCausalLM.from_pretrained(
            self.config.model_name,
            torch_dtype=torch_dtype,
            device_map=device_map,
            trust_remote_code=True
        )
        
        # Apply LoRA if configured
        if self.config.use_lora:
            self._apply_lora()
        
        # Log model info
        num_params = sum(p.numel() for p in self.model.parameters())
        trainable_params = sum(p.numel() for p in self.model.parameters() if p.requires_grad)
        
        self.logger.info(f"Model loaded - Total params: {num_params:,}")
        self.logger.info(f"Trainable params: {trainable_params:,} ({100*trainable_params/num_params:.2f}%)")
    
    def _apply_lora(self) -> None:
        """Apply LoRA configuration for parameter-efficient fine-tuning."""
        self.logger.info("Applying LoRA configuration")
        
        lora_config = LoraConfig(
            task_type=TaskType.CAUSAL_LM,
            r=self.config.lora_rank,
            lora_alpha=self.config.lora_alpha,
            lora_dropout=self.config.lora_dropout,
            target_modules=self.config.target_modules,
            bias="none"
        )
        
        self.model = get_peft_model(self.model, lora_config)
        self.model.print_trainable_parameters()
    
    def tokenize_dataset(self) -> None:
        """Tokenize datasets for training."""
        self.logger.info("Tokenizing datasets...")
        
        def tokenize_function(examples):
            """Tokenize prompt/completion pairs into training format."""
            # Format as instruction-following prompt
            formatted_texts = []
            for prompt, completion in zip(examples['prompt'], examples['completion']):
                text = f"### Instruction:\n{prompt}\n\n### Response:\n{completion}"
                formatted_texts.append(text)
            
            # Tokenize with truncation and padding
            tokenized = self.tokenizer(
                formatted_texts,
                truncation=True,
                max_length=self.config.max_sequence_length,
                padding=False,
                return_tensors=None
            )
            
            # For causal LM, labels are the same as input_ids
            tokenized["labels"] = tokenized["input_ids"].copy()
            
            return tokenized
        
        # Apply tokenization
        self.train_dataset = self.train_dataset.map(
            tokenize_function,
            batched=True,
            remove_columns=self.train_dataset.column_names
        )
        
        if self.eval_dataset:
            self.eval_dataset = self.eval_dataset.map(
                tokenize_function,
                batched=True,
                remove_columns=self.eval_dataset.column_names
            )
        
        self.logger.info("Tokenization complete")
    
    def train_model(self) -> None:
        """Train the model using HuggingFace Trainer."""
        self.logger.info("Starting model training...")
        
        # Create output directory
        os.makedirs(self.config.output_dir, exist_ok=True)
        
        # Setup training arguments
        training_args = TrainingArguments(
            output_dir=self.config.output_dir,
            num_train_epochs=self.config.num_epochs,
            per_device_train_batch_size=self.config.batch_size,
            per_device_eval_batch_size=self.config.batch_size,
            gradient_accumulation_steps=self.config.gradient_accumulation_steps,
            learning_rate=self.config.learning_rate,
            warmup_steps=self.config.warmup_steps,
            weight_decay=self.config.weight_decay,
            logging_steps=self.config.logging_steps,
            save_steps=self.config.save_steps,
            eval_steps=self.config.eval_steps if self.eval_dataset else None,
            evaluation_strategy="steps" if self.eval_dataset else "no",
            save_strategy="steps",
            load_best_model_at_end=True if self.eval_dataset else False,
            metric_for_best_model="eval_loss" if self.eval_dataset else None,
            fp16=self.config.fp16 and torch.cuda.is_available(),
            dataloader_pin_memory=False,
            report_to="none",  # Disable wandb for focused training
            remove_unused_columns=False,
        )
        
        # Setup data collator
        data_collator = DataCollatorForLanguageModeling(
            tokenizer=self.tokenizer,
            mlm=False,  # Causal LM, not masked LM
            pad_to_multiple_of=8
        )
        
        # Create trainer
        trainer = Trainer(
            model=self.model,
            args=training_args,
            train_dataset=self.train_dataset,
            eval_dataset=self.eval_dataset,
            tokenizer=self.tokenizer,
            data_collator=data_collator,
        )
        
        # Train the model
        try:
            trainer.train()
            self.logger.info("Training completed successfully")
            
            # Save final model and tokenizer
            self.save_model_and_tokenizer(trainer)
            
        except Exception as e:
            self.logger.error(f"Training failed: {e}")
            raise
    
    def save_model_and_tokenizer(self, trainer: Trainer) -> None:
        """Save trained model, tokenizer, and configuration for reproducibility."""
        self.logger.info(f"Saving model and tokenizer to {self.config.output_dir}")
        
        # Save model and tokenizer
        trainer.save_model()
        self.tokenizer.save_pretrained(self.config.output_dir)
        
        # Save training configuration for reproducibility
        config_dict = {
            "model_name": self.config.model_name,
            "train_data_path": self.config.train_data_path,
            "max_sequence_length": self.config.max_sequence_length,
            "num_epochs": self.config.num_epochs,
            "batch_size": self.config.batch_size,
            "learning_rate": self.config.learning_rate,
            "use_lora": self.config.use_lora,
            "lora_rank": self.config.lora_rank if self.config.use_lora else None,
            "lora_alpha": self.config.lora_alpha if self.config.use_lora else None,
            "target_modules": self.config.target_modules if self.config.use_lora else None,
        }
        
        config_path = os.path.join(self.config.output_dir, "training_config.json")
        with open(config_path, 'w') as f:
            json.dump(config_dict, f, indent=2)
        
        # Save README with usage instructions
        readme_content = f"""# Security-Specialized LLM Training Results

## Model Information
- **Base Model**: {self.config.model_name}
- **Training Data**: {self.config.train_data_path}
- **Training Method**: {"LoRA Fine-tuning" if self.config.use_lora else "Full Fine-tuning"}

## Training Configuration
- **Epochs**: {self.config.num_epochs}
- **Batch Size**: {self.config.batch_size}
- **Learning Rate**: {self.config.learning_rate}
- **Max Sequence Length**: {self.config.max_sequence_length}

## Usage

```python
from transformers import AutoTokenizer, AutoModelForCausalLM

# Load the trained model
tokenizer = AutoTokenizer.from_pretrained("{self.config.output_dir}")
model = AutoModelForCausalLM.from_pretrained("{self.config.output_dir}")

# Example usage
prompt = "### Instruction:\\nExplain SQL injection vulnerabilities\\n\\n### Response:\\n"
inputs = tokenizer(prompt, return_tensors="pt")
outputs = model.generate(**inputs, max_length=200, temperature=0.7)
response = tokenizer.decode(outputs[0], skip_special_tokens=True)
print(response)
```

## Files
- `pytorch_model.bin` / `model.safetensors` - Trained model weights
- `tokenizer.json` - Tokenizer configuration
- `config.json` - Model configuration
- `training_config.json` - Training parameters for reproducibility
- `README.md` - This file
"""
        
        readme_path = os.path.join(self.config.output_dir, "README.md")
        with open(readme_path, 'w') as f:
            f.write(readme_content)
        
        self.logger.info("Model, tokenizer, and documentation saved successfully")


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments for training configuration."""
    parser = argparse.ArgumentParser(
        description="Train security-specialized LLM from JSONL corpus",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Required arguments
    parser.add_argument(
        "--train_data", 
        required=True,
        help="Path to JSONL training corpus with prompt/completion pairs"
    )
    
    # Model configuration
    parser.add_argument(
        "--model_name",
        default="codellama/CodeLlama-7b-Instruct-hf",
        help="HuggingFace model name for base LLM"
    )
    
    parser.add_argument(
        "--output_dir",
        default="./trained_security_model",
        help="Directory to save trained model and tokenizer"
    )
    
    # Training hyperparameters
    parser.add_argument(
        "--num_epochs",
        type=int,
        default=3,
        help="Number of training epochs"
    )
    
    parser.add_argument(
        "--batch_size",
        type=int,
        default=4,
        help="Training batch size per device"
    )
    
    parser.add_argument(
        "--learning_rate",
        type=float,
        default=2e-4,
        help="Learning rate for training"
    )
    
    parser.add_argument(
        "--max_length",
        type=int,
        default=512,
        help="Maximum sequence length for tokenization"
    )
    
    # LoRA/PEFT configuration
    parser.add_argument(
        "--use_lora",
        action="store_true",
        help="Enable LoRA parameter-efficient fine-tuning"
    )
    
    parser.add_argument(
        "--lora_rank",
        type=int,
        default=16,
        help="LoRA rank parameter"
    )
    
    parser.add_argument(
        "--lora_alpha",
        type=int,
        default=32,
        help="LoRA alpha parameter"
    )
    
    # Data configuration
    parser.add_argument(
        "--validation_split",
        type=float,
        default=0.1,
        help="Fraction of data to use for validation"
    )
    
    return parser.parse_args()


def main():
    """Main training function."""
    print("🔒 Security LLM Training Pipeline")
    print("=" * 50)
    
    # Parse arguments
    args = parse_arguments()
    
    # Create training configuration
    config = TrainingConfig(
        train_data_path=args.train_data,
        model_name=args.model_name,
        output_dir=args.output_dir,
        num_epochs=args.num_epochs,
        batch_size=args.batch_size,
        learning_rate=args.learning_rate,
        max_sequence_length=args.max_length,
        use_lora=args.use_lora,
        lora_rank=args.lora_rank,
        lora_alpha=args.lora_alpha,
        validation_split=args.validation_split,
    )
    
    try:
        # Initialize trainer
        trainer = SecurityLLMTrainer(config)
        
        # Execute training pipeline
        trainer.load_jsonl_corpus()
        trainer.load_and_setup_model()
        trainer.tokenize_dataset()
        trainer.train_model()
        
        print("\n✅ Training completed successfully!")
        print(f"📁 Model saved to: {config.output_dir}")
        
    except Exception as e:
        print(f"\n❌ Training failed: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())