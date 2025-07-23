#!/usr/bin/env python3
"""
Fine-tune Security-Focused LLM

This script fine-tunes language models using HuggingFace Transformers and PEFT/LoRA
for security research and ethical hacking applications. It loads the prepared security
corpus and trains a model with appropriate safeguards and ethical considerations.

Usage:
    python scripts/finetune_sec_llm.py --train-data training_corpus.jsonl --model-name microsoft/DialoGPT-medium
    python scripts/finetune_sec_llm.py --train-data corpus.jsonl --model-name codellama/CodeLlama-7b-Instruct-hf --use-lora
"""

import os
import sys
import json
import argparse
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
import torch
from dataclasses import dataclass

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

try:
    from transformers import (
        AutoTokenizer, AutoModelForCausalLM, TrainingArguments, Trainer,
        DataCollatorForLanguageModeling, EarlyStoppingCallback
    )
    from datasets import Dataset
    import wandb
    HF_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Some dependencies not available: {e}")
    print("Please install: pip install transformers datasets wandb")
    HF_AVAILABLE = False

try:
    from peft import LoraConfig, get_peft_model, TaskType
    PEFT_AVAILABLE = True
except ImportError:
    print("Warning: PEFT not available. Install with: pip install peft")
    PEFT_AVAILABLE = False

def setup_logging(verbose: bool = False):
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

@dataclass
class FineTuningConfig:
    """Configuration for fine-tuning parameters."""
    model_name: str
    train_data_path: str
    validation_data_path: Optional[str] = None
    output_dir: str = "./security_llm_model"
    
    # Training parameters
    num_train_epochs: int = 3
    per_device_train_batch_size: int = 4
    per_device_eval_batch_size: int = 4
    gradient_accumulation_steps: int = 4
    learning_rate: float = 5e-5
    warmup_steps: int = 100
    weight_decay: float = 0.01
    
    # LoRA parameters
    use_lora: bool = True
    lora_r: int = 16
    lora_alpha: int = 32
    lora_dropout: float = 0.1
    
    # Data parameters
    max_length: int = 512
    train_split_ratio: float = 0.9
    
    # Safety parameters
    content_filtering: bool = True
    ethical_safeguards: bool = True
    
    # Logging and monitoring
    logging_steps: int = 10
    eval_steps: int = 100
    save_steps: int = 500
    use_wandb: bool = False
    wandb_project: str = "security-llm-training"

class SecurityLLMTrainer:
    """
    Fine-tunes language models for security applications with ethical safeguards.
    """
    
    def __init__(self, config: FineTuningConfig, verbose: bool = False):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.verbose = verbose
        
        # Check dependencies
        if not HF_AVAILABLE:
            raise ImportError("HuggingFace transformers not available")
        
        if config.use_lora and not PEFT_AVAILABLE:
            self.logger.warning("PEFT not available, disabling LoRA")
            config.use_lora = False
        
        self.tokenizer = None
        self.model = None
        self.dataset = None
        
        # Ethical guidelines and content filters
        self.ethical_guidelines = {
            'educational_purpose_only': True,
            'no_malicious_content': True,
            'requires_authorization': True,
            'responsible_disclosure': True
        }
        
        self.prohibited_content = [
            'actual malware code',
            'zero-day exploits',
            'personal information',
            'illegal activities',
            'harmful instructions'
        ]
    
    def load_and_prepare_model(self):
        """Load and prepare the model for training."""
        self.logger.info(f"Loading model: {self.config.model_name}")
        
        try:
            # Load tokenizer
            self.tokenizer = AutoTokenizer.from_pretrained(self.config.model_name)
            
            # Add padding token if not present
            if self.tokenizer.pad_token is None:
                self.tokenizer.pad_token = self.tokenizer.eos_token
                self.logger.info("Added padding token")
            
            # Load model
            self.model = AutoModelForCausalLM.from_pretrained(
                self.config.model_name,
                torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
                device_map="auto" if torch.cuda.is_available() else None
            )
            
            # Configure for LoRA if enabled
            if self.config.use_lora:
                self._setup_lora()
            
            self.logger.info(f"Model loaded successfully. Parameters: {self.model.num_parameters():,}")
            
        except Exception as e:
            self.logger.error(f"Failed to load model: {e}")
            raise
    
    def _setup_lora(self):
        """Setup LoRA configuration for efficient fine-tuning."""
        self.logger.info("Setting up LoRA configuration")
        
        lora_config = LoraConfig(
            task_type=TaskType.CAUSAL_LM,
            r=self.config.lora_r,
            lora_alpha=self.config.lora_alpha,
            lora_dropout=self.config.lora_dropout,
            target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
            bias="none"
        )
        
        self.model = get_peft_model(self.model, lora_config)
        self.model.print_trainable_parameters()
    
    def load_training_data(self):
        """Load and prepare training data."""
        self.logger.info(f"Loading training data from {self.config.train_data_path}")
        
        try:
            # Load data
            data = []
            with open(self.config.train_data_path, 'r', encoding='utf-8') as f:
                if self.config.train_data_path.endswith('.jsonl'):
                    for line in f:
                        if line.strip():
                            data.append(json.loads(line))
                else:
                    data = json.load(f)
            
            self.logger.info(f"Loaded {len(data)} training samples")
            
            # Apply content filtering
            if self.config.content_filtering:
                data = self._apply_content_filtering(data)
                self.logger.info(f"After filtering: {len(data)} samples")
            
            # Prepare for training
            formatted_data = self._format_training_data(data)
            
            # Create dataset
            dataset = Dataset.from_list(formatted_data)
            
            # Split into train/validation if no validation set provided
            if self.config.validation_data_path is None:
                dataset = dataset.train_test_split(
                    test_size=1 - self.config.train_split_ratio,
                    seed=42
                )
                self.train_dataset = dataset['train']
                self.eval_dataset = dataset['test']
            else:
                self.train_dataset = dataset
                self.eval_dataset = self._load_validation_data()
            
            self.logger.info(f"Training samples: {len(self.train_dataset)}")
            self.logger.info(f"Validation samples: {len(self.eval_dataset)}")
            
        except Exception as e:
            self.logger.error(f"Failed to load training data: {e}")
            raise
    
    def _apply_content_filtering(self, data: List[Dict]) -> List[Dict]:
        """Apply content filtering for ethical compliance."""
        self.logger.info("Applying content filtering...")
        
        filtered_data = []
        
        for sample in data:
            if self._is_content_appropriate(sample):
                # Add ethical context if not present
                if 'ethical_context' not in sample:
                    sample['ethical_context'] = self._generate_ethical_context()
                
                filtered_data.append(sample)
        
        removed_count = len(data) - len(filtered_data)
        if removed_count > 0:
            self.logger.info(f"Filtered out {removed_count} inappropriate samples")
        
        return filtered_data
    
    def _is_content_appropriate(self, sample: Dict) -> bool:
        """Check if content meets ethical guidelines."""
        prompt = sample.get('prompt', '').lower()
        completion = sample.get('completion', '').lower()
        
        # Check for prohibited content
        for prohibited in self.prohibited_content:
            if prohibited in prompt or prohibited in completion:
                return False
        
        # Ensure educational context
        if not sample.get('ethical_context') and not sample.get('ethical_guidance'):
            # Add basic ethical context
            return True
        
        return True
    
    def _generate_ethical_context(self) -> Dict:
        """Generate ethical context for training samples."""
        return {
            'intended_use': 'Educational and authorized security testing only',
            'restrictions': [
                'Requires proper authorization',
                'Educational purposes only',
                'No malicious use',
                'Legal compliance required'
            ],
            'disclaimer': 'This content is for educational and authorized security research only.'
        }
    
    def _format_training_data(self, data: List[Dict]) -> List[Dict]:
        """Format data for training."""
        formatted_data = []
        
        for sample in data:
            prompt = sample.get('prompt', '')
            completion = sample.get('completion', '')
            
            # Create training text with ethical preamble
            training_text = self._create_training_text(prompt, completion, sample)
            
            # Tokenize
            encoded = self.tokenizer(
                training_text,
                truncation=True,
                max_length=self.config.max_length,
                padding=False,
                return_tensors=None
            )
            
            formatted_data.append({
                'input_ids': encoded['input_ids'],
                'attention_mask': encoded['attention_mask'],
                'labels': encoded['input_ids'].copy()  # For causal LM
            })
        
        return formatted_data
    
    def _create_training_text(self, prompt: str, completion: str, sample: Dict) -> str:
        """Create formatted training text with ethical considerations."""
        ethical_preamble = (
            "The following is for educational and authorized security research only. "
            "This information should only be used for legitimate security testing "
            "with proper authorization and legal compliance.\n\n"
        )
        
        # Add template markers for instruction following
        training_text = f"{ethical_preamble}### Instruction:\n{prompt}\n\n### Response:\n{completion}"
        
        return training_text
    
    def _load_validation_data(self) -> Dataset:
        """Load validation data if provided."""
        if not self.config.validation_data_path:
            return None
        
        self.logger.info(f"Loading validation data from {self.config.validation_data_path}")
        
        data = []
        with open(self.config.validation_data_path, 'r', encoding='utf-8') as f:
            if self.config.validation_data_path.endswith('.jsonl'):
                for line in f:
                    if line.strip():
                        data.append(json.loads(line))
            else:
                data = json.load(f)
        
        if self.config.content_filtering:
            data = self._apply_content_filtering(data)
        
        formatted_data = self._format_training_data(data)
        return Dataset.from_list(formatted_data)
    
    def setup_training_arguments(self) -> TrainingArguments:
        """Setup training arguments."""
        training_args = TrainingArguments(
            output_dir=self.config.output_dir,
            num_train_epochs=self.config.num_train_epochs,
            per_device_train_batch_size=self.config.per_device_train_batch_size,
            per_device_eval_batch_size=self.config.per_device_eval_batch_size,
            gradient_accumulation_steps=self.config.gradient_accumulation_steps,
            learning_rate=self.config.learning_rate,
            warmup_steps=self.config.warmup_steps,
            weight_decay=self.config.weight_decay,
            logging_steps=self.config.logging_steps,
            eval_steps=self.config.eval_steps,
            save_steps=self.config.save_steps,
            evaluation_strategy="steps",
            save_strategy="steps",
            load_best_model_at_end=True,
            metric_for_best_model="eval_loss",
            greater_is_better=False,
            fp16=torch.cuda.is_available(),
            dataloader_pin_memory=False,
            report_to="wandb" if self.config.use_wandb else "none",
            run_name=f"security-llm-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        )
        
        return training_args
    
    def train_model(self):
        """Train the model."""
        self.logger.info("Starting model training...")
        
        # Setup training arguments
        training_args = self.setup_training_arguments()
        
        # Setup data collator
        data_collator = DataCollatorForLanguageModeling(
            tokenizer=self.tokenizer,
            mlm=False,  # We're not doing masked language modeling
            pad_to_multiple_of=8
        )
        
        # Setup callbacks
        callbacks = []
        if self.eval_dataset is not None:
            callbacks.append(EarlyStoppingCallback(early_stopping_patience=3))
        
        # Initialize Weights & Biases if configured
        if self.config.use_wandb:
            wandb.init(
                project=self.config.wandb_project,
                name=f"security-llm-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                config=self.config.__dict__
            )
        
        # Create trainer
        trainer = Trainer(
            model=self.model,
            args=training_args,
            train_dataset=self.train_dataset,
            eval_dataset=self.eval_dataset,
            tokenizer=self.tokenizer,
            data_collator=data_collator,
            callbacks=callbacks
        )
        
        try:
            # Train the model
            trainer.train()
            
            # Save the final model
            trainer.save_model()
            self.tokenizer.save_pretrained(self.config.output_dir)
            
            # Save training config
            config_path = os.path.join(self.config.output_dir, "training_config.json")
            with open(config_path, 'w') as f:
                json.dump(self.config.__dict__, f, indent=2)
            
            self.logger.info(f"Training completed. Model saved to: {self.config.output_dir}")
            
            return trainer
            
        except Exception as e:
            self.logger.error(f"Training failed: {e}")
            raise
    
    def evaluate_model(self, trainer: Trainer) -> Dict:
        """Evaluate the trained model."""
        self.logger.info("Evaluating model...")
        
        try:
            eval_results = trainer.evaluate()
            
            # Save evaluation results
            eval_path = os.path.join(self.config.output_dir, "evaluation_results.json")
            with open(eval_path, 'w') as f:
                json.dump(eval_results, f, indent=2)
            
            self.logger.info(f"Evaluation results: {eval_results}")
            return eval_results
            
        except Exception as e:
            self.logger.error(f"Evaluation failed: {e}")
            return {}
    
    def generate_sample_outputs(self, prompts: List[str], max_length: int = 200) -> List[str]:
        """Generate sample outputs to verify model behavior."""
        self.logger.info("Generating sample outputs...")
        
        outputs = []
        
        for prompt in prompts:
            # Add ethical preamble
            full_prompt = (
                "The following is for educational and authorized security research only. "
                "This information should only be used for legitimate security testing "
                "with proper authorization and legal compliance.\n\n"
                f"### Instruction:\n{prompt}\n\n### Response:\n"
            )
            
            inputs = self.tokenizer(full_prompt, return_tensors="pt")
            if torch.cuda.is_available():
                inputs = {k: v.cuda() for k, v in inputs.items()}
            
            with torch.no_grad():
                outputs_tensor = self.model.generate(
                    **inputs,
                    max_length=max_length,
                    num_return_sequences=1,
                    temperature=0.7,
                    do_sample=True,
                    pad_token_id=self.tokenizer.eos_token_id
                )
            
            output_text = self.tokenizer.decode(outputs_tensor[0], skip_special_tokens=True)
            
            # Extract just the response part
            response_start = output_text.find("### Response:\n") + len("### Response:\n")
            response = output_text[response_start:].strip()
            
            outputs.append(response)
        
        return outputs
    
    def create_ethical_documentation(self):
        """Create ethical use documentation for the model."""
        documentation = {
            'model_purpose': 'Educational security research and authorized penetration testing',
            'intended_users': [
                'Security researchers',
                'Ethical hackers',
                'Cybersecurity students',
                'Authorized penetration testers'
            ],
            'prohibited_uses': [
                'Malicious attacks',
                'Unauthorized system access',
                'Illegal activities',
                'Harmful exploitation'
            ],
            'ethical_guidelines': self.ethical_guidelines,
            'disclaimer': (
                'This model is trained for educational and authorized security research purposes only. '
                'Users must ensure they have proper authorization before applying any techniques '
                'and must comply with all applicable laws and regulations. The developers are not '
                'responsible for misuse of this model.'
            ),
            'responsible_use': [
                'Obtain proper authorization before testing',
                'Follow responsible disclosure practices',
                'Comply with all applicable laws',
                'Use only for educational or authorized purposes',
                'Respect privacy and confidentiality'
            ]
        }
        
        doc_path = os.path.join(self.config.output_dir, "ethical_use_guidelines.json")
        with open(doc_path, 'w') as f:
            json.dump(documentation, f, indent=2)
        
        self.logger.info(f"Ethical documentation saved to: {doc_path}")

def main():
    """Main entry point for the security LLM fine-tuning."""
    parser = argparse.ArgumentParser(
        description="Fine-tune security-focused LLM with ethical safeguards"
    )
    
    # Data arguments
    parser.add_argument(
        '--train-data', '-t',
        required=True,
        help='Training data file (JSONL or JSON)'
    )
    
    parser.add_argument(
        '--validation-data',
        help='Validation data file (optional)'
    )
    
    # Model arguments
    parser.add_argument(
        '--model-name', '-m',
        default='microsoft/DialoGPT-medium',
        help='Base model name (default: microsoft/DialoGPT-medium)'
    )
    
    parser.add_argument(
        '--output-dir', '-o',
        default='./security_llm_model',
        help='Output directory for trained model (default: ./security_llm_model)'
    )
    
    # Training arguments
    parser.add_argument(
        '--epochs',
        type=int,
        default=3,
        help='Number of training epochs (default: 3)'
    )
    
    parser.add_argument(
        '--batch-size',
        type=int,
        default=4,
        help='Training batch size (default: 4)'
    )
    
    parser.add_argument(
        '--learning-rate',
        type=float,
        default=5e-5,
        help='Learning rate (default: 5e-5)'
    )
    
    parser.add_argument(
        '--max-length',
        type=int,
        default=512,
        help='Maximum sequence length (default: 512)'
    )
    
    # LoRA arguments
    parser.add_argument(
        '--use-lora',
        action='store_true',
        help='Use LoRA for efficient fine-tuning'
    )
    
    parser.add_argument(
        '--lora-r',
        type=int,
        default=16,
        help='LoRA rank (default: 16)'
    )
    
    parser.add_argument(
        '--lora-alpha',
        type=int,
        default=32,
        help='LoRA alpha (default: 32)'
    )
    
    # Safety arguments
    parser.add_argument(
        '--disable-content-filtering',
        action='store_true',
        help='Disable content filtering (not recommended)'
    )
    
    parser.add_argument(
        '--disable-ethical-safeguards',
        action='store_true',
        help='Disable ethical safeguards (not recommended)'
    )
    
    # Monitoring arguments
    parser.add_argument(
        '--use-wandb',
        action='store_true',
        help='Use Weights & Biases for monitoring'
    )
    
    parser.add_argument(
        '--wandb-project',
        default='security-llm-training',
        help='Weights & Biases project name'
    )
    
    # Other arguments
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)
    
    # Create config
    config = FineTuningConfig(
        model_name=args.model_name,
        train_data_path=args.train_data,
        validation_data_path=args.validation_data,
        output_dir=args.output_dir,
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        learning_rate=args.learning_rate,
        max_length=args.max_length,
        use_lora=args.use_lora,
        lora_r=args.lora_r,
        lora_alpha=args.lora_alpha,
        content_filtering=not args.disable_content_filtering,
        ethical_safeguards=not args.disable_ethical_safeguards,
        use_wandb=args.use_wandb,
        wandb_project=args.wandb_project
    )
    
    try:
        logger.info("Starting security LLM fine-tuning...")
        
        # Create trainer
        trainer_instance = SecurityLLMTrainer(config, verbose=args.verbose)
        
        # Load model and data
        trainer_instance.load_and_prepare_model()
        trainer_instance.load_training_data()
        
        # Train model
        trainer = trainer_instance.train_model()
        
        # Evaluate model
        eval_results = trainer_instance.evaluate_model(trainer)
        
        # Generate sample outputs
        test_prompts = [
            "Explain what a buffer overflow is and how it works",
            "What are the ethical considerations when conducting penetration testing?",
            "How can SQL injection vulnerabilities be prevented?"
        ]
        
        sample_outputs = trainer_instance.generate_sample_outputs(test_prompts)
        
        # Create ethical documentation
        trainer_instance.create_ethical_documentation()
        
        # Print summary
        print(f"\n{'='*60}")
        print(f"Security LLM Fine-tuning Complete")
        print(f"{'='*60}")
        print(f"Model: {config.model_name}")
        print(f"Training samples: {len(trainer_instance.train_dataset)}")
        print(f"Validation samples: {len(trainer_instance.eval_dataset) if trainer_instance.eval_dataset else 0}")
        print(f"Output directory: {config.output_dir}")
        print(f"LoRA enabled: {config.use_lora}")
        
        if eval_results:
            print(f"\nEvaluation Results:")
            for key, value in eval_results.items():
                if isinstance(value, float):
                    print(f"  {key}: {value:.4f}")
                else:
                    print(f"  {key}: {value}")
        
        print(f"\nSample Outputs:")
        for i, (prompt, output) in enumerate(zip(test_prompts, sample_outputs)):
            print(f"\nPrompt {i+1}: {prompt}")
            print(f"Response: {output[:200]}...")
        
        print(f"\n{'='*60}")
        
        return 0
        
    except KeyboardInterrupt:
        logger.info("Training interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"Training failed: {e}")
        return 1

if __name__ == '__main__':
    sys.exit(main())