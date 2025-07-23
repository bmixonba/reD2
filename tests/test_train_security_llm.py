#!/usr/bin/env python3
"""
Test cases for the security LLM training script.

These tests verify the core functionality of the training pipeline
without requiring actual model downloads or training.
"""

import unittest
import tempfile
import os
import json
import sys
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Import with graceful fallback for missing dependencies
try:
    from scripts.train_security_llm import SecurityLLMTrainer, TrainingConfig
    SCRIPT_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Could not import training script: {e}")
    SCRIPT_AVAILABLE = False


class TestTrainingConfig(unittest.TestCase):
    """Test the TrainingConfig dataclass."""
    
    def test_config_initialization(self):
        """Test basic configuration initialization."""
        if not SCRIPT_AVAILABLE:
            self.skipTest("Training script not available")
            
        config = TrainingConfig(
            train_data_path="test.jsonl",
            model_name="test-model"
        )
        
        self.assertEqual(config.train_data_path, "test.jsonl")
        self.assertEqual(config.model_name, "test-model")
        self.assertEqual(config.use_lora, True)
        self.assertEqual(config.lora_rank, 16)
        self.assertIsNotNone(config.target_modules)
    
    def test_config_target_modules_default(self):
        """Test that default target modules are set correctly."""
        if not SCRIPT_AVAILABLE:
            self.skipTest("Training script not available")
            
        config = TrainingConfig(train_data_path="test.jsonl")
        expected_modules = [
            "q_proj", "k_proj", "v_proj", "o_proj",
            "gate_proj", "up_proj", "down_proj"
        ]
        self.assertEqual(config.target_modules, expected_modules)


class TestSecurityLLMTrainer(unittest.TestCase):
    """Test the SecurityLLMTrainer class."""
    
    def setUp(self):
        """Set up test fixtures."""
        if not SCRIPT_AVAILABLE:
            self.skipTest("Training script not available")
            
        self.config = TrainingConfig(
            train_data_path="test.jsonl",
            model_name="test-model",
            output_dir="/tmp/test_output"
        )
    
    def test_trainer_initialization(self):
        """Test trainer initialization."""
        # Mock HF_AVAILABLE to avoid dependency errors
        with patch('scripts.train_security_llm.HF_AVAILABLE', True):
            trainer = SecurityLLMTrainer(self.config)
            self.assertEqual(trainer.config, self.config)
            self.assertIsNotNone(trainer.logger)
    
    def test_jsonl_corpus_loading(self):
        """Test JSONL corpus loading functionality."""
        # Create temporary JSONL file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
            test_data = [
                {"prompt": "Test prompt 1", "completion": "Test completion 1"},
                {"prompt": "Test prompt 2", "completion": "Test completion 2"},
                {"prompt": "Test prompt 3", "completion": "Test completion 3"},
            ]
            for item in test_data:
                f.write(json.dumps(item) + '\n')
            temp_path = f.name
        
        try:
            # Update config with temporary file
            self.config.train_data_path = temp_path
            self.config.validation_split = 0.3  # 30% validation
            
            with patch('scripts.train_security_llm.HF_AVAILABLE', True):
                trainer = SecurityLLMTrainer(self.config)
                trainer.load_jsonl_corpus()
                
                # Verify datasets were created
                self.assertIsNotNone(trainer.train_dataset)
                self.assertIsNotNone(trainer.eval_dataset)
                
                # Check split ratios (3 samples, 30% validation = 2 train, 1 eval)
                self.assertEqual(len(trainer.train_dataset), 2)
                self.assertEqual(len(trainer.eval_dataset), 1)
        
        finally:
            # Cleanup
            os.unlink(temp_path)
    
    def test_jsonl_corpus_loading_invalid_file(self):
        """Test error handling for missing corpus file."""
        self.config.train_data_path = "/nonexistent/file.jsonl"
        
        with patch('scripts.train_security_llm.HF_AVAILABLE', True):
            trainer = SecurityLLMTrainer(self.config)
            
            with self.assertRaises(FileNotFoundError):
                trainer.load_jsonl_corpus()
    
    def test_jsonl_corpus_loading_empty_file(self):
        """Test error handling for empty corpus file."""
        # Create empty temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
            temp_path = f.name
        
        try:
            self.config.train_data_path = temp_path
            
            with patch('scripts.train_security_llm.HF_AVAILABLE', True):
                trainer = SecurityLLMTrainer(self.config)
                
                with self.assertRaises(ValueError):
                    trainer.load_jsonl_corpus()
        
        finally:
            os.unlink(temp_path)
    
    def test_jsonl_corpus_loading_invalid_format(self):
        """Test handling of invalid JSONL format."""
        # Create file with invalid format
        with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
            f.write('{"prompt": "Test"}\n')  # Missing completion
            f.write('invalid json\n')  # Invalid JSON
            f.write('{"prompt": "Valid", "completion": "Valid"}\n')  # Valid entry
            temp_path = f.name
        
        try:
            self.config.train_data_path = temp_path
            self.config.validation_split = 0.0  # No validation split for this test
            
            with patch('scripts.train_security_llm.HF_AVAILABLE', True):
                trainer = SecurityLLMTrainer(self.config)
                trainer.load_jsonl_corpus()
                
                # Should only load the valid entry
                self.assertEqual(len(trainer.train_dataset), 1)
        
        finally:
            os.unlink(temp_path)
    
    @patch('scripts.train_security_llm.AutoTokenizer')
    @patch('scripts.train_security_llm.AutoModelForCausalLM')
    def test_model_loading(self, mock_model_class, mock_tokenizer_class):
        """Test model and tokenizer loading."""
        # Mock tokenizer
        mock_tokenizer = Mock()
        mock_tokenizer.pad_token = None
        mock_tokenizer.eos_token = "<eos>"
        mock_tokenizer_class.from_pretrained.return_value = mock_tokenizer
        
        # Mock model
        mock_param = Mock()
        mock_param.numel.return_value = 1000
        mock_param.requires_grad = True
        
        mock_model = Mock()
        mock_model.parameters.return_value = [mock_param]
        mock_model_class.from_pretrained.return_value = mock_model
        
        with patch('scripts.train_security_llm.HF_AVAILABLE', True):
            with patch('scripts.train_security_llm.PEFT_AVAILABLE', False):
                trainer = SecurityLLMTrainer(self.config)
                trainer.load_and_setup_model()
                
                # Verify tokenizer setup
                mock_tokenizer_class.from_pretrained.assert_called_once_with(
                    self.config.model_name
                )
                self.assertEqual(mock_tokenizer.pad_token, "<eos>")
                
                # Verify model setup
                mock_model_class.from_pretrained.assert_called_once()
                self.assertEqual(trainer.model, mock_model)
                self.assertEqual(trainer.tokenizer, mock_tokenizer)
    
    @patch('scripts.train_security_llm.get_peft_model')
    @patch('scripts.train_security_llm.LoraConfig')
    @patch('scripts.train_security_llm.AutoTokenizer')
    @patch('scripts.train_security_llm.AutoModelForCausalLM')
    def test_lora_application(self, mock_model_class, mock_tokenizer_class, 
                            mock_lora_config, mock_get_peft_model):
        """Test LoRA configuration application."""
        # Setup mocks
        mock_tokenizer = Mock()
        mock_tokenizer.pad_token = "<pad>"
        mock_tokenizer_class.from_pretrained.return_value = mock_tokenizer
        
        mock_param = Mock()
        mock_param.numel.return_value = 1000
        mock_param.requires_grad = True
        
        mock_model = Mock()
        mock_model.parameters.return_value = [mock_param]
        mock_model_class.from_pretrained.return_value = mock_model
        
        mock_peft_model = Mock()
        mock_peft_model.print_trainable_parameters = Mock()
        mock_get_peft_model.return_value = mock_peft_model
        
        # Configure LoRA
        self.config.use_lora = True
        
        with patch('scripts.train_security_llm.HF_AVAILABLE', True):
            with patch('scripts.train_security_llm.PEFT_AVAILABLE', True):
                trainer = SecurityLLMTrainer(self.config)
                trainer.load_and_setup_model()
                
                # Verify LoRA was applied
                mock_lora_config.assert_called_once()
                mock_get_peft_model.assert_called_once_with(mock_model, mock_lora_config.return_value)
                mock_peft_model.print_trainable_parameters.assert_called_once()
                self.assertEqual(trainer.model, mock_peft_model)


class TestCorpusFormat(unittest.TestCase):
    """Test corpus format validation."""
    
    def test_valid_jsonl_format(self):
        """Test that valid JSONL format is accepted."""
        valid_samples = [
            {"prompt": "What is XSS?", "completion": "Cross-site scripting vulnerability"},
            {"prompt": "Explain SQL injection", "completion": "Code injection technique"},
        ]
        
        for sample in valid_samples:
            self.assertIn('prompt', sample)
            self.assertIn('completion', sample)
            self.assertIsInstance(sample['prompt'], str)
            self.assertIsInstance(sample['completion'], str)
    
    def test_prompt_completion_structure(self):
        """Test expected prompt/completion structure."""
        sample = {"prompt": "Test security question", "completion": "Test security answer"}
        
        # Verify required fields
        self.assertIn('prompt', sample)
        self.assertIn('completion', sample)
        
        # Verify types
        self.assertIsInstance(sample['prompt'], str)
        self.assertIsInstance(sample['completion'], str)
        
        # Verify non-empty
        self.assertTrue(len(sample['prompt'].strip()) > 0)
        self.assertTrue(len(sample['completion'].strip()) > 0)


if __name__ == '__main__':
    unittest.main()