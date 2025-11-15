#!/usr/bin/env python3
"""
Test cases for custom base64 decoder.

This tests the Python conversion of the Java base64 decoder implementation.
"""

import unittest
import base64
import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Import directly without going through utils package to avoid androguard dependency
import importlib.util
spec = importlib.util.spec_from_file_location("base64_decoder", 
    os.path.join(os.path.dirname(__file__), '..', 'utils', 'base64_decoder.py'))
base64_decoder_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base64_decoder_module)
decode_base64 = base64_decoder_module.decode_base64


class TestBase64Decoder(unittest.TestCase):
    """Test cases for the custom base64 decoder."""
    
    def test_empty_string(self):
        """Test decoding an empty string."""
        result = decode_base64("")
        self.assertIsNone(result)
    
    def test_none_input(self):
        """Test decoding None input."""
        result = decode_base64(None)
        self.assertIsNone(result)
    
    def test_simple_text(self):
        """Test decoding simple text."""
        # "Hello" in base64 is "SGVsbG8="
        result = decode_base64("SGVsbG8=")
        self.assertEqual(result, b"Hello")
    
    def test_without_padding(self):
        """Test decoding without padding."""
        # "Hello" in base64 without padding
        result = decode_base64("SGVsbG8")
        self.assertEqual(result, b"Hello")
    
    def test_standard_base64(self):
        """Test standard base64 with + and /."""
        # Test string that uses + and / characters
        original = b"test\xff\xfe\xfd"
        encoded = base64.b64encode(original).decode('ascii')
        result = decode_base64(encoded)
        self.assertEqual(result, original)
    
    def test_url_safe_base64(self):
        """Test URL-safe base64 with - and _."""
        # Test string that would use - and _ in URL-safe encoding
        original = b"test\xff\xfe\xfd"
        encoded = base64.urlsafe_b64encode(original).decode('ascii')
        result = decode_base64(encoded)
        self.assertEqual(result, original)
    
    def test_mixed_padding_whitespace(self):
        """Test with mixed padding and whitespace."""
        # "Hello" with various whitespace
        result = decode_base64("SGVsbG8=\n")
        self.assertEqual(result, b"Hello")
        
        result = decode_base64("SGVsbG8=  \t")
        self.assertEqual(result, b"Hello")
        
        result = decode_base64("SGVsbG8=\r\n")
        self.assertEqual(result, b"Hello")
    
    def test_embedded_whitespace(self):
        """Test with embedded whitespace (should be skipped)."""
        # "Hello" with spaces in between
        result = decode_base64("SGVs bG8=")
        self.assertEqual(result, b"Hello")
        
        result = decode_base64("SGVs\nbG8=")
        self.assertEqual(result, b"Hello")
    
    def test_all_alphabet_ranges(self):
        """Test all character ranges (A-Z, a-z, 0-9, +/, -_)."""
        # Test with various characters
        test_cases = [
            "QUJD",  # ABC (uppercase)
            "YWJj",  # abc (lowercase)
            "MDEy",  # 012 (digits)
        ]
        
        for encoded in test_cases:
            result = decode_base64(encoded)
            # Verify it decodes without error
            self.assertIsNotNone(result)
            self.assertIsInstance(result, bytes)
    
    def test_invalid_character(self):
        """Test with invalid characters."""
        # Invalid character '@'
        result = decode_base64("SGVs@G8=")
        self.assertIsNone(result)
        
        # Invalid character '#'
        result = decode_base64("SGVs#G8=")
        self.assertIsNone(result)
    
    def test_single_character_invalid(self):
        """Test single character in final group (invalid)."""
        # Only 1 character in the last group is invalid
        result = decode_base64("Q")
        self.assertIsNone(result)
    
    def test_two_characters(self):
        """Test two characters (12 bits = 1 byte)."""
        # "A" in base64 can be "QQ==" -> 1 byte
        result = decode_base64("QQ")
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)
    
    def test_three_characters(self):
        """Test three characters (18 bits = 2 bytes)."""
        # "AB" in base64 is "QUI=" -> 2 bytes
        result = decode_base64("QUI")
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 2)
    
    def test_four_characters(self):
        """Test four characters (24 bits = 3 bytes)."""
        # "ABC" in base64 is "QUJD" -> 3 bytes
        result = decode_base64("QUJD")
        self.assertEqual(result, b"ABC")
    
    def test_longer_strings(self):
        """Test with longer strings."""
        test_strings = [
            b"The quick brown fox jumps over the lazy dog",
            b"1234567890" * 10,
            b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09",
        ]
        
        for original in test_strings:
            # Test with standard base64
            encoded = base64.b64encode(original).decode('ascii')
            result = decode_base64(encoded)
            self.assertEqual(result, original, 
                           f"Failed for: {original}")
            
            # Test without padding
            encoded_no_pad = encoded.rstrip('=')
            result = decode_base64(encoded_no_pad)
            self.assertEqual(result, original, 
                           f"Failed without padding for: {original}")
    
    def test_binary_data(self):
        """Test with binary data."""
        # Test with various binary patterns
        binary_data = bytes(range(256))
        encoded = base64.b64encode(binary_data).decode('ascii')
        result = decode_base64(encoded)
        self.assertEqual(result, binary_data)
    
    def test_comparison_with_standard_base64(self):
        """Compare results with Python's standard base64 module."""
        test_cases = [
            "SGVsbG8gV29ybGQ=",  # "Hello World"
            "VGhlIHF1aWNrIGJyb3duIGZveA==",  # "The quick brown fox"
            "MTIzNDU2Nzg5MA==",  # "1234567890"
        ]
        
        for encoded in test_cases:
            result = decode_base64(encoded)
            expected = base64.b64decode(encoded)
            self.assertEqual(result, expected,
                           f"Mismatch for: {encoded}")
    
    def test_edge_cases(self):
        """Test edge cases."""
        # All padding
        result = decode_base64("====")
        self.assertIsNone(result)
        
        # Only whitespace
        result = decode_base64("   \n\t\r")
        self.assertIsNone(result)
        
        # Single valid character followed by padding
        result = decode_base64("Q===")
        self.assertIsNone(result)


if __name__ == '__main__':
    unittest.main()
