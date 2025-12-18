#!/usr/bin/env python3
"""
Test cases for stateful base64 decoder with XOR decryption.

This tests the Python conversion of the decompiled Java base64 decoder
with stateful decoding and XOR capability.
"""

import unittest
import base64
import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Import directly without going through utils package to avoid androguard dependency
import importlib.util
spec = importlib.util.spec_from_file_location("base64_decoder_stateful", 
    os.path.join(os.path.dirname(__file__), '..', 'utils', 'base64_decoder_stateful.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
StatefulBase64Decoder = module.StatefulBase64Decoder
decode_and_xor = module.decode_and_xor


class TestStatefulBase64Decoder(unittest.TestCase):
    """Test cases for the stateful base64 decoder."""
    
    def test_simple_decode_mult_of_8(self):
        """Test simple decoding with MULT_OF_8_ARRAY (standard base64)."""
        decoder = StatefulBase64Decoder()
        result = decoder.decode("SGVsbG8gV29ybGQ=", flags=0)
        self.assertEqual(result, b"Hello World")
    
    def test_simple_decode_other_array(self):
        """Test simple decoding with OTHER_ARRAY (URL-safe base64)."""
        decoder = StatefulBase64Decoder()
        # Using URL-safe encoding
        result = decoder.decode("SGVsbG8gV29ybGQ=", flags=8)
        self.assertEqual(result, b"Hello World")
    
    def test_standard_base64_with_plus_slash(self):
        """Test standard base64 with + and / characters."""
        decoder = StatefulBase64Decoder()
        # This contains + and / in standard encoding
        original = b"test\xff\xfe\xfd"
        encoded = base64.b64encode(original).decode('ascii')
        result = decoder.decode(encoded, flags=0)
        self.assertEqual(result, original)
    
    def test_url_safe_base64_with_minus_underscore(self):
        """Test URL-safe base64 with - and _ characters."""
        decoder = StatefulBase64Decoder()
        # This would contain - and _ in URL-safe encoding
        original = b"test\xff\xfe\xfd"
        encoded = base64.urlsafe_b64encode(original).decode('ascii')
        result = decoder.decode(encoded, flags=8)
        self.assertEqual(result, original)
    
    def test_decode_without_padding(self):
        """Test decoding without padding."""
        decoder = StatefulBase64Decoder()
        result = decoder.decode("SGVsbG8", flags=0)
        self.assertEqual(result, b"Hello")
    
    def test_longer_text(self):
        """Test with longer text."""
        decoder = StatefulBase64Decoder()
        original = b"The quick brown fox jumps over the lazy dog"
        encoded = base64.b64encode(original).decode('ascii')
        result = decoder.decode(encoded, flags=0)
        self.assertEqual(result, original)
    
    def test_binary_data(self):
        """Test with binary data."""
        decoder = StatefulBase64Decoder()
        original = bytes(range(256))
        encoded = base64.b64encode(original).decode('ascii')
        result = decoder.decode(encoded, flags=0)
        self.assertEqual(result, original)
    
    def test_empty_string(self):
        """Test with empty string."""
        decoder = StatefulBase64Decoder()
        result = decoder.decode("", flags=0)
        self.assertEqual(result, b"")
    
    def test_invalid_base64(self):
        """Test with invalid base64 characters."""
        decoder = StatefulBase64Decoder()
        with self.assertRaises(ValueError):
            decoder.decode("Invalid@String!", flags=0)
    
    def test_decode_and_xor_none(self):
        """Test decode_and_xor with None input."""
        result = decode_and_xor(None)
        self.assertIsNone(result)
    
    def test_decode_and_xor_simple(self):
        """Test decode_and_xor with simple text."""
        # First, encode "Hello" and XOR it with "Netease"
        original = b"Hello"
        key = b"Netease"
        
        # XOR the original with key
        xored = bytearray(original)
        for i in range(len(xored)):
            xored[i] = xored[i] ^ key[i % len(key)]
        
        # Encode to base64
        encoded = base64.b64encode(xored).decode('ascii')
        
        # Decode and XOR back
        result = decode_and_xor(encoded)
        self.assertEqual(result, "Hello")
    
    def test_decode_and_xor_longer_text(self):
        """Test decode_and_xor with text longer than key."""
        # Test with text longer than "Netease" (7 chars)
        original = b"Hello World Test"
        key = b"Netease"
        
        # XOR the original with key
        xored = bytearray(original)
        for i in range(len(xored)):
            xored[i] = xored[i] ^ key[i % len(key)]
        
        # Encode to base64
        encoded = base64.b64encode(xored).decode('ascii')
        
        # Decode and XOR back
        result = decode_and_xor(encoded)
        self.assertEqual(result, "Hello World Test")
    
    def test_decode_and_xor_invalid(self):
        """Test decode_and_xor with invalid input."""
        result = decode_and_xor("Invalid@String!")
        self.assertIsNone(result)
    
    def test_stateful_decoding_chunks(self):
        """Test stateful decoding with multiple chunks."""
        decoder = StatefulBase64Decoder()
        input_data = b"SGVsbG8gV29ybGQ="
        
        # Allocate output buffer
        output_buffer = bytearray((len(input_data) * 3) // 4)
        decoder.choose_decode_array(0, output_buffer)
        
        # Decode in chunks
        success = decoder.decode_chunk(input_data, 0, len(input_data), True)
        
        self.assertTrue(success)
        result = bytes(output_buffer[:decoder.oo000])
        self.assertEqual(result, b"Hello World")
    
    def test_comparison_with_standard_library(self):
        """Compare results with Python's standard base64."""
        test_cases = [
            "SGVsbG8gV29ybGQ=",
            "VGhlIHF1aWNrIGJyb3duIGZveA==",
            "MTIzNDU2Nzg5MA==",
        ]
        
        for encoded in test_cases:
            decoder = StatefulBase64Decoder()
            result = decoder.decode(encoded, flags=0)
            expected = base64.b64decode(encoded)
            self.assertEqual(result, expected, f"Mismatch for: {encoded}")
    
    def test_padding_variants(self):
        """Test different padding scenarios."""
        decoder = StatefulBase64Decoder()
        
        # 1 byte padding (QQ==)
        result = decoder.decode("QQ==", flags=0)
        self.assertEqual(len(result), 1)
        
        # 2 byte padding (QUI=)
        result = decoder.decode("QUI=", flags=0)
        self.assertEqual(len(result), 2)
        
        # No padding needed
        result = decoder.decode("QUJD", flags=0)
        self.assertEqual(result, b"ABC")
    
    def test_multiple_decode_instances(self):
        """Test that multiple decoder instances are independent."""
        decoder1 = StatefulBase64Decoder()
        decoder2 = StatefulBase64Decoder()
        
        result1 = decoder1.decode("SGVsbG8=", flags=0)
        result2 = decoder2.decode("V29ybGQ=", flags=0)
        
        self.assertEqual(result1, b"Hello")
        self.assertEqual(result2, b"World")
    
    def test_byte_input(self):
        """Test decoding with byte input instead of string."""
        decoder = StatefulBase64Decoder()
        result = decoder.decode(b"SGVsbG8gV29ybGQ=", flags=0)
        self.assertEqual(result, b"Hello World")


if __name__ == '__main__':
    unittest.main()
