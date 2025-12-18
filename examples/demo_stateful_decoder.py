#!/usr/bin/env python3
"""
Demonstration of the stateful base64 decoder with XOR decryption.

This script shows various use cases of the StatefulBase64Decoder class
and decode_and_xor function converted from decompiled Java code.
"""

import sys
import os
import base64

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Import directly to avoid dependency issues
import importlib.util
spec = importlib.util.spec_from_file_location("base64_decoder_stateful", 
    os.path.join(os.path.dirname(__file__), '..', 'utils', 'base64_decoder_stateful.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
StatefulBase64Decoder = module.StatefulBase64Decoder
decode_and_xor = module.decode_and_xor


def print_section(title):
    """Print a formatted section header."""
    print(f"\n{'=' * 70}")
    print(f"{title}")
    print('=' * 70)


def demo_basic_decoding():
    """Demonstrate basic base64 decoding."""
    print_section("1. Basic Base64 Decoding")
    
    decoder = StatefulBase64Decoder()
    
    test_cases = [
        ("SGVsbG8gV29ybGQ=", 0, "Standard base64 with padding"),
        ("SGVsbG8gV29ybGQ", 0, "Standard base64 without padding"),
        ("SGVsbG8", 0, "Shorter text"),
    ]
    
    for encoded, flags, description in test_cases:
        result = decoder.decode(encoded, flags)
        print(f"\n{description}:")
        print(f"  Input:  {encoded}")
        print(f"  Output: {result!r}")
        try:
            print(f"  Text:   {result.decode('utf-8')}")
        except:
            print(f"  Text:   (binary data)")


def demo_decode_tables():
    """Demonstrate the two different decode tables."""
    print_section("2. Different Decode Tables (Standard vs URL-Safe)")
    
    # Show difference with characters that differ between tables
    test_data = b"test\xff\xfe\xfd"
    
    # Standard base64 uses +/
    standard_encoded = base64.b64encode(test_data).decode('ascii')
    print(f"\nStandard base64 (+/):")
    print(f"  Original: {test_data!r}")
    print(f"  Encoded:  {standard_encoded}")
    
    decoder = StatefulBase64Decoder()
    decoded = decoder.decode(standard_encoded, flags=0)
    print(f"  Decoded:  {decoded!r}")
    print(f"  Match:    {decoded == test_data}")
    
    # URL-safe base64 uses -_
    urlsafe_encoded = base64.urlsafe_b64encode(test_data).decode('ascii')
    print(f"\nURL-safe base64 (-_):")
    print(f"  Original: {test_data!r}")
    print(f"  Encoded:  {urlsafe_encoded}")
    
    decoder = StatefulBase64Decoder()
    decoded = decoder.decode(urlsafe_encoded, flags=8)
    print(f"  Decoded:  {decoded!r}")
    print(f"  Match:    {decoded == test_data}")


def demo_xor_decryption():
    """Demonstrate XOR decryption with Netease key."""
    print_section("3. XOR Decryption with 'Netease' Key")
    
    # Simulate encoding: XOR then base64
    original_text = "Hello World"
    print(f"\nOriginal text: {original_text!r}")
    
    # XOR with Netease key
    key = b"Netease"
    xored = bytearray(original_text.encode('utf-8'))
    for i in range(len(xored)):
        xored[i] = xored[i] ^ key[i % len(key)]
    print(f"After XOR:      {xored.hex()}")
    
    # Base64 encode
    encoded = base64.b64encode(xored).decode('ascii')
    print(f"Base64 encoded: {encoded}")
    
    # Decrypt using decode_and_xor
    decrypted = decode_and_xor(encoded)
    print(f"Decrypted:      {decrypted!r}")
    print(f"Match:          {decrypted == original_text}")


def demo_stateful_chunked():
    """Demonstrate stateful/chunked decoding."""
    print_section("4. Stateful (Chunked) Decoding")
    
    input_data = b"SGVsbG8gV29ybGQ="
    print(f"Input data: {input_data.decode('ascii')}")
    
    decoder = StatefulBase64Decoder()
    output_buffer = bytearray((len(input_data) * 3) // 4)
    decoder.choose_decode_array(0, output_buffer)
    
    # Process in one chunk
    print(f"\nProcessing {len(input_data)} bytes in one chunk:")
    success = decoder.decode_chunk(input_data, 0, len(input_data), True)
    result = bytes(output_buffer[:decoder.oo000])
    
    print(f"  Success: {success}")
    print(f"  Output:  {result!r}")
    print(f"  Text:    {result.decode('utf-8')}")


def demo_binary_data():
    """Demonstrate decoding binary data."""
    print_section("5. Binary Data Decoding")
    
    # Create some binary data
    binary_data = bytes(range(0, 16))
    print(f"Original binary: {binary_data.hex()}")
    
    # Encode to base64
    encoded = base64.b64encode(binary_data).decode('ascii')
    print(f"Base64 encoded:  {encoded}")
    
    # Decode using our decoder
    decoder = StatefulBase64Decoder()
    decoded = decoder.decode(encoded, flags=0)
    print(f"Decoded binary:  {decoded.hex()}")
    print(f"Match:           {decoded == binary_data}")


def demo_error_handling():
    """Demonstrate error handling."""
    print_section("6. Error Handling")
    
    test_cases = [
        ("Invalid@String!", "Invalid characters"),
        ("Q", "Only 1 character (insufficient data)"),
        ("", "Empty string"),
    ]
    
    for encoded, description in test_cases:
        print(f"\n{description}: {encoded!r}")
        decoder = StatefulBase64Decoder()
        try:
            result = decoder.decode(encoded, flags=0)
            print(f"  Result: {result!r}")
        except ValueError as e:
            print(f"  Error:  {e}")


def demo_comparison():
    """Compare with Python's standard base64."""
    print_section("7. Comparison with Standard Library")
    
    test_strings = [
        "Hello World",
        "The quick brown fox",
        "12345678901234567890",
    ]
    
    for text in test_strings:
        print(f"\nOriginal: {text!r}")
        
        # Standard library
        std_encoded = base64.b64encode(text.encode()).decode('ascii')
        std_decoded = base64.b64decode(std_encoded)
        
        # Our decoder
        decoder = StatefulBase64Decoder()
        our_decoded = decoder.decode(std_encoded, flags=0)
        
        print(f"  Encoded:  {std_encoded}")
        print(f"  Match:    {std_decoded == our_decoded}")


def main():
    """Run all demonstrations."""
    print("=" * 70)
    print("Stateful Base64 Decoder - Demonstration")
    print("Converted from Decompiled Java Code")
    print("=" * 70)
    
    demo_basic_decoding()
    demo_decode_tables()
    demo_xor_decryption()
    demo_stateful_chunked()
    demo_binary_data()
    demo_error_handling()
    demo_comparison()
    
    print("\n" + "=" * 70)
    print("Demonstration complete!")
    print("=" * 70)


if __name__ == '__main__':
    main()
