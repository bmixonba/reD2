#!/usr/bin/env python3
"""
Demonstration of the custom base64 decoder.

This script shows various use cases of the decode_base64() function
converted from Java.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Import directly to avoid dependency issues
import importlib.util
spec = importlib.util.spec_from_file_location("base64_decoder", 
    os.path.join(os.path.dirname(__file__), '..', 'utils', 'base64_decoder.py'))
base64_decoder_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base64_decoder_module)
decode_base64 = base64_decoder_module.decode_base64


def print_result(description, encoded, result):
    """Print a formatted result."""
    print(f"\n{description}")
    print(f"  Input:  {encoded!r}")
    if result is None:
        print(f"  Output: None (invalid)")
    else:
        print(f"  Output: {result!r}")
        try:
            print(f"  Decoded: {result.decode('utf-8', errors='replace')!r}")
        except:
            print(f"  Decoded: (binary data)")


def main():
    """Run demonstrations of the base64 decoder."""
    print("=" * 70)
    print("Custom Base64 Decoder - Demonstration")
    print("=" * 70)
    
    # Example 1: Simple text
    print_result(
        "Example 1: Simple text with padding",
        "SGVsbG8gV29ybGQ=",
        decode_base64("SGVsbG8gV29ybGQ=")
    )
    
    # Example 2: Without padding
    print_result(
        "Example 2: Same text without padding",
        "SGVsbG8gV29ybGQ",
        decode_base64("SGVsbG8gV29ybGQ")
    )
    
    # Example 3: With embedded whitespace
    print_result(
        "Example 3: Text with embedded whitespace (auto-skipped)",
        "SGVs bG8g\nV29y bGQ=",
        decode_base64("SGVs bG8g\nV29y bGQ=")
    )
    
    # Example 4: URL-safe base64
    print_result(
        "Example 4: URL-safe base64 (with - and _)",
        "SGVsbG8-V29ybGQ_",
        decode_base64("SGVsbG8-V29ybGQ_")
    )
    
    # Example 5: Standard base64 (with + and /)
    print_result(
        "Example 5: Standard base64 (with + and /)",
        "dGVzdP/+/Q==",
        decode_base64("dGVzdP/+/Q==")
    )
    
    # Example 6: Invalid input
    print_result(
        "Example 6: Invalid input (contains @)",
        "SGVs@G8=",
        decode_base64("SGVs@G8=")
    )
    
    # Example 7: Only one character in final group (invalid)
    print_result(
        "Example 7: Single character (invalid - only 6 bits)",
        "Q",
        decode_base64("Q")
    )
    
    # Example 8: Empty/whitespace only
    print_result(
        "Example 8: Only whitespace (invalid)",
        "   \n\t  ",
        decode_base64("   \n\t  ")
    )
    
    # Example 9: Longer text
    print_result(
        "Example 9: Longer text",
        "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw==",
        decode_base64("VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw==")
    )
    
    print("\n" + "=" * 70)
    print("Demonstration complete!")
    print("=" * 70)


if __name__ == '__main__':
    main()
