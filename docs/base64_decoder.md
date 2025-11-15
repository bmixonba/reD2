# Base64 Decoder - Java to Python Conversion

This module contains a Python implementation of a custom base64 decoder, converted from Java code.

## Original Java Code

The original Java method was a custom base64 decoder that supports both standard and URL-safe base64 encoding:

```java
public static byte[] a(String str) {
    // Custom base64 decoder implementation
    // Supports standard (A-Z, a-z, 0-9, +, /) and URL-safe (-, _) base64
}
```

## Python Implementation

The Python version maintains the same logic and behavior:

```python
from utils.base64_decoder import decode_base64

# Decode standard base64
result = decode_base64("SGVsbG8gV29ybGQ=")  # Returns: b"Hello World"

# Decode without padding
result = decode_base64("SGVsbG8gV29ybGQ")   # Returns: b"Hello World"

# Decode URL-safe base64
result = decode_base64("SGVs-G8_")          # Returns decoded bytes

# Handle whitespace (automatically stripped)
result = decode_base64("SGVsbG8=\n\t ")     # Returns: b"Hello"

# Invalid input returns None
result = decode_base64("Invalid@String")    # Returns: None
```

## Key Features

1. **Dual Alphabet Support**: Handles both standard (`+/`) and URL-safe (`-_`) base64
2. **Whitespace Handling**: Automatically strips and skips whitespace characters
3. **Flexible Padding**: Works with or without padding (`=`)
4. **Error Handling**: Returns `None` for invalid input
5. **Exact Translation**: Maintains the same bit-manipulation logic as the Java original

## Conversion Notes

### Character Mapping
- `A-Z` → 0-25
- `a-z` → 26-51  (Java used `charAt2 - 'G'` where 'G' = 71, so 'a'(97) - 71 = 26)
- `0-9` → 52-61  (Java used `charAt2 + 4` where '0'(48) + 4 = 52)
- `+` or `-` → 62
- `/` or `_` → 63

### Bit Manipulation
The decoder accumulates 6-bit values and outputs bytes when it has collected enough bits:
- Every 4 base64 characters (24 bits) produces 3 output bytes
- Remaining characters are handled specially:
  - 2 characters (12 bits) → 1 byte
  - 3 characters (18 bits) → 2 bytes
  - 1 character (6 bits) → Invalid (returns None)

## Testing

The implementation includes comprehensive unit tests:

```bash
python tests/test_base64_decoder.py -v
```

Test coverage includes:
- Standard and URL-safe base64
- With and without padding
- Whitespace handling
- Invalid input detection
- Binary data
- Comparison with Python's standard base64 module
- Edge cases

## Usage in the Project

This decoder can be used anywhere custom base64 decoding is needed, particularly when:
- Input may use either standard or URL-safe base64
- Input may have embedded whitespace
- You need to handle malformed input gracefully (returns None instead of raising exceptions)

## Performance Considerations

The implementation maintains the character-by-character processing approach from the Java original. For most use cases, Python's built-in `base64` module will be faster, but this custom decoder is useful when you need the specific behavior of the original Java implementation.
