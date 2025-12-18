# Stateful Base64 Decoder - Java to Python Conversion

This module contains a Python implementation of a stateful base64 decoder with XOR decryption, converted from decompiled Java code.

## Original Java Code

The original Java code was a decompiled obfuscated class containing:
- Two lookup tables (`multOf8Array` and `otherArray`)
- A stateful decoder that processes base64 data in chunks
- An XOR decryption method that uses "Netease" as the key

## Python Implementation

The Python version maintains the same logic and behavior:

```python
from utils.base64_decoder_stateful import StatefulBase64Decoder, decode_and_xor

# Simple decoding
decoder = StatefulBase64Decoder()
result = decoder.decode("SGVsbG8gV29ybGQ=", flags=0)  # Returns: b"Hello World"

# URL-safe base64 (use flags=8)
decoder = StatefulBase64Decoder()
result = decoder.decode("SGVs-G8_", flags=8)  # Returns decoded bytes

# Decode and XOR with "Netease" key
result = decode_and_xor("encoded_string")  # Returns decrypted string
```

## Key Features

1. **Dual Decode Tables**: 
   - `MULT_OF_8_ARRAY`: Standard base64 (`+/`) - used when `flags & 8 == 0`
   - `OTHER_ARRAY`: URL-safe base64 (`-_`) - used when `flags & 8 != 0`

2. **Stateful Processing**: Maintains state across decode operations for streaming

3. **XOR Decryption**: Built-in support for XORing with "Netease" key

4. **Fast Path Optimization**: Decodes 4 characters at once when possible

## Class Structure

### StatefulBase64Decoder

```python
class StatefulBase64Decoder:
    def __init__(self):
        """Initialize the decoder with fresh state."""
        
    def choose_decode_array(self, flags, output_buffer):
        """Select which decode table to use based on flags."""
        
    def decode_chunk(self, input_bytes, offset, length, is_final):
        """Decode a chunk of base64 data (supports streaming)."""
        
    def decode(self, data, flags=0):
        """Decode complete base64 data in one call."""
```

### decode_and_xor Function

```python
def decode_and_xor(encoded_str):
    """
    Decode base64 string and XOR with "Netease" key.
    Equivalent to Java method c(String str).
    """
```

## Implementation Details

### Decode Tables

The decoder uses 256-element lookup tables:
- Valid base64 characters map to their 6-bit values (0-63)
- `=` (padding) maps to -2
- Invalid characters map to -1

**Standard Base64 Table (MULT_OF_8_ARRAY):**
- `A-Z` → 0-25
- `a-z` → 26-51
- `0-9` → 52-61
- `+` → 62
- `/` → 63
- `=` → -2

**URL-Safe Base64 Table (OTHER_ARRAY):**
- `A-Z` → 0-25
- `a-z` → 26-51
- `0-9` → 52-61
- `-` → 62
- `_` → 63
- `=` → -2

### State Machine

The decoder uses a state machine with 6 states (0-5):
- **State 0**: Waiting for first character
- **State 1**: Have 1 character (6 bits)
- **State 2**: Have 2 characters (12 bits) - can output 1 byte with padding
- **State 3**: Have 3 characters (18 bits) - can output 2 bytes with padding or 3 bytes with 4th char
- **State 4**: After padding in state 2, expect second padding
- **State 5**: After padding in state 3, at end
- **State 6**: Error state

### XOR Encryption/Decryption

The `decode_and_xor` function:
1. Decodes the base64 input
2. XORs each byte with the corresponding byte from "Netease" key (repeating as needed)
3. Returns the result as a UTF-8 string

```python
key = b"Netease"  # 7 bytes
for i in range(len(data)):
    data[i] = data[i] ^ key[i % 7]
```

## Usage Examples

### Basic Decoding

```python
decoder = StatefulBase64Decoder()

# Standard base64
result = decoder.decode("SGVsbG8=", flags=0)
print(result)  # b'Hello'

# URL-safe base64
result = decoder.decode("SGVs-G8_", flags=8)
print(result)  # decoded bytes
```

### Streaming (Chunked) Decoding

```python
decoder = StatefulBase64Decoder()
output_buffer = bytearray(100)
decoder.choose_decode_array(0, output_buffer)

# Process first chunk
success = decoder.decode_chunk(chunk1, 0, len(chunk1), False)

# Process second chunk
success = decoder.decode_chunk(chunk2, 0, len(chunk2), True)

result = bytes(output_buffer[:decoder.oo000])
```

### XOR Decryption

```python
# Assume we have data that was base64-encoded after XORing with "Netease"
encrypted_b64 = "..."
decrypted = decode_and_xor(encrypted_b64)
print(decrypted)  # Original string
```

## Differences from Original Java

1. **Naming**: Python uses more descriptive names where possible
2. **Error Handling**: Returns None or raises ValueError instead of null
3. **Type Hints**: Added type annotations for better IDE support
4. **Pythonic**: Uses Python idioms while maintaining algorithm fidelity

## Testing

The implementation includes comprehensive tests:

```bash
python tests/test_base64_decoder_stateful.py -v
```

Test coverage includes:
- Both decode tables (standard and URL-safe)
- Padding variants
- Binary data
- XOR encryption/decryption
- Stateful/streaming decode
- Edge cases and error conditions

## Performance

The decoder includes a "fast path" optimization that processes 4 characters at once when in state 0, similar to the Java implementation. This provides good performance for typical base64 data.

## Security Note

This decoder is intended for reverse engineering and security research purposes. The XOR with "Netease" suggests this may have been used in applications from that company. Use responsibly and only on applications you have authorization to analyze.
