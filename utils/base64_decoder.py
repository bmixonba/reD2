"""
Custom base64 decoder utility.

This module provides a custom base64 decoder that handles both standard 
and URL-safe base64 encoding, converted from Java implementation.
"""


def decode_base64(s: str) -> bytes:
    """
    Decode a base64 encoded string using custom logic.
    
    This decoder supports both standard base64 (with +/) and URL-safe 
    base64 (with -_) encoding. It also handles padding and whitespace.
    
    Args:
        s: Base64 encoded string to decode
        
    Returns:
        Decoded bytes, or None if the input is invalid
        
    Note:
        This is a direct conversion from Java code that handles:
        - Standard base64 alphabet (A-Z, a-z, 0-9, +, /)
        - URL-safe base64 alphabet (A-Z, a-z, 0-9, -, _)
        - Trailing padding (=) and whitespace (\n, \r, space, tab)
    """
    if not s:
        return None
    
    # Strip trailing padding and whitespace
    length = len(s)
    while length > 0:
        char = s[length - 1]
        if char not in ('=', '\n', '\r', ' ', '\t'):
            break
        length -= 1
    
    # If all characters were whitespace/padding, return None
    if length == 0:
        return None
    
    # Calculate output array size
    byte_array = bytearray((length * 6) // 8)
    
    i5 = 0  # Input position
    i6 = 0  # Accumulated bits
    i7 = 0  # Number of characters processed
    i8 = 0  # Output position
    
    while i5 < length:
        char = s[i5]
        
        # Decode character to 6-bit value
        if 'A' <= char <= 'Z':
            i = ord(char) - ord('A')
        elif 'a' <= char <= 'z':
            i = ord(char) - ord('a') + 26  # 'G' = 71, 'a' = 97, so 97 - 71 = 26
        elif '0' <= char <= '9':
            i = ord(char) - ord('0') + 52  # '0' = 48, 48 + 4 = 52
        elif char in ('+', '-'):
            i = 62
        elif char in ('/', '_'):
            i = 63
        elif char in ('\n', '\r', ' ', '\t'):
            # Skip whitespace characters
            i5 += 1
            continue
        else:
            # Invalid character
            return None
        
        # Accumulate bits
        i2 = i | (i6 << 6)
        i3 = i7 + 1
        
        # Every 4 characters (24 bits), output 3 bytes
        if i3 % 4 == 0:
            i9 = i8 + 1
            byte_array[i8] = (i2 >> 16) & 0xFF
            i10 = i9 + 1
            byte_array[i9] = (i2 >> 8) & 0xFF
            i4 = i10 + 1
            byte_array[i10] = i2 & 0xFF
        else:
            i4 = i8
        
        i5 += 1
        i8 = i4
        i7 = i3
        i6 = i2
    
    # Handle remaining bits
    i11 = i7 % 4
    if i11 == 1:
        # Invalid: only 1 character in final group
        return None
    elif i11 == 2:
        # 2 characters = 12 bits = 1 byte
        byte_array[i8] = ((i6 << 12) >> 16) & 0xFF
        i8 += 1
    elif i11 == 3:
        # 3 characters = 18 bits = 2 bytes
        i12 = i6 << 6
        i13 = i8 + 1
        byte_array[i8] = (i12 >> 16) & 0xFF
        i8 = i13 + 1
        byte_array[i13] = (i12 >> 8) & 0xFF
    
    # Return exact size array
    if i8 == len(byte_array):
        return bytes(byte_array)
    else:
        return bytes(byte_array[:i8])
