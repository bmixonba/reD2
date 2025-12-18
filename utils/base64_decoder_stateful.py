"""
Stateful base64 decoder with XOR decryption capability.

This module provides a stateful base64 decoder converted from decompiled Java code.
It includes support for two different decode tables and XOR decryption.
"""


class StatefulBase64Decoder:
    """
    Stateful base64 decoder with support for multiple decode tables.
    
    This decoder maintains internal state across decode operations and can
    handle base64 decoding with optional XOR decryption using a key.
    """
    
    # Standard base64 decode table (when i & 8 == 0)
    # This maps ASCII values 0-255 to base64 6-bit values or special codes
    MULT_OF_8_ARRAY = [-1] * 256
    # URL-safe base64 decode table (when i & 8 != 0)
    OTHER_ARRAY = [-1] * 256
    
    @classmethod
    def _init_tables(cls):
        """Initialize the decode tables."""
        # Standard base64: A-Z -> 0-25, a-z -> 26-51, 0-9 -> 52-61, + -> 62, / -> 63, = -> -2
        for i in range(26):
            cls.MULT_OF_8_ARRAY[ord('A') + i] = i
            cls.MULT_OF_8_ARRAY[ord('a') + i] = 26 + i
        for i in range(10):
            cls.MULT_OF_8_ARRAY[ord('0') + i] = 52 + i
        cls.MULT_OF_8_ARRAY[ord('+')] = 62
        cls.MULT_OF_8_ARRAY[ord('/')] = 63
        cls.MULT_OF_8_ARRAY[ord('=')] = -2
        
        # URL-safe base64: A-Z -> 0-25, a-z -> 26-51, 0-9 -> 52-61, - -> 62, _ -> 63, = -> -2
        for i in range(26):
            cls.OTHER_ARRAY[ord('A') + i] = i
            cls.OTHER_ARRAY[ord('a') + i] = 26 + i
        for i in range(10):
            cls.OTHER_ARRAY[ord('0') + i] = 52 + i
        cls.OTHER_ARRAY[ord('-')] = 62
        cls.OTHER_ARRAY[ord('_')] = 63
        cls.OTHER_ARRAY[ord('=')] = -2
    
    def __init__(self):
        """Initialize the decoder."""
        self.which_array = None
        self.oo000 = 0  # Output position
        self.b_arr = None  # Output buffer
        self.oo00000 = 0  # State (0-5 normal, 6 = error)
        self.oo000000 = 0  # Accumulated bits
    
    def choose_decode_array(self, flags, output_buffer):
        """
        Choose which decode array to use based on flags.
        
        Args:
            flags: Integer flags, if (flags & 8) == 0 use MULT_OF_8_ARRAY, else OTHER_ARRAY
            output_buffer: Byte array to store decoded output
        """
        self.b_arr = output_buffer
        self.which_array = self.MULT_OF_8_ARRAY if (flags & 8) == 0 else self.OTHER_ARRAY
        self.oo00000 = 0
        self.oo000000 = 0
        self.oo000 = 0
    
    def decode_chunk(self, input_bytes, offset, length, is_final):
        """
        Decode a chunk of base64 data.
        
        Args:
            input_bytes: Input byte array containing base64 data
            offset: Starting position in input array
            length: Number of bytes to process
            is_final: Whether this is the final chunk
            
        Returns:
            True if decoding successful, False if error occurred
        """
        if self.oo00000 == 6:  # Error state
            return False
        
        i4 = offset
        i5 = offset + length
        i6 = self.oo00000  # State
        i7 = self.oo000000  # Accumulated bits
        i8 = self.oo000  # Output position - continue from where we left off!
        b_arr2 = self.b_arr
        i_arr = self.which_array
        
        while True:
            if i4 >= i5:
                i3 = i8
                break
            
            if i6 == 0:
                # Fast path: decode 4 characters at once when in state 0
                while i4 + 4 <= i5:
                    val = (
                        (i_arr[input_bytes[i4] & 0xFF] << 18) |
                        (i_arr[input_bytes[i4 + 1] & 0xFF] << 12) |
                        (i_arr[input_bytes[i4 + 2] & 0xFF] << 6) |
                        i_arr[input_bytes[i4 + 3] & 0xFF]
                    )
                    if val >= 0:
                        b_arr2[i8 + 2] = val & 0xFF
                        b_arr2[i8 + 1] = (val >> 8) & 0xFF
                        b_arr2[i8] = (val >> 16) & 0xFF
                        i8 += 3
                        i4 += 4
                        i7 = val
                    else:
                        break
                
                if i4 >= i5:
                    i3 = i8
                    break
            
            # Process one character at a time
            i9 = i4 + 1
            i10 = i_arr[input_bytes[i4] & 0xFF]
            
            if i6 == 0:
                if i10 >= 0:
                    i7 = i10
                    i6 += 1
                elif i10 != -1:
                    self.oo00000 = 6
                    return False
            elif i6 == 1:
                if i10 >= 0:
                    i7 = (i7 << 6) | i10
                    i6 += 1
                elif i10 != -1:
                    self.oo00000 = 6
                    return False
            elif i6 == 2:
                if i10 >= 0:
                    i7 = (i7 << 6) | i10
                    i6 += 1
                elif i10 == -2:  # Padding
                    b_arr2[i8] = (i7 >> 4) & 0xFF
                    i6 = 4
                    i8 += 1
                elif i10 != -1:
                    self.oo00000 = 6
                    return False
            elif i6 == 3:
                if i10 >= 0:
                    i7 = (i7 << 6) | i10
                    b_arr2[i8 + 2] = i7 & 0xFF
                    b_arr2[i8 + 1] = (i7 >> 8) & 0xFF
                    b_arr2[i8] = (i7 >> 16) & 0xFF
                    i8 += 3
                    i6 = 0
                elif i10 == -2:  # Padding
                    b_arr2[i8 + 1] = (i7 >> 2) & 0xFF
                    b_arr2[i8] = (i7 >> 10) & 0xFF
                    i8 += 2
                    i6 = 5
                elif i10 != -1:
                    self.oo00000 = 6
                    return False
            elif i6 == 4:
                if i10 == -2:  # Expected padding
                    i6 += 1
                elif i10 != -1:
                    self.oo00000 = 6
                    return False
            elif i6 == 5:
                if i10 != -1:  # Should only see whitespace/nothing
                    self.oo00000 = 6
                    return False
            
            i4 = i9
        
        # Update state
        self.oo00000 = i6
        self.oo000000 = i7
        self.oo000 = i3
        
        if not is_final:
            return True
        
        # Final processing - handle remaining bits
        if i6 == 0:
            # Clean end
            return True
        elif i6 == 1:
            # Only 1 character in final group - error
            self.oo00000 = 6
            return False
        elif i6 == 2:
            # 2 characters = 12 bits = 1 byte
            b_arr2[i3] = (i7 >> 4) & 0xFF
            self.oo000 = i3 + 1
            return True
        elif i6 == 3:
            # 3 characters = 18 bits = 2 bytes
            b_arr2[i3] = (i7 >> 10) & 0xFF
            b_arr2[i3 + 1] = (i7 >> 2) & 0xFF
            self.oo000 = i3 + 2
            return True
        elif i6 == 4 or i6 == 5:
            # Already at end after padding
            return True
        else:
            # Error state
            return False
    
    def decode(self, data, flags=0):
        """
        Decode base64 data.
        
        Args:
            data: String or bytes to decode
            flags: Flags to control decoding (bit 3 selects decode table)
            
        Returns:
            Decoded bytes or None if error
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        return self._decode_bytes(data, 0, len(data), flags)
    
    def _decode_bytes(self, input_bytes, offset, length, flags):
        """
        Internal method to decode bytes.
        
        Args:
            input_bytes: Byte array to decode
            offset: Starting offset
            length: Number of bytes to process
            flags: Decode flags
            
        Returns:
            Decoded bytes or None if error
        """
        # Allocate output buffer
        output_buffer = bytearray((length * 3) // 4)
        self.choose_decode_array(flags, output_buffer)
        
        if self.decode_chunk(input_bytes, offset, length, True):
            if self.oo000 == len(self.b_arr):
                return bytes(self.b_arr)
            else:
                return bytes(self.b_arr[:self.oo000])
        else:
            raise ValueError("Base64 decoding error")


# Initialize tables when module is loaded
StatefulBase64Decoder._init_tables()


def decode_and_xor(encoded_str):
    """
    Decode base64 string and XOR with "Netease" key.
    
    This is equivalent to the Java method `c(String str)`.
    
    Args:
        encoded_str: Base64 encoded string
        
    Returns:
        Decoded and XORed string, or None if error
    """
    if encoded_str is None:
        return None
    
    try:
        # Decode the base64 string
        decoder = StatefulBase64Decoder()
        decoded_bytes = decoder.decode(encoded_str, 0)
        
        if decoded_bytes is None:
            return None
        
        # XOR with "Netease" key
        key = b"Netease"
        result = bytearray(decoded_bytes)
        key_len = len(key)
        
        for i in range(len(result)):
            key_index = i % key_len
            result[i] = result[i] ^ key[key_index]
        
        return result.decode('utf-8')
    except Exception:
        return None
