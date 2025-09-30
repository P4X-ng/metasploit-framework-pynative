#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Ruby Base64 Encoder Module
Port of modules/encoders/ruby/base64.rb to Python

This module requires Metasploit: https://metasploit.com/download
Current source: https://github.com/rapid7/metasploit-framework

This encoder returns a base64 string encapsulated in
eval(%(base64 encoded string).unpack(%(m0)).first).
"""

import base64 as b64


class BadcharError(Exception):
    """Exception raised when bad characters are found"""
    pass


class RubyBase64Encoder:
    """
    Ruby Base64 Encoder
    
    Encodes Ruby code using base64 and wraps it in an eval statement
    """
    
    # Rank constant
    RANK_GREAT = 500
    
    def __init__(self):
        """Initialize the encoder"""
        self.name = 'Ruby Base64 Encoder'
        self.description = (
            'This encoder returns a base64 string encapsulated in '
            'eval(%(base64 encoded string).unpack(%(m0)).first).'
        )
        self.author = 'Robin Stenvi <robin.stenvi[at]gmail.com>'
        self.license = 'BSD_LICENSE'
        self.arch = 'ARCH_RUBY'
        self.rank = self.RANK_GREAT
    
    def encode_block(self, state, buf):
        """
        Encode a block of data
        
        Args:
            state: Encoder state object containing badchars
            buf: Buffer to encode
            
        Returns:
            str: Encoded string
            
        Raises:
            BadcharError: If bad characters are found in encoding
        """
        # Required characters for the encoding format
        required_chars = ['(', ')', '.', '%', 'e', 'v', 'a', 'l', 
                         'u', 'n', 'p', 'c', 'k', 'm', '0', 'f', 'i', 'r', 's', 't']
        
        # Check if any required characters are in badchars
        badchars = getattr(state, 'badchars', '')
        for c in required_chars:
            if c in badchars:
                raise BadcharError(f"Required character '{c}' is in badchars")
        
        # Encode to base64
        b64_encoded = b64.b64encode(buf.encode() if isinstance(buf, str) else buf).decode('ascii')
        
        # Check if any badchars are in the base64 output
        for byte_char in badchars:
            if byte_char in b64_encoded:
                raise BadcharError(f"Badchar '{byte_char}' found in base64 output")
        
        # Return the encoded string in eval format
        return f'eval(%({b64_encoded}).unpack(%(m0)).first)'


# For use as a standalone encoder
def encode(buf, badchars=''):
    """
    Standalone encoding function
    
    Args:
        buf: Buffer to encode
        badchars: String of bad characters to avoid
        
    Returns:
        str: Encoded string
    """
    class State:
        def __init__(self, badchars):
            self.badchars = badchars
    
    encoder = RubyBase64Encoder()
    state = State(badchars)
    return encoder.encode_block(state, buf)


if __name__ == '__main__':
    # Example usage
    import sys
    
    if len(sys.argv) > 1:
        payload = sys.argv[1]
        badchars = sys.argv[2] if len(sys.argv) > 2 else ''
        
        try:
            encoded = encode(payload, badchars)
            print(encoded)
        except BadcharError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print("Usage: python base64.py <payload> [badchars]")
        print("Example: python base64.py 'puts \"hello\"'")
