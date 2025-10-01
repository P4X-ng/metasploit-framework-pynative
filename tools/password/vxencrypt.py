#!/usr/bin/env python3
"""
VxWorks password hash calculator

This script can be used to calculate hash values for VxWorks passwords.
"""

import sys


def hashit(inp):
    """Calculate VxWorks password hash"""
    if len(inp) < 8 or len(inp) > 120:
        raise ValueError("The password must be between 8 and 120 characters")
    
    total = 0
    bytes_arr = [ord(c) for c in inp]
    
    for i, byte in enumerate(bytes_arr):
        total += (byte * (i + 1)) ^ (i + 1)
    
    return hackit(total)


def hackit(total):
    """Apply VxWorks hash algorithm"""
    magic = 31695317
    res = str((total * magic) & 0xffffffff)
    
    result = []
    for c in res:
        byte = ord(c)
        if byte < 0x33:
            byte += 0x21
        if byte < 0x37:
            byte += 0x2f
        if byte < 0x39:
            byte += 0x42
        result.append(chr(byte))
    
    return ''.join(result)


def main():
    password = sys.argv[1] if len(sys.argv) > 1 else "flintstone"
    hash_value = hashit(password)
    print(f"[*] Hash for password '{password}' is {hash_value}", file=sys.stderr)


if __name__ == "__main__":
    main()
