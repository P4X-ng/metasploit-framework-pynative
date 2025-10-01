#!/usr/bin/env python3
"""
Write data preceded by little-endian 4-byte size
"""

import struct
import sys


def main():
    if len(sys.argv) < 2:
        print("Usage: write_size_and_data.py <file>", file=sys.stderr)
        sys.exit(1)
    
    with open(sys.argv[1], 'rb') as f:
        bundle = f.read()
    
    # Pack as little-endian 4-byte size followed by data
    data = struct.pack('<I', len(bundle)) + bundle
    sys.stdout.buffer.write(data)


if __name__ == "__main__":
    main()
