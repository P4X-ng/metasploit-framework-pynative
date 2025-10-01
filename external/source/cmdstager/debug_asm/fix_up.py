#!/usr/bin/env python3
"""
Fix up the assembly based on the debug.exe transcript

Joshua J. Drake
"""

import re
import sys


def main():
    # Read debug transcript
    try:
        with open("woop.txt", "r") as fd:
            dtrans = fd.read()
    except IOError as e:
        print(f"Error reading woop.txt: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Read assembly input
    try:
        with open("h2b.com.dbg.in", "r") as fd:
            asm = fd.read()
    except IOError as e:
        print(f"Error reading h2b.com.dbg.in: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Extract label addresses
    addrs = {}
    for ln in dtrans.split('\n'):
        if ';' in ln and ':' in ln:
            # Look for lines with labels (format: "address ;label:")
            parts = ln.split()
            if len(parts) >= 2 and parts[1].startswith(';'):
                label_part = parts[1]
                if ':' in label_part:
                    label = label_part[1:label_part.index(':')]
                    addr_part = parts[0].split(':')
                    if len(addr_part) >= 2:
                        addr = int(addr_part[1], 16)
                        addrs[label] = addr
    
    # Replace calls, jmps, and read/write handle/filename references
    replaces = []
    
    for ln in asm.split('\n'):
        # Handle call instructions
        if 'call ' in ln:
            parts = ln.split()
            if len(parts) >= 4 and parts[0] == "call" and parts[2] == ";call":
                old = parts[1]
                func = parts[3]
                if func in addrs:
                    new = addrs[func]
                    replaces.append([func, old, format(new, 'x')])
        
        # Handle jump instructions
        if '(jmp)' in ln:
            parts = ln.split()
            if len(parts) >= 5 and parts[0][0] == 'j' and parts[2].startswith(';j') and parts[4] == "(jmp)":
                old = parts[1]
                func = parts[3]
                if func in addrs:
                    new = addrs[func]
                    replaces.append([func, old, format(new, 'x')])
        
        # Handle read/write handle/filename references
        if re.search(r';(read|write)_(handle|filename)=', ln):
            parts = ln.split()
            if len(parts) >= 3 and parts[0] == "mov":
                parts2 = parts[2].split('=')
                if len(parts2) >= 2:
                    label = parts2[0]
                    if label.startswith(';'):
                        label = label[1:]
                    old = parts2[1]
                    if label in addrs:
                        new = addrs[label]
                        replaces.append([label, old, format(new, 'x')])
    
    # Remove duplicates
    unique_replaces = []
    seen = set()
    for arr in replaces:
        key = (arr[0], arr[1], arr[2])
        if key not in seen:
            seen.add(key)
            unique_replaces.append(arr)
    
    # Replace the stuff
    for arr in unique_replaces:
        asm = asm.replace(arr[1], arr[2])
    
    print(asm)


if __name__ == "__main__":
    main()
