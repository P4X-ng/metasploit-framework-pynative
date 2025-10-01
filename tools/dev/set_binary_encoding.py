#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Set Binary Encoding Tool

This script adds a UTF-8 encoding declaration to Python files that don't have one.
This is the Python equivalent of setting binary encoding in Ruby files.
"""

import sys
import os


def set_encoding(filename):
    """
    Add UTF-8 encoding declaration to a Python file if it doesn't have one
    
    Args:
        filename: Path to the Python file to process
    """
    if not os.path.exists(filename):
        print(f"Error: File '{filename}' not found")
        return False
    
    # The encoding string to add
    encoding_str = '# -*- coding: utf-8 -*-'
    
    try:
        # Read the file
        with open(filename, 'r', encoding='utf-8', errors='ignore') as fd:
            lines = fd.readlines()
        
        if not lines:
            return False
        
        # Check if encoding is already present
        done = False
        data = []
        
        for i, line in enumerate(lines):
            # Check if this line already has a coding declaration
            if 'coding:' in line or 'coding=' in line:
                done = True
            
            # If we haven't added encoding yet and this is not a shebang line
            if not done and i > 0:  # Skip first line if it's shebang
                if not line.strip().startswith('#!'):
                    data.append(encoding_str + '\n')
                    done = True
            elif not done and i == 0:
                # First line - check if it's shebang
                if not line.strip().startswith('#!'):
                    # No shebang, add encoding first
                    data.append(encoding_str + '\n')
                    done = True
            
            data.append(line)
        
        # If we still haven't added it (file only had shebang or was empty), add after shebang
        if not done and data:
            if data[0].strip().startswith('#!'):
                data.insert(1, encoding_str + '\n')
            else:
                data.insert(0, encoding_str + '\n')
        
        # Write the file back
        with open(filename, 'w', encoding='utf-8') as fd:
            fd.writelines(data)
        
        return True
    
    except Exception as e:
        print(f"Error processing file: {e}")
        return False


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 set_binary_encoding.py <filename>")
        print("\nAdds UTF-8 encoding declaration to Python files")
        sys.exit(1)
    
    filename = sys.argv[1]
    
    if set_encoding(filename):
        print(f"Successfully processed: {filename}")
    else:
        print(f"Failed to process: {filename}")
        sys.exit(1)
