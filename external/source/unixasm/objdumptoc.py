#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Object Dump to C Converter
Port of external/source/unixasm/objdumptoc.rb to Python

Converts objdump output to C array format
"""

import sys
import re


class Parser:
    """Parser for objdump output to C array format"""
    
    SIZE1 = 28
    SIZE2 = 28 + 4 + 32
    SIZE3 = 28 + 4 + 32 + 4
    
    def __init__(self, filename=''):
        """
        Initialize the parser
        
        Args:
            filename (str): Input filename, empty string for stdin
        """
        if filename:
            self.file = open(filename, 'r')
        else:
            self.file = sys.stdin
        
        self.block = []
        self.block_size = 0
    
    def block_begin(self, line):
        """
        Begin a new block based on label line
        
        Args:
            line (str): Line containing block label
        """
        # Get the block name from label
        temp = re.findall(r'\w+', line)
        block_name = temp[1].replace('<', '').replace('>', '').replace(':', '')
        
        self.block.append([])
        self.block[-1].append(f"char {block_name}[]=")
    
    def block_end(self):
        """End the current block"""
        # Insert the block size
        self.block[-1][0] = self.block[-1][0].ljust(self.SIZE1)
        self.block[-1][0] += '/*  '
        self.block[-1][0] += f"{self.block_size} bytes"
        self.block[-1][0] = self.block[-1][0].ljust(self.SIZE2)
        self.block[-1][0] += '  */'
        
        # Reset the block size
        self.block_size = 0
        
        self.block[-1].append(';')
        self.block[-1].append('')
    
    def block_do(self, line):
        """
        Process a block line
        
        Args:
            line (str): Line to process
        """
        temp = line.split('\t')
        
        temp[1] = temp[1].strip()
        temp[1] = re.findall(r'\w+', temp[1])
        
        self.block[-1].append('    "')
        
        for byte in temp[1]:
            self.block[-1][-1] += f"\\x{byte}"
            self.block_size += 1
        
        self.block[-1][-1] += '"'
        self.block[-1][-1] = self.block[-1][-1].ljust(self.SIZE1)
        self.block[-1][-1] += '/*  '
        
        # For file format aixcoff-rs6000
        if len(temp) == 4:
            temp[2] += ' '
            temp[2] += temp[3]
            temp.pop()
        
        if len(temp) == 3:
            temp[2] = temp[2].strip()
            temp[2] = re.findall(r'[$%()+,\-\.<>\w]+', temp[2])
            
            if len(temp[2]) == 2:
                self.block[-1][-1] += temp[2][0].ljust(8)
                self.block[-1][-1] += temp[2][1]
            elif len(temp[2]) == 3:
                self.block[-1][-1] += temp[2][0].ljust(8)
                self.block[-1][-1] += temp[2][1]
                self.block[-1][-1] += ' '
                self.block[-1][-1] += temp[2][2]
            else:
                self.block[-1][-1] += str(temp[2])
        
        self.block[-1][-1] = self.block[-1][-1].ljust(self.SIZE2)
        self.block[-1][-1] += '  */'
    
    def parse_line(self, line):
        """
        Parse a single line
        
        Args:
            line (str): Line to parse
        """
        if re.search(r'\w+ <[\.\w]+>:', line):
            # End a previous block
            if self.block_size != 0:
                self.block_end()
            self.block_begin(line)
        
        elif re.search(r'\w+:\t', line):
            self.block_do(line)
    
    def parse_file(self, file):
        """
        Parse entire file
        
        Args:
            file: File object to parse
        """
        for line in file:
            self.parse_line(line)
        
        # End the last block
        if self.block_size != 0:
            self.block_end()
    
    def parse(self):
        """Parse the input file"""
        self.parse_file(self.file)
    
    def dump_all(self):
        """Dump all parsed blocks"""
        for block in self.block:
            for line in block:
                print(line)
    
    def __del__(self):
        """Cleanup file handle"""
        if self.file != sys.stdin:
            self.file.close()


def main():
    """Main function"""
    if not sys.stdin.isatty():
        # Reading from pipe
        p = Parser('')
        p.parse()
        p.dump_all()
    else:
        # Interactive mode - show usage
        print("Tested with:")
        print("\tGNU objdump 2.9-aix51-020209")
        print("\tGNU objdump 2.15.92.0.2 20040927")
        print("Usage: objdump -dM suffix <file(s)> | python objdumptoc.py")


if __name__ == '__main__':
    main()
