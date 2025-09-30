#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AIX Power Assembly Template Generator
Port of external/source/unixasm/aix-power.rb to Python

Generates AIX PowerPC assembly code with system call numbers for different AIX versions
"""

import sys
import struct


class Template:
    """Base template class"""
    
    def __init__(self, filename):
        """
        Initialize template from file
        
        Args:
            filename (str): Template file path
        """
        self.template = ''
        self.result = ''
        
        try:
            with open(filename, 'r') as f:
                self.template = f.read()
        except FileNotFoundError:
            pass
    
    def parse(self):
        """Parse template - to be implemented by subclass"""
        # In Python, we'd use string.Template or jinja2 instead of ERB
        # For now, this is a placeholder
        self.result = self.template
    
    def get_result(self):
        """Get parsed result"""
        return self.result


class Source(Template):
    """Source code template with AIX system call numbers"""
    
    def __init__(self, filename):
        """Initialize source template"""
        self.__CAL = 2047
        self.__cal = b"\x38\x5d"
        self._cal = {}
        self.cal = {}
        self.ver = ''
        
        # System call attributes
        self.__NR_execve = 0
        self.__NR_getpeername = 0
        self.__NR_accept = 0
        self.__NR_listen = 0
        self.__NR_bind = 0
        self.__NR_socket = 0
        self.__NR_connect = 0
        self.__NR_close = 0
        self.__NR_kfcntl = 0
        
        # String accumulator for each syscall
        self.execve = ''
        self.getpeername = ''
        self.accept = ''
        self.listen = ''
        self.bind = ''
        self.socket = ''
        self.connect = ''
        self.close = ''
        self.kfcntl = ''
        
        super().__init__(filename)
    
    def parse(self):
        """Parse and generate system call definitions"""
        # Calculate negative call numbers
        __NC_execve = -(self.__CAL - self.__NR_execve)
        __NC_getpeername = -(self.__CAL - self.__NR_getpeername)
        __NC_accept = -(self.__CAL - self.__NR_accept)
        __NC_listen = -(self.__CAL - self.__NR_listen)
        __NC_bind = -(self.__CAL - self.__NR_bind)
        __NC_socket = -(self.__CAL - self.__NR_socket)
        __NC_connect = -(self.__CAL - self.__NR_connect)
        __NC_close = -(self.__CAL - self.__NR_close)
        __NC_kfcntl = -(self.__CAL - self.__NR_kfcntl)
        
        # Build binary call sequences
        self._cal[self.ver] = {
            'execve': self.__cal + struct.pack('>H', __NC_execve & 0xFFFF),
            'getpeername': self.__cal + struct.pack('>H', __NC_getpeername & 0xFFFF),
            'accept': self.__cal + struct.pack('>H', __NC_accept & 0xFFFF),
            'listen': self.__cal + struct.pack('>H', __NC_listen & 0xFFFF),
            'bind': self.__cal + struct.pack('>H', __NC_bind & 0xFFFF),
            'socket': self.__cal + struct.pack('>H', __NC_socket & 0xFFFF),
            'connect': self.__cal + struct.pack('>H', __NC_connect & 0xFFFF),
            'close': self.__cal + struct.pack('>H', __NC_close & 0xFFFF),
            'kfcntl': self.__cal + struct.pack('>H', __NC_kfcntl & 0xFFFF),
        }
        
        # Convert to string format
        cal = {}
        cal[self.ver] = {}
        
        for key, value in self._cal[self.ver].items():
            cal[self.ver][key] = []
            output = ''
            output += f'#ifdef AIX{self.ver.replace(".", "")}\n'
            output += '    "'
            for byte in value:
                output += f'\\x{byte:02x}'
            output += '"'.ljust(7)
            
            # Unpack and calculate offset
            unpacked = struct.unpack('>HH', value)
            offset = 65536 - unpacked[1]
            output += f'/*  cal     r2,-{offset}(r29)'
            output += '*/'.rjust(15)
            output += '\n'
            output += '#endif\n'
            
            cal[self.ver][key].append(output)
        
        # Accumulate into instance variables
        for ver_key, ver_dict in cal.items():
            for syscall_key, value in ver_dict.items():
                current_value = getattr(self, syscall_key, '')
                setattr(self, syscall_key, current_value + value[-1])
        
        # Call parent parse
        super().parse()


class Parser:
    """Parser for AIX version-specific system calls"""
    
    def __init__(self, filename):
        """
        Initialize parser
        
        Args:
            filename (str): Template filename
        """
        self.src = Source(filename)
    
    def parse(self):
        """Parse all AIX versions"""
        vers = [
            '6.1.4',
            '6.1.3',
            '6.1.2',
            '6.1.1',
            '6.1.0',
            '5.3.10',
            '5.3.9',
            '5.3.8',
            '5.3.7',
        ]
        
        for ver in vers:
            # System call numbers for each version
            syscalls = {
                '6.1.4': {
                    'execve': 7, 'getpeername': 211, 'accept': 237,
                    'listen': 240, 'bind': 242, 'socket': 243,
                    'connect': 244, 'close': 278, 'kfcntl': 658,
                },
                '6.1.3': {
                    'execve': 7, 'getpeername': 205, 'accept': 232,
                    'listen': 235, 'bind': 237, 'socket': 238,
                    'connect': 239, 'close': 272, 'kfcntl': 644,
                },
                '6.1.2': {
                    'execve': 7, 'getpeername': 205, 'accept': 232,
                    'listen': 235, 'bind': 237, 'socket': 238,
                    'connect': 239, 'close': 272, 'kfcntl': 635,
                },
                '6.1.1': {
                    'execve': 7, 'getpeername': 202, 'accept': 229,
                    'listen': 232, 'bind': 234, 'socket': 235,
                    'connect': 236, 'close': 269, 'kfcntl': 614,
                },
                '6.1.0': {
                    'execve': 6, 'getpeername': 203, 'accept': 229,
                    'listen': 232, 'bind': 234, 'socket': 235,
                    'connect': 236, 'close': 269, 'kfcntl': 617,
                },
            }
            
            # Versions 5.3.x share the same syscall numbers
            if ver.startswith('5.3'):
                syscalls[ver] = {
                    'execve': 6, 'getpeername': 198, 'accept': 214,
                    'listen': 215, 'bind': 216, 'socket': 217,
                    'connect': 218, 'close': 245, 'kfcntl': 493,
                }
            
            # Set system call numbers
            self.src.__NR_execve = syscalls[ver]['execve']
            self.src.__NR_getpeername = syscalls[ver]['getpeername']
            self.src.__NR_accept = syscalls[ver]['accept']
            self.src.__NR_listen = syscalls[ver]['listen']
            self.src.__NR_bind = syscalls[ver]['bind']
            self.src.__NR_socket = syscalls[ver]['socket']
            self.src.__NR_connect = syscalls[ver]['connect']
            self.src.__NR_close = syscalls[ver]['close']
            self.src.__NR_kfcntl = syscalls[ver]['kfcntl']
            
            self.src.ver = ver
            self.src.parse()
    
    def get_result(self):
        """Get parser result"""
        return self.src.get_result()


def main():
    """Main function"""
    if len(sys.argv) < 2:
        print("Usage: python aix-power.py <template_file>", file=sys.stderr)
        sys.exit(1)
    
    filename = sys.argv[1]
    
    parser = Parser(filename)
    parser.parse()
    print(parser.get_result())


if __name__ == '__main__':
    main()
