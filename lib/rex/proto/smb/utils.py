#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SMB Protocol Utilities
Port of rex/proto/smb/utils.rb to Python
"""

# Import constants (assuming they exist or will be created)
# from .constants import Constants as CONST


class Utils:
    """
    Utility class for SMB protocol operations
    """
    
    # Note: These constants would typically come from a constants module
    # For now, defining them here based on the Ruby implementation
    OPEN_ACCESS_READ = 0x01
    OPEN_ACCESS_READWRITE = 0x03
    OPEN_SHARE_DENY_NONE = 0x40
    
    OPEN_MODE_EXCL = 0x10
    OPEN_MODE_TRUNC = 0x20
    OPEN_MODE_CREAT = 0x10
    OPEN_MODE_OPEN = 0x01
    
    CREATE_ACCESS_OPENCREATE = 0x10
    CREATE_ACCESS_EXIST = 0x01
    
    @staticmethod
    def open_mode_to_access(mode_str):
        """
        Creates an access mask for use with the CLIENT.open() call based on a string
        
        Args:
            mode_str (str): Mode string (e.g., 'r', 'w', 'rw')
            
        Returns:
            int: Access mask value
        """
        access = Utils.OPEN_ACCESS_READ | Utils.OPEN_SHARE_DENY_NONE
        
        for c in mode_str.lower():
            if c == 'w':
                access |= Utils.OPEN_ACCESS_READWRITE
                
        return access
    
    @staticmethod
    def open_mode_to_mode(mode_str):
        """
        Creates a mode mask for use with the CLIENT.open() call based on a string
        
        Args:
            mode_str (str): Mode string containing flags
            
        Returns:
            int: Mode mask value
        """
        mode = 0
        
        for c in mode_str.lower():
            if c == 'x':  # Fail if the file already exists
                mode |= Utils.OPEN_MODE_EXCL
            elif c == 't':  # Truncate the file if it already exists
                mode |= Utils.OPEN_MODE_TRUNC
            elif c == 'c':  # Create the file if it does not exist
                mode |= Utils.OPEN_MODE_CREAT
            elif c == 'o':  # Just open the file, clashes with x
                mode |= Utils.OPEN_MODE_OPEN
                
        return mode
    
    @staticmethod
    def create_mode_to_disposition(mode_str):
        """
        Returns a disposition value for smb.create based on permission string
        
        Args:
            mode_str (str): Mode string
            
        Returns:
            int: Disposition value
        """
        for c in mode_str.lower():
            if c == 'c':  # Create the file if it does not exist
                return Utils.CREATE_ACCESS_OPENCREATE
            elif c == 'o':  # Just open the file and fail if it does not exist
                return Utils.CREATE_ACCESS_EXIST
                
        return Utils.CREATE_ACCESS_OPENCREATE
    
    @staticmethod
    def time_smb_to_unix(thi, tlo):
        """
        Convert a 64-bit signed SMB time to a unix timestamp
        
        NOTE: the difference below came from: ::Time.utc("1970-1-1") - ::Time.utc("1601-1-1")
        
        Args:
            thi (int): High 32 bits of SMB time
            tlo (int): Low 32 bits of SMB time
            
        Returns:
            int: Unix timestamp
        """
        return (((thi << 32) + tlo) // 10000000) - 11644473600
    
    @staticmethod
    def time_unix_to_smb(unix_time):
        """
        Convert a unix timestamp to a 64-bit signed server time
        
        Args:
            unix_time (int): Unix timestamp
            
        Returns:
            tuple: (thi, tlo) - high and low 32 bits of SMB time
        """
        t64 = (unix_time + 11644473600) * 10000000
        thi = (t64 & 0xffffffff00000000) >> 32
        tlo = (t64 & 0x00000000ffffffff)
        return (thi, tlo)
    
    @staticmethod
    def nbname_encode(name_str):
        """
        Convert a name to its NetBIOS equivalent
        
        Args:
            name_str (str): Name to encode
            
        Returns:
            str: NetBIOS encoded name
        """
        encoded = ''
        
        for x in range(16):
            if x >= len(name_str):
                encoded += 'CA'
            else:
                c = ord(name_str[x].upper())
                encoded += chr((c // 16) + 0x41) + chr((c % 16) + 0x41)
                
        return encoded
    
    @staticmethod
    def nbname_decode(encoded_str):
        """
        Convert a name from its NetBIOS equivalent
        
        Args:
            encoded_str (str): NetBIOS encoded name
            
        Returns:
            str: Decoded name
        """
        decoded = ''
        encoded = encoded_str
        
        # Pad if odd length
        if len(encoded) % 2 != 0:
            encoded += 'A'
            
        while len(encoded) > 0:
            two = encoded[:2]
            encoded = encoded[2:]
            
            if len(two) == 2:
                decoded += chr(((ord(two[0]) - 0x41) * 16) + ord(two[1]) - 0x41)
                
        return decoded
