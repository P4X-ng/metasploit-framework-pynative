#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MSF Util Helper Module

This module provides cross-platform utility functions for finding executables
and other system helpers.
"""

import os


class Helper:
    """Cross-platform utility helper functions"""
    
    @staticmethod
    def which(cmd):
        """
        Cross-platform way of finding an executable in the $PATH.
        
        Args:
            cmd: Command name to search for (e.g., 'ruby', 'python')
            
        Returns:
            Full path to the executable if found, None otherwise
            
        Example:
            which('ruby') #=> /usr/bin/ruby
        """
        # On Windows, check PATHEXT environment variable for extensions
        exts = os.environ.get('PATHEXT', '').split(';') if os.name == 'nt' else ['']
        
        # Search each directory in PATH
        for path in os.environ.get('PATH', '').split(os.pathsep):
            for ext in exts:
                exe = os.path.join(path, f"{cmd}{ext}")
                if os.path.isfile(exe) and os.access(exe, os.X_OK):
                    return exe
        
        return None


if __name__ == '__main__':
    # Example usage
    import sys
    
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        result = Helper.which(cmd)
        if result:
            print(f"Found: {result}")
        else:
            print(f"'{cmd}' not found in PATH")
    else:
        # Test with common executables
        for test_cmd in ['python', 'python3', 'ruby', 'bash']:
            result = Helper.which(test_cmd)
            print(f"{test_cmd}: {result if result else 'not found'}")
