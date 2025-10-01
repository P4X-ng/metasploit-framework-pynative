#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
WARNING: Metasploit no longer maintains or accepts meterpreter scripts.
If you'd like to improve this script, please try to port it as a post
module instead. Thank you.

Meterpreter script for listing installed applications and their version.
Provided: carlos_perez[at]darkoperator[dot]com

This is a Python translation of the Ruby meterpreter script.
"""

import argparse
import sys
import threading
import time


class ApplicationList:
    """List installed applications on Windows systems"""
    
    def __init__(self, client):
        """
        Initialize the application list extractor
        
        Args:
            client: Meterpreter client session object
        """
        self.client = client
        self.applications = []
    
    def print_status(self, msg):
        """Print status message"""
        print(f"[*] {msg}")
    
    def print_error(self, msg):
        """Print error message"""
        print(f"[-] {msg}")
    
    def print_line(self, msg):
        """Print message"""
        print(msg)
    
    def app_list(self):
        """
        Extract list of installed applications from Windows registry
        """
        # Registry keys to check for installed applications
        appkeys = [
            'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
            'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall'
        ]
        
        threadnum = 0
        threads = []
        
        for keyx86 in appkeys:
            try:
                soft_keys = self.client.registry_enumkeys(keyx86)
                if not soft_keys:
                    continue
                
                for k in soft_keys:
                    if threadnum < 10:
                        # Create thread to query registry
                        t = threading.Thread(
                            target=self._query_app_info,
                            args=(f"{keyx86}\\{k}",)
                        )
                        t.daemon = True
                        t.start()
                        threads.append(t)
                        threadnum += 1
                    else:
                        # Wait for threads to complete
                        time.sleep(0.05)
                        threads = [t for t in threads if t.is_alive()]
                        threadnum = len(threads)
            except Exception as e:
                self.print_error(f"Error enumerating {keyx86}: {e}")
        
        # Wait for all threads to complete
        for t in threads:
            t.join(timeout=5.0)
        
        # Display results in table format
        self._display_table()
    
    def _query_app_info(self, reg_key):
        """
        Query application information from registry key
        
        Args:
            reg_key: Registry key path
        """
        try:
            dispnm = self.client.registry_getvaldata(reg_key, "DisplayName")
            dispversion = self.client.registry_getvaldata(reg_key, "DisplayVersion")
            
            # Only add if display name has content
            if dispnm and str(dispnm).strip():
                self.applications.append({
                    'name': dispnm,
                    'version': dispversion if dispversion else ''
                })
        except Exception:
            # Silently ignore errors for individual keys
            pass
    
    def _display_table(self):
        """Display applications in a formatted table"""
        if not self.applications:
            self.print_line("\nNo applications found\n")
            return
        
        # Sort by name
        self.applications.sort(key=lambda x: x['name'].lower() if x['name'] else '')
        
        # Calculate column widths
        max_name_len = max(len(app['name']) for app in self.applications) if self.applications else 20
        max_ver_len = max(len(str(app['version'])) for app in self.applications) if self.applications else 10
        
        # Ensure minimum widths
        max_name_len = max(max_name_len, 20)
        max_ver_len = max(max_ver_len, 10)
        
        # Print table
        self.print_line("\nInstalled Applications")
        self.print_line("=" * (max_name_len + max_ver_len + 5))
        self.print_line(f" {'Name':<{max_name_len}} {'Version':<{max_ver_len}}")
        self.print_line("-" * (max_name_len + max_ver_len + 5))
        
        for app in self.applications:
            name = app['name'][:max_name_len] if len(app['name']) > max_name_len else app['name']
            version = str(app['version'])[:max_ver_len] if len(str(app['version'])) > max_ver_len else str(app['version'])
            self.print_line(f" {name:<{max_name_len}} {version:<{max_ver_len}}")
        
        self.print_line("")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Meterpreter Script for extracting a list of installed applications and their version',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # No need to explicitly add -h/--help as argparse adds it automatically
    
    args = parser.parse_args()
    
    # NOTE: In actual use, this would get the client from the framework
    print("NOTE: This is a translated script that requires meterpreter framework integration")
    print("[*] Extracting installed application list...")
    print("[*] This would enumerate:")
    print("    - HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
    print("    - HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
    print("[*] And display application names and versions")
    
    # Placeholder for actual implementation
    # client = get_meterpreter_client()
    # 
    # if client.platform != 'windows':
    #     print("[-] This version of Meterpreter is not supported with this Script!")
    #     return 1
    # 
    # app_lister = ApplicationList(client)
    # app_lister.app_list()
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
