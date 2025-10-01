#!/usr/bin/env python3
#
# WARNING: Metasploit no longer maintains or accepts meterpreter scripts.
# If you'd like to improve this script, please try to port it as a post
# module instead. Thank you.
#

# Author: Carlos Perez at carlos_perez[at]darkoperator.com
# Python translation: Your Name/Handle
#
# Meterpreter script for listing installed applications and their version.

import argparse
import threading

# This script assumes a 'client' object is available, representing the Meterpreter session.
# All framework, sys, and fs calls are performed through this object.

# ================== Mock Client for Standalone Testing ==================
class MockRegistry:
    def enum_key(self, key_path):
        print(f"[*] Enumerating key: {key_path}")
        if "Uninstall" in key_path:
            return ["App1", "App2", "Microsoft .NET Framework"]
        return []

    def query_value(self, key_path, value_name):
        class MockValue:
            def __init__(self, data):
                self.data = data

        if "App1" in key_path and value_name == "DisplayName":
            return MockValue("Application One")
        if "App1" in key_path and value_name == "DisplayVersion":
            return MockValue("1.0.0")
        if "App2" in key_path and value_name == "DisplayName":
            return MockValue("The Second Application")
        if "App2" in key_path and value_name == "DisplayVersion":
            return MockValue("2.5")
        # Return empty for the .NET framework to simulate a key without a DisplayName
        if "Framework" in key_path:
            return MockValue("")
        raise RuntimeError("Value not found")

class MockClient:
    def __init__(self):
        self.platform = 'windows'
        self.sys = self
        self.registry = MockRegistry()

# ================== Helper Functions ==================
def print_status(msg):
    print(f"[*] {msg}")

def print_error(msg):
    print(f"[-] {msg}")

def print_line(msg):
    print(msg)

# ================== Main Logic ==================
def get_app_info(key_path, subkey, results, lock):
    """Worker thread function to retrieve application info from a registry key."""
    try:
        full_key = f"{key_path}\\{subkey}"
        disp_name = client.sys.registry.query_value(full_key, "DisplayName").data
        disp_version = client.sys.registry.query_value(full_key, "DisplayVersion").data

        if disp_name and disp_name.strip():
            with lock:
                results.append((disp_name, disp_version or ""))
    except Exception:
        # Silently ignore keys that can't be read, just like the original script
        pass

def app_list():
    """Enumerates and lists installed applications."""
    results = []
    lock = threading.Lock()
    threads = []

    app_keys = [
        'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
        'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall'
    ]

    print_status("Enumerating installed applications via the registry...")

    for key_path in app_keys:
        try:
            subkeys = client.sys.registry.enum_key(key_path)
            if subkeys:
                for subkey in subkeys:
                    thread = threading.Thread(target=get_app_info, args=(key_path, subkey, results, lock))
                    threads.append(thread)
                    thread.start()
        except Exception as e:
            print_error(f"Could not access registry key {key_path}: {e}")

    # Wait for all threads to complete
    for t in threads:
        t.join()

    # Sort results alphabetically by application name
    results.sort(key=lambda x: x[0])

    # Format and print the table
    if not results:
        print_status("No applications found or could not read registry keys.")
        return

    # Basic table formatting
    col1_width = max(len(row[0]) for row in results) + 2
    header1, header2 = "Name", "Version"

    print_line("\nInstalled Applications")
    print_line("=" * (col1_width + len(header2) + 1))
    print_line(f"{header1:<{col1_width}}{header2}")
    print_line(f"{'-'*(col1_width-2):<{col1_width}}{'-'*len(header2)}")

    for name, version in results:
        print_line(f"{name:<{col1_width}}{version}")

    print_line("")


def main():
    parser = argparse.ArgumentParser(description="Lists installed applications and their versions.")
    # The -h is handled automatically by argparse
    args = parser.parse_args()

    if client.platform != 'windows':
        print_error("This script only runs on Windows platforms!")
        return

    app_list()

if __name__ == "__main__":
    if 'client' not in globals():
        print_status("This script is intended to run in a Meterpreter session.")
        print_status("Initializing a mock client for testing purposes.")
        client = MockClient()
        main()
    else:
        main()

        
        
"""
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
    List installed applications on Windows systems
    
    def __init__(self, client):
        Initialize the application list extractor
        
        Args:
            client: Meterpreter client session object
        self.client = client
        self.applications = []
    
    def print_status(self, msg):
        print(f"[*] {msg}")
    
    def print_error(self, msg):
        print(f"[-] {msg}")
    
    def print_line(self, msg):
        print(msg)
    
    def app_list(self):
        Extract list of installed applications from Windows registry
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
        "
        Query application information from registry key
        
        Args:
            reg_key: Registry key path
        "
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
    "Main entry point"
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
"""
        
        