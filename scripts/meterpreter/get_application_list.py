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