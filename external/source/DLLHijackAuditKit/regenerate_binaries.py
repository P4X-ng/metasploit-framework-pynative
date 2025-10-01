#!/usr/bin/env python3
"""
Regenerate test binaries using msfvenom
"""

import os
import subprocess
import sys


def main():
    # Get paths
    dllbase = os.path.dirname(os.path.abspath(__file__))
    msfbase = os.path.abspath(os.path.join(dllbase, "..", "..", ".."))
    msfv = os.path.join(msfbase, "msfvenom")
    
    # Change to DLL directory
    os.chdir(dllbase)
    
    # Generate binaries
    commands = [
        ["ruby", msfv, "-p", "windows/exec", "CMD=calc.exe", "-f", "exe", "-o", "runcalc.exe"],
        ["ruby", msfv, "-p", "windows/exec", "CMD=calc.exe", "-f", "dll", "-o", "runcalc.dll"],
        ["ruby", msfv, "-p", "windows/exec", "CMD=cmd.exe /c echo yes > exploited.txt", "-f", "dll", "-o", "runtest.dll"],
        ["ruby", msfv, "-p", "windows/exec", "CMD=cmd.exe /c echo yes > exploited.txt", "-f", "exe", "-o", "runtest.exe"],
    ]
    
    for cmd in commands:
        print(f"Running: {' '.join(cmd)}")
        result = subprocess.run(cmd)
        if result.returncode != 0:
            print(f"Command failed with exit code {result.returncode}", file=sys.stderr)
            sys.exit(1)
    
    print("All binaries generated successfully")


if __name__ == "__main__":
    main()
