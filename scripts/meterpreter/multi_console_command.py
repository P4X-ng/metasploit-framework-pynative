#!/usr/bin/env python3
##
# WARNING: Metasploit no longer maintains or accepts meterpreter scripts.
# If you'd like to improve this script, please try to port it as a post
# module instead. Thank you.
##

"""
Meterpreter script for running multiple console commands on a meterpreter session
Provided by Carlos Perez at carlos_perez[at]darkoperator[dot]com
Version: 0.1
"""

import argparse
import os
import sys

# NOTE: This would need actual framework initialization in a real implementation
# Placeholder for Meterpreter client
client = None


def usage():
    """Display usage information"""
    print("Console Multi Command Execution Meterpreter Script")
    print("Usage:")
    print("  -c <commands>  Commands to execute. The command must be enclosed in double quotes and separated by a comma.")
    print("  -r <file>      Text file with list of commands, one per line.")
    print("  -s             Hide commands output for work in background sessions")
    print("  -h             Help menu.")


def main():
    parser = argparse.ArgumentParser(
        description="Console Multi Command Execution Meterpreter Script",
        add_help=False
    )
    parser.add_argument(
        "-c", "--commands",
        help="Commands to execute. The command must be enclosed in double quotes and separated by a comma."
    )
    parser.add_argument(
        "-r", "--read-file",
        help="Text file with list of commands, one per line."
    )
    parser.add_argument(
        "-s", "--silence", action="store_true",
        help="Hide commands output for work in background sessions"
    )
    parser.add_argument(
        "-h", "--help", action="store_true",
        help="Help menu."
    )
    
    args = parser.parse_args()
    
    if args.help or (args.commands is None and args.read_file is None):
        usage()
        sys.exit(0)
    
    commands = None
    
    if args.commands:
        commands = args.commands.split(',')
    
    if args.read_file:
        script = args.read_file
        if not os.path.exists(script):
            print(f"[-] Command List File does not exist: {script}")
            sys.exit(1)
        else:
            commands = []
            with open(script, 'r') as f:
                for line in f:
                    commands.append(line.strip())
    
    if client is None:
        print("[-] No active client")
        sys.exit(1)
    
    if commands is None:
        usage()
        sys.exit(1)
    
    print("[*] Running Command List ...")
    
    for cmd in commands:
        cmd = cmd.strip()
        if len(cmd) < 1:
            continue
        if cmd[0] == "#":
            continue
        
        try:
            print(f"[*] \tRunning command {cmd}")
            if args.silence:
                client.console.disable_output = True
            
            client.console.run_single(cmd)
            
            if args.silence:
                client.console.disable_output = False
        
        except Exception as e:
            print(f"[*] Error Running Command {cmd}: {type(e).__name__} {e}")


if __name__ == "__main__":
    main()
