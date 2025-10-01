#!/usr/bin/env python3
##
# WARNING: Metasploit no longer maintains or accepts meterpreter scripts.
# If you'd like to improve this script, please try to port it as a post
# module instead. Thank you.
##

"""
Meterpreter script for running multiple scripts on a Meterpreter Session
Provided by Carlos Perez at carlos_perez[at]darkoperator[dot]com
Version: 0.2
"""

import argparse
import os
import sys

# NOTE: This would need actual framework initialization in a real implementation
# Placeholder for Meterpreter session
session = None


def script_exec(session, scrptlst):
    """Function for running a list of scripts stored in a string"""
    print("[*] Running script List ...")
    
    for scrpt in scrptlst.split('\n'):
        scrpt = scrpt.strip()
        if len(scrpt) < 1:
            continue
        if scrpt[0] == "#":
            continue
        
        try:
            script_components = scrpt.split()
            script = script_components[0]
            script_args = script_components[1:]
            print(f"[*] \trunning script {scrpt}")
            session.execute_script(script, script_args)
        except Exception as e:
            print(f"[-] Error: {type(e).__name__} {e}")
            print(f"[-] Error in script: {scrpt}")


def usage():
    """Display usage information"""
    print("Multi Script Execution Meterpreter Script")
    print("Usage:")
    print("  -c <commands>  Collection of scripts to execute. Each script command must be enclosed in double quotes and separated by a semicolon.")
    print("  -r <file>      Text file with list of commands, one per line.")
    print("  -h             Help menu.")


def main():
    parser = argparse.ArgumentParser(
        description="Multi Script Execution Meterpreter Script",
        add_help=False
    )
    parser.add_argument(
        "-c", "--commands",
        help="Collection of scripts to execute. Each script command must be enclosed in double quotes and separated by a semicolon."
    )
    parser.add_argument(
        "-r", "--read-file",
        help="Text file with list of commands, one per line."
    )
    parser.add_argument(
        "-h", "--help", action="store_true",
        help="Help menu."
    )
    
    args = parser.parse_args()
    
    if args.help or (args.commands is None and args.read_file is None):
        usage()
        sys.exit(0)
    
    commands = ""
    
    if args.commands:
        commands = args.commands.replace(';', '\n')
    
    if args.read_file:
        script = args.read_file
        if not os.path.exists(script):
            print(f"[-] Script List File does not exist: {script}")
            sys.exit(1)
        else:
            with open(script, 'r') as f:
                for line in f:
                    commands += line
    
    if session is None:
        print("[-] No active session")
        sys.exit(1)
    
    print("[*] Running Multiscript script.....")
    script_exec(session, commands)


if __name__ == "__main__":
    main()
