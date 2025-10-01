#!/usr/bin/env python3
##
# WARNING: Metasploit no longer maintains or accepts meterpreter scripts.
# If you'd like to improve this script, please try to port it as a post
# module instead. Thank you.
##

"""
Meterpreter script for running multiple commands on Windows 2003, Windows Vista
and Windows XP and Windows 2008 targets.
Provided by Carlos Perez at carlos_perez[at]darkoperator[dot]com
Version: 0.1
"""

import argparse
import os
import sys

# NOTE: This would need actual framework initialization in a real implementation
# Placeholder for Meterpreter session
session = None


def list_exec(session, cmdlst):
    """Function for running a list of commands stored in a list, returns string"""
    print("[*] Running Command List ...")
    cmdout = ""
    session.response_timeout = 120
    
    for cmd in cmdlst:
        cmd = cmd.strip()
        if len(cmd) < 1:
            continue
        if cmd[0] == "#":
            continue
        
        try:
            print(f"[*] \trunning command {cmd}")
            tmpout = "\n"
            tmpout += "*****************************************\n"
            tmpout += f"      Output of {cmd}\n"
            tmpout += "*****************************************\n"
            
            r = session.sys.process.execute(cmd, None, {'Hidden': True, 'Channelized': True})
            while True:
                d = r.channel.read()
                if not d or d == "":
                    break
                tmpout += d
            
            cmdout += tmpout
            r.channel.close()
        
        except Exception as e:
            print(f"[*] Error Running Command {cmd}: {type(e).__name__} {e}")
    
    return cmdout


def filewrt(file2wrt, data2wrt):
    """Function for writing results of other functions to a file"""
    with open(file2wrt, "a") as output:
        for d in data2wrt.split('\n'):
            output.write(d + '\n')


def usage():
    """Display usage information"""
    print("Windows Multi Command Execution Meterpreter Script")
    print("Usage:")
    print("  -c <commands>  Commands to execute. The command must be enclosed in double quotes and separated by a comma.")
    print("  -r <file>      Text file with list of commands, one per line.")
    print("  -f <file>      File where to save output of command.")
    print("  -h             Help menu.")


def main():
    parser = argparse.ArgumentParser(
        description="Windows Multi Command Execution Meterpreter Script",
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
        "-f", "--output-file",
        help="File where to save output of command."
    )
    parser.add_argument(
        "-h", "--help", action="store_true",
        help="Help menu."
    )
    
    args = parser.parse_args()
    
    if args.help or (args.commands is None and args.read_file is None):
        usage()
        sys.exit(0)
    
    if session is None:
        print("[-] No active session")
        sys.exit(1)
    
    commands = []
    
    if args.commands:
        commands = args.commands.split(',')
    
    if args.read_file:
        script = args.read_file
        if not os.path.exists(script):
            print(f"[-] Command List File does not exist: {script}")
            sys.exit(1)
        else:
            with open(script, 'r') as f:
                for line in f:
                    commands.append(line.strip())
    
    if not commands:
        usage()
        sys.exit(1)
    
    if args.output_file:
        filewrt(args.output_file, list_exec(session, commands))
    else:
        for line in list_exec(session, commands).split('\n'):
            print(f"[*] {line}")


if __name__ == "__main__":
    main()
