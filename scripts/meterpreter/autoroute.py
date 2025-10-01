#!/usr/bin/env python3

#
# WARNING: Metasploit no longer maintains or accepts meterpreter scripts.
# If you'd like to improve this script, please try to port it as a post
# module instead. Thank you.
#

#
# Meterpreter script for setting up a route from within a
# Meterpreter session, without having to background the
# current session.
#

import argparse
import ipaddress

# This script assumes a 'client' object is available, which is the Meterpreter session.
# It also assumes the client object has a 'switchboard' attribute that is a Python
# equivalent of Rex::Socket::SwitchBoard.

# Mock client for standalone testing
class MockSwitchboard:
    def __init__(self):
        self._routes = []

    def add_route(self, subnet, netmask, session):
        # In a real implementation, 'session' would be the client object.
        route = {'subnet': subnet, 'netmask': netmask, 'comm': session}
        if route not in self._routes:
            self._routes.append(route)
            return True
        return False

    def remove_route(self, subnet, netmask, session):
        route = {'subnet': subnet, 'netmask': netmask, 'comm': session}
        if route in self._routes:
            self._routes.remove(route)
            return True
        return False

    def routes(self):
        return self._routes

    def __iter__(self):
        return iter(self._routes)

    def __len__(self):
        return len(self._routes)

class MockSession:
    def __init__(self, sid):
        self.sid = sid
        self.name = f"MockSession::{sid}"

class MockClient:
    def __init__(self):
        self.switchboard = MockSwitchboard()
        self.sock = self # for peerhost
        self.peerhost = "127.0.0.1"
        self.session = MockSession(1) # a mock session object

# Uncomment for standalone testing
# client = MockClient()

def print_status(msg):
    print(f"[*] {msg}")

def print_error(msg):
    print(f"[-] {msg}")

def print_good(msg):
    print(f"[+] {msg}")


def delete_all_routes(client):
    """Deletes all routes from the switchboard."""
    if len(client.switchboard) > 0:
        routes_to_delete = [
            {'subnet': r['subnet'], 'netmask': r['netmask']} for r in client.switchboard
        ]
        for route_opts in routes_to_delete:
            delete_route(client, route_opts)
        print_status("Deleted all routes")
    else:
        print_status("No routes have been added yet")

def print_routes(client):
    """Prints the active routing table."""
    if len(client.switchboard) > 0:
        header = "Active Routing Table"
        columns = ['Subnet', 'Netmask', 'Gateway']

        # Basic table formatting
        print(f"\n{header}\n" + "=" * len(header))
        print(f"{columns[0]:<18} {columns[1]:<18} {columns[2]}")
        print(f"{'-'*17:<18} {'-'*17:<18} {'-'*17}")

        for route in client.switchboard:
            comm = route['comm']
            # This logic mimics the original Ruby script's check for session type
            if hasattr(comm, 'sid'):
                gw = f"Session {comm.sid}"
            else:
                gw = comm.name.split('::')[-1]
            print(f"{route['subnet']:<18} {route['netmask']:<18} {gw}")
        print()
    else:
        print_status("No routes have been added yet")

def check_ip(ip_str):
    """Validates if a string is a valid IPv4 address."""
    if not ip_str or not ip_str.strip():
        return False
    try:
        ipaddress.IPv4Address(ip_str.strip())
        return True
    except ipaddress.AddressValueError:
        return False

def add_route(client, opts):
    """Adds a route to the framework instance."""
    subnet = opts.get('subnet')
    netmask = opts.get('netmask', "255.255.255.0")
    return client.switchboard.add_route(subnet, netmask, client.session)

def delete_route(client, opts):
    """Removes a route from the framework instance."""
    subnet = opts.get('subnet')
    netmask = opts.get('netmask', "255.255.255.0")
    return client.switchboard.remove_route(subnet, netmask, client.session)

def main():
    parser = argparse.ArgumentParser(
        description="Meterpreter script for setting up routes from within a session.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""\
Examples:
  run autoroute.py -s 10.1.1.0 -n 255.255.255.0  # Add a route
  run autoroute.py -s 10.10.10.1                 # Netmask defaults to 255.255.255.0
  run autoroute.py -s 10.10.10.1/24              # CIDR notation is also okay
  run autoroute.py -p                            # Print active routing table
  run autoroute.py -d -s 10.10.10.1              # Deletes the specified route
  run autoroute.py -D                            # Deletes all routes

Deprecation warning: This script has been replaced by the post/multi/manage/autoroute module.
"""
    )
    parser.add_argument("-s", "--subnet", help="Subnet (IPv4, e.g., 10.10.10.0 or 10.10.10.0/24)")
    parser.add_argument("-n", "--netmask", default="255.255.255.0", help="Netmask (e.g., 255.255.255.0 or 24)")
    parser.add_argument("-p", "--print-routes", action="store_true", help="Print active routing table and exit.")
    parser.add_argument("-d", "--delete", action="store_true", help="Delete the named route instead of adding it.")
    parser.add_argument("-D", "--delete-all", action="store_true", help="Delete all routes and. exit")

    args = parser.parse_args()

    if args.print_routes:
        print_routes(client)
        return

    if args.delete_all:
        delete_all_routes(client)
        return

    subnet_str = args.subnet
    netmask_str = args.netmask

    # Handle CIDR notation for subnet
    if subnet_str and '/' in subnet_str:
        try:
            network = ipaddress.ip_network(subnet_str, strict=False)
            subnet_str = str(network.network_address)
            netmask_str = str(network.netmask)
        except ValueError:
            print_error("Invalid CIDR notation for subnet.")
            return

    # Handle CIDR notation for netmask
    if netmask_str and netmask_str.isdigit() and 0 <= int(netmask_str) <= 32:
        try:
            prefix = int(netmask_str)
            netmask_str = str(ipaddress.IPv4Address(int('1'*prefix + '0'*(32-prefix), 2)))
        except ValueError:
             print_error("Invalid CIDR value for netmask.")
             return

    # --- Validation ---
    if not subnet_str:
        print_error("Missing -s (subnet) option.")
        parser.print_help()
        return

    if not check_ip(subnet_str):
        print_error("Subnet invalid (must be a valid IPv4 address).")
        return

    if not check_ip(netmask_str):
        print_error("Netmask invalid (must be a valid IPv4 address).")
        return

    # --- Execution ---
    if args.delete:
        print_status(f"Deleting route to {subnet_str}/{netmask_str}...")
        route_result = delete_route(client, {'subnet': subnet_str, 'netmask': netmask_str})
    else:
        print_status(f"Adding a route to {subnet_str}/{netmask_str}...")
        route_result = add_route(client, {'subnet': subnet_str, 'netmask': netmask_str})

    if route_result:
        action = "Deleted" if args.delete else "Added"
        print_good(f"{action} route to {subnet_str}/{netmask_str} via {client.sock.peerhost}")
    else:
        action = "delete" if args.delete else "add"
        print_error(f"Could not {action} route. It may already exist or not be present.")

    if len(client.switchboard) > 0:
        print_status("Use the -p option to list all active routes")

if __name__ == "__main__":
    # This check is for when the script is run directly.
    # In a real scenario, a 'client' object would be provided by the framework.
    if 'client' not in globals():
        print_status("This script is intended to run in a Meterpreter session.")
        print_status("Initializing a mock client for testing purposes.")
        client = MockClient()
        # Example of how to simulate command-line arguments for testing:
        # import sys
        # sys.argv = ['autoroute.py', '-s', '192.168.1.0/24']
        main()
    else:
        main()