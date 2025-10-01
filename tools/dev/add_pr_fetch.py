#!/usr/bin/env python3
"""
Add pull request fetch configuration to git config
"""

import os
import subprocess
import sys


def main():
    # Get the top-level git directory
    try:
        toplevel = subprocess.check_output(['git', 'rev-parse', '--show-toplevel'], 
                                          encoding='utf-8').strip()
    except subprocess.CalledProcessError:
        print("Error: Not in a git repository", file=sys.stderr)
        sys.exit(1)
    
    infile = os.path.join(toplevel, '.git', 'config')
    outfile = infile
    
    print(f"Rewriting {infile}", file=sys.stderr)
    
    try:
        with open(infile, 'r') as f:
            data = f.read()
    except IOError as e:
        print(f"Error reading {infile}: {e}", file=sys.stderr)
        sys.exit(1)
    
    newdata = ""
    new_pr_line = False
    
    for line in data.split('\n'):
        newdata += line + '\n'
        
        # Check if this is a fetch line for a remote
        if 'fetch' in line and 'remotes/' in line:
            parts = line.split('remotes/')
            if len(parts) >= 2:
                remote_part = parts[1].split('/')[0]
                # Extract whitespace
                ws = line[:len(line) - len(line.lstrip())]
                
                pr_line = f"fetch = +refs/pull/*/head:refs/remotes/{remote_part}/pr/*"
                
                # Skip if this line is already a pr fetch line
                if line.strip() == pr_line.strip():
                    continue
                
                # Skip if the pr_line already exists in data
                if pr_line in data:
                    print(f"Skipping {remote_part}, already present", file=sys.stderr)
                    continue
                else:
                    new_pr_line = True
                    print(f"Adding pull request fetch for {remote_part}", file=sys.stderr)
                    newdata += f"{ws}{pr_line}\n"
    
    if new_pr_line:
        try:
            with open(outfile, 'w') as f:
                f.write(newdata)
            print(f"Wrote {outfile}", file=sys.stderr)
        except IOError as e:
            print(f"Error writing {outfile}: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print(f"No changes to {outfile}", file=sys.stderr)


if __name__ == "__main__":
    main()
