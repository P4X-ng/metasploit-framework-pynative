#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module Rank Utility
Port of tools/modules/module_rank.rb to Python

This module requires Metasploit: https://metasploit.com/download
Current source: https://github.com/rapid7/metasploit-framework

This script lists each module with its rank
"""

import sys
import argparse

# Rank definitions
RANKS = {
    'Manual': 0,
    'Low': 100,
    'Average': 200,
    'Normal': 300,
    'Good': 400,
    'Great': 500,
    'Excellent': 600
}

FILTERS = ['all', 'exploit', 'payload', 'post', 'nop', 'encoder', 'auxiliary']


class Table:
    """Simple table formatter for output"""
    
    def __init__(self, header, indent, columns):
        self.header = header
        self.indent = indent
        self.columns = columns
        self.rows = []
    
    def add_row(self, row):
        """Add a row to the table"""
        self.rows.append(row)
    
    def sort_rows(self, column_index):
        """Sort rows by specified column"""
        self.rows.sort(key=lambda x: x[column_index])
    
    def reverse_rows(self):
        """Reverse the order of rows"""
        self.rows.reverse()
    
    def __str__(self):
        """Convert table to string representation"""
        if not self.rows:
            return f"{' ' * self.indent}{self.header}\n{' ' * self.indent}No data"
        
        # Calculate column widths
        col_widths = [len(col) for col in self.columns]
        for row in self.rows:
            for i, cell in enumerate(row):
                col_widths[i] = max(col_widths[i], len(str(cell)))
        
        # Build header
        result = f"{' ' * self.indent}{self.header}\n"
        result += ' ' * self.indent
        result += ' | '.join(col.ljust(col_widths[i]) for i, col in enumerate(self.columns))
        result += '\n'
        result += ' ' * self.indent + '-' * (sum(col_widths) + 3 * (len(self.columns) - 1))
        result += '\n'
        
        # Build rows
        for row in self.rows:
            result += ' ' * self.indent
            result += ' | '.join(str(cell).ljust(col_widths[i]) for i, cell in enumerate(row))
            result += '\n'
        
        return result


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Metasploit Script for Displaying Module Rank information.'
    )
    parser.add_argument(
        '-M', '--max-rank',
        choices=list(RANKS.keys()),
        default='Excellent',
        help='Set Maximum Rank (Default = Excellent)'
    )
    parser.add_argument(
        '-m', '--min-rank',
        choices=list(RANKS.keys()),
        default='Manual',
        help='Set Minimum Rank (Default = Manual)'
    )
    parser.add_argument(
        '-s', '--sort',
        action='store_true',
        help='Sort by Rank instead of Module Type'
    )
    parser.add_argument(
        '-r', '--reverse',
        action='store_true',
        help='Reverse Sort by Rank'
    )
    parser.add_argument(
        '-f', '--filter',
        choices=[f.capitalize() for f in FILTERS],
        default='All',
        help='Filter based on Module Type (Default = All)'
    )
    
    args = parser.parse_args()
    
    minrank = RANKS[args.min_rank]
    maxrank = RANKS[args.max_rank]
    
    if args.max_rank != 'Excellent':
        print(f"Maximum Rank: {args.max_rank}")
    if args.min_rank != 'Manual':
        print(f"Minimum Rank: {args.min_rank}")
    if args.sort:
        print("Sorting by Rank")
    if args.reverse:
        print("Reverse Sorting by Rank")
    if args.filter != 'All':
        print(f"Module Filter: {args.filter}")
    
    # Initialize framework options
    # NOTE: This would need actual framework initialization
    # framework_opts = {'DisableDatabase': True}
    # if args.filter.lower() != 'all':
    #     framework_opts['module_types'] = [args.filter.lower()]
    
    # Create table
    indent = 4
    tbl = Table(
        header='Module Ranks',
        indent=indent,
        columns=['Module', 'Rank']
    )
    
    # NOTE: The actual framework iteration would go here
    # This is a placeholder that would need to be implemented based on
    # how the Python version of Metasploit is structured
    
    # Example pseudo-code for what the implementation would look like:
    # framework = initialize_framework(framework_opts)
    # for name, mod in framework.modules.items():
    #     module_instance = mod()
    #     modrank = module_instance.rank
    #     if minrank <= modrank <= maxrank:
    #         tbl.add_row([module_instance.fullname, modrank])
    
    # Sort if requested
    if args.sort or args.reverse:
        tbl.sort_rows(1)  # Sort by rank column
        if args.reverse:
            tbl.reverse_rows()
    
    print(str(tbl))


if __name__ == '__main__':
    main()
