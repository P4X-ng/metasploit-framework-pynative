#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module Mixins Utility
Port of tools/modules/module_mixins.rb to Python

This module requires Metasploit: https://metasploit.com/download
Current source: https://github.com/rapid7/metasploit-framework

This script lists all modules with their mixins. Handy for finding different "kinds" of modules.
"""

import sys
import inspect


def do_want(klass):
    """
    Determine if a class should be included in the mixin list
    
    Args:
        klass: Class to check
        
    Returns:
        bool: True if class should be included
    """
    # Check if it's actually a module/class
    if not inspect.isclass(klass) and not inspect.ismodule(klass):
        return False
    
    # Exclude certain built-in modules
    # In Python, we'd exclude things like builtins, abc, etc.
    excluded_names = ['builtins', '__builtin__', 'abc']
    module_name = getattr(klass, '__name__', '')
    
    if any(excluded in module_name for excluded in excluded_names):
        return False
    
    # Exclude subscriber-related classes (Python equivalent)
    if 'Subscriber' in module_name:
        return False
    
    return True


def main():
    """Main function"""
    # NOTE: This would need actual framework initialization
    # framework = initialize_framework({'DisableDatabase': True})
    # all_modules = framework.exploits
    
    # If you give an argument (any argument will do), you really want a sorted
    # list of mixins, regardless of the module they're in.
    if len(sys.argv) > 1:
        mod_hash = {}
        longest_name = 0
        
        # NOTE: The actual framework iteration would go here
        # Example pseudo-code for what the implementation would look like:
        # for name, mod in all_modules.items():
        #     module_instance = mod()
        #     # Get the MRO (Method Resolution Order) - Python's equivalent to Ruby's ancestors
        #     mixins = [m for m in inspect.getmro(module_instance.__class__) if do_want(m)]
        #     
        #     for m in mixins:
        #         mixin_name = m.__name__
        #         mod_hash[mixin_name] = mod_hash.get(mixin_name, 0) + 1
        #         longest_name = max(longest_name, len(mixin_name))
        
        # Sort by count (descending) and print
        for mixin_name, count in sorted(mod_hash.items(), key=lambda x: x[1], reverse=True):
            print(f"{mixin_name:<{longest_name}} | {count}")
    else:
        # Tables kind of suck for this.
        results = []
        longest_name = 0
        
        # NOTE: The actual framework iteration would go here
        # Example pseudo-code for what the implementation would look like:
        # for name, mod in all_modules.items():
        #     module_instance = mod()
        #     # Get the MRO (Method Resolution Order) - Python's equivalent to Ruby's ancestors
        #     mixins = [m for m in inspect.getmro(module_instance.__class__) if do_want(m)]
        #     
        #     # Sort mixins by name
        #     mixin_names = sorted([m.__name__ for m in mixins])
        #     mixin_str = ', '.join(mixin_names)
        #     
        #     fullname = getattr(module_instance, 'fullname', name)
        #     results.append([fullname, mixin_str])
        #     longest_name = max(longest_name, len(fullname))
        
        # name | module1, module2, etc.
        for fullname, mixin_str in results:
            print(f"{fullname:<{longest_name}} | {mixin_str}")


if __name__ == '__main__':
    main()
