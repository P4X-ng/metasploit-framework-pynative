# Ruby to Python Translation Summary

This document summarizes the Ruby files that have been translated to Python in this repository.

## Translated Files

### 1. lib/rex/proto/smb/utils.rb → lib/rex/proto/smb/utils.py
**Purpose:** SMB protocol utility functions

**Key Features:**
- Access mode conversion for SMB file operations
- File mode mask generation
- SMB time ↔ Unix timestamp conversion
- NetBIOS name encoding/decoding

**Usage Example:**
```python
from lib.rex.proto.smb.utils import Utils

# NetBIOS encoding
encoded = Utils.nbname_encode('WORKGROUP')
print(encoded)  # FHEPFCELEHFCEPFFFACACACACACACACA

# Time conversion
import time
unix_time = int(time.time())
hi, lo = Utils.time_unix_to_smb(unix_time)
back = Utils.time_smb_to_unix(hi, lo)
```

### 2. tools/modules/module_rank.rb → tools/modules/module_rank.py
**Purpose:** Display module rank information for Metasploit modules

**Key Features:**
- Filter modules by rank (Manual, Low, Average, Normal, Good, Great, Excellent)
- Sort by rank or module type
- Filter by module type (exploit, payload, post, nop, encoder, auxiliary)

**Usage:**
```bash
python3 tools/modules/module_rank.py --help
python3 tools/modules/module_rank.py -m Normal -M Excellent -s
```

### 3. tools/modules/module_count.rb → tools/modules/module_count.py
**Purpose:** Count modules by type and output as CSV

**Key Features:**
- Count exploit, auxiliary, post, payload, encoder, and nop modules
- CSV output format

### 4. tools/modules/module_mixins.rb → tools/modules/module_mixins.py
**Purpose:** List all modules with their mixins (using Python's MRO)

**Key Features:**
- Identify module inheritance patterns
- Sort and count mixin usage across modules

### 5. tools/modules/solo.rb → tools/modules/solo.py
**Purpose:** Run a module outside of Metasploit Framework

**Key Features:**
- Message logging with different levels (error, warning, good, info)
- Report processing
- Module execution outside framework context

### 6. modules/encoders/ruby/base64.rb → modules/encoders/ruby/ruby_base64_encoder.py
**Purpose:** Ruby Base64 encoder for payloads

**Key Features:**
- Base64 encoding with Ruby eval wrapper
- Badchar checking
- Generates: `eval(%(base64_string).unpack(%(m0)).first)`

**Usage:**
```bash
python3 modules/encoders/ruby/ruby_base64_encoder.py 'puts "hello"'
# Output: eval(%(cHV0cyAiaGVsbG8i).unpack(%(m0)).first)
```

### 7. scripts/meterpreter/get_local_subnets.rb → scripts/meterpreter/get_local_subnets.py
**Purpose:** Meterpreter script to display local subnets

**Key Features:**
- List local subnets based on host routes
- Filter out multicast and loopback interfaces

### 8. external/source/unixasm/objdumptoc.rb → external/source/unixasm/objdumptoc.py
**Purpose:** Convert objdump output to C array format

**Key Features:**
- Parse objdump assembly output
- Generate C-style byte arrays
- Include assembly comments in output

**Usage:**
```bash
objdump -dM suffix <file> | python3 external/source/unixasm/objdumptoc.py
```

### 9. external/source/unixasm/aix-power.rb → external/source/unixasm/aix-power.py
**Purpose:** Generate AIX PowerPC assembly with system call numbers

**Key Features:**
- Support for multiple AIX versions (5.3.7-6.1.4)
- Generate system call sequences for socket operations
- Template-based code generation

### 10. lib/msf/core/modules/external.rb → lib/msf/core/modules/external.py
**Purpose:** Support for loading external Metasploit modules

**Key Features:**
- Module path management
- Framework integration
- Lazy metadata loading
- Module execution with callbacks

### 11. scripts/meterpreter/winenum.rb → scripts/meterpreter/winenum.py
**Purpose:** Comprehensive Windows local enumeration script

**Key Features:**
- Gathers system, network, and user information
- Dumps password hashes
- Lists security tokens
- Detects virtual machine environments
- Optional process migration, registry dumping, and event log clearing

**Usage:**
```bash
python3 scripts/meterpreter/winenum.py --help
```


### 12. lib/msf/util/helper.rb → lib/msf/util/helper.py
**Purpose:** Cross-platform utility functions

**Key Features:**
- `which()` function to find executables in PATH
- Cross-platform compatibility (Windows/Unix)
- Handles PATHEXT on Windows

**Usage:**
```python
from lib.msf.util.helper import Helper

# Find python3 executable
python_path = Helper.which('python3')
print(python_path)  # /usr/bin/python3
```

### 13. lib/msf/util/ruby_deserialization.rb → lib/msf/util/ruby_deserialization.py
**Purpose:** Ruby deserialization exploit payloads

**Key Features:**
- Generate payloads for Ruby deserialization vulnerabilities
- Supports `net_writeadapter` payload (universal gadget for Ruby 2.x-3.x)
- Marshal format payload generation

**Usage:**
```python
from lib.msf.util.ruby_deserialization import RubyDeserialization

# Generate payload
payload = RubyDeserialization.payload('net_writeadapter', 'whoami')
# Returns bytes of serialized Ruby Marshal payload
```

### 14. lib/msf/util/python_deserialization.rb → lib/msf/util/python_deserialization.py
**Purpose:** Python deserialization exploit payloads

**Key Features:**
- Generate payloads for Python deserialization vulnerabilities (pickle)
- Supports `py3_exec` (direct execution) and `py3_exec_threaded` (threaded execution)
- Automatic escaping of special characters

**Usage:**
```python
from lib.msf.util.python_deserialization import PythonDeserialization

# Generate payload for Python 3.x
payload = PythonDeserialization.payload('py3_exec', 'import os; os.system("id")')
# Returns pickle protocol string
```

### 15. lib/msf/util/java_deserialization.rb → lib/msf/util/java_deserialization.py
**Purpose:** Java deserialization exploit payloads (ysoserial)

**Key Features:**
- Load and generate ysoserial payloads
- Support for multiple payload types (CommonsCollections1-7, BeanShell1, etc.)
- Dynamic command injection with automatic length correction
- Evasion through randomization of ysoserial signatures

**Usage:**
```python
from lib.msf.util.java_deserialization import JavaDeserialization

# List available payloads
payloads = JavaDeserialization.ysoserial_payload_names()

# Generate payload
payload = JavaDeserialization.ysoserial_payload('CommonsCollections1', 'calc.exe')
# Returns bytes of serialized Java object
```

### 16. tools/dev/set_binary_encoding.rb → tools/dev/set_binary_encoding.py
**Purpose:** Add UTF-8 encoding declarations to Python files

**Key Features:**
- Automatically adds `# -*- coding: utf-8 -*-` to Python files
- Handles files with or without shebang lines
- Skips files that already have encoding declarations

**Usage:**
```bash
python3 tools/dev/set_binary_encoding.py myfile.py
```

### 17. scripts/meterpreter/migrate.rb → scripts/meterpreter/migrate.py
**Purpose:** Meterpreter process migration script

**Key Features:**
- Migrate to specific PID or process name
- Option to spawn new process (notepad.exe) for migration
- Kill original process after migration
- Windows platform support

**Usage:**
```bash
python3 scripts/meterpreter/migrate.py -p 1234
python3 scripts/meterpreter/migrate.py -n explorer.exe
python3 scripts/meterpreter/migrate.py -f -k
```

### 18. scripts/meterpreter/uploadexec.rb → scripts/meterpreter/uploadexec.py
**Purpose:** Upload and execute files on target system

**Key Features:**
- Upload files to target (default: %TEMP%)
- Execute with optional arguments
- Verbose mode to capture output
- Optional file removal after execution
- Optional session termination

**Usage:**
```bash
python3 scripts/meterpreter/uploadexec.py -e payload.exe
python3 scripts/meterpreter/uploadexec.py -e script.bat -p C:\\temp -v -r
```

### 19. scripts/shell/migrate.rb → scripts/shell/migrate.py
**Purpose:** Display message that migration is not supported for CommandShell sessions

**Key Features:**
- Simple error message for command shell sessions

**Usage:**
```bash
python3 scripts/shell/migrate.py
# Output: [-] Error: command shell sessions do not support migration
```

### 20. scripts/meterpreter/get_application_list.rb → scripts/meterpreter/get_application_list.py
**Purpose:** List installed applications and their versions

**Key Features:**
- Enumerate installed applications from Windows registry
- Query both HKLM and HKCU Uninstall keys
- Multi-threaded registry queries for performance
- Formatted table output

**Usage:**
```bash
python3 scripts/meterpreter/get_application_list.py
```

### 21. scripts/meterpreter/file_collector.rb → scripts/meterpreter/file_collector.py
**Purpose:** Search and collect files matching specific patterns

**Key Features:**
- Search for files by pattern/wildcard
- Support for multiple search patterns (pipe-separated)
- Recursive directory search
- Save search results to file
- Download files from results list

**Usage:**
```bash
# Search for files
python3 scripts/meterpreter/file_collector.py -d C:\\Users -f "*.doc|*.pdf" -r -o results.txt

# Download files from list
python3 scripts/meterpreter/file_collector.py -i results.txt -l ./downloads

### Common Patterns

1. **Module Structure**: Ruby modules are translated to Python classes or module-level functions
2. **String Encoding**: Ruby's `pack`/`unpack` is replaced with Python's `struct` module
3. **Regular Expressions**: Ruby regex patterns work mostly as-is in Python with `re` module
4. **File I/O**: Ruby's `File.new` becomes Python's `open()` or `with open()` context manager
5. **Command Line Arguments**: Ruby's `Rex::Parser::Arguments` becomes Python's `argparse`

### Key Differences

- **Naming**: Some files renamed to avoid conflicts (e.g., base64.py → ruby_base64_encoder.py)
- **Framework Integration**: Python versions include placeholders for framework initialization as the full framework may not be implemented yet
- **String Interpolation**: Ruby's `#{var}` becomes Python's f-strings `{var}`
- **Symbols**: Ruby symbols (`:symbol`) become Python strings (`'symbol'`)
- **Class Variables**: Ruby's `@var` becomes Python's `self._var`

## Testing

All translated files have been verified for:
- ✅ Valid Python syntax (using `python3 -m py_compile`)
- ✅ Executable permissions set
- ✅ Basic functionality tests where applicable

## Future Work

These translations provide a foundation for a Python-native Metasploit implementation. Some files contain placeholders for framework integration that would need to be completed when the full Python framework is available.
