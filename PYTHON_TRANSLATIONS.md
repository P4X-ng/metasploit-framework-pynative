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

### 12. scripts/meterpreter/autoroute.rb → scripts/meterpreter/autoroute.py
**Purpose:** Manage network routes within a Meterpreter session.

**Key Features:**
- Add, delete, and list network routes.
- Supports CIDR notation for subnets and netmasks.
- Can delete all routes at once.
- Provides clear, formatted output of the routing table.

**Usage:**
```bash
python3 scripts/meterpreter/autoroute.py --help
```

### 13. scripts/meterpreter/duplicate.rb → scripts/meterpreter/duplicate.py
**Purpose:** Spawns a new Meterpreter session in a different process.

**Key Features:**
- Injects payload into an existing or newly spawned process.
- Can write and execute a standalone payload executable.
- Can automatically start a handler for the new session.

**Usage:**
```bash
python3 scripts/meterpreter/duplicate.py --help
```

### 14. scripts/meterpreter/enum_firefox.rb → scripts/meterpreter/enum_firefox.py
**Purpose:** Extracts sensitive data from Firefox profiles.

**Key Features:**
- Enumerates profiles for all users on the system.
- Downloads and parses SQLite databases for history, bookmarks, cookies, and downloads.
- Downloads credential files (`key3.db`, `signons.sqlite`, etc.).
- Can optionally kill running Firefox processes.

**Usage:**
```bash
python3 scripts/meterpreter/enum_firefox.py --help
```

### 15. scripts/meterpreter/get_application_list.rb → scripts/meterpreter/get_application_list.py
**Purpose:** Lists installed applications and their versions.

**Key Features:**
- Enumerates `Uninstall` keys in both HKLM and HKCU.
- Uses threading to speed up registry queries.
- Displays results in a formatted table.

**Usage:**
```bash
python3 scripts/meterpreter/get_application_list.py --help
```

### 16. scripts/meterpreter/get_filezilla_creds.rb → scripts/meterpreter/get_filezilla_creds.py
**Purpose:** Extracts saved server credentials from FileZilla.

**Key Features:**
- Finds FileZilla profiles for all users.
- Parses `sitemanager.xml` and `recentservers.xml`.
- Decodes Base64-encoded passwords.
- Handles different Windows versions and privilege levels.

**Usage:**
```bash
python3 scripts/meterpreter/get_filezilla_creds.py --help
```

### 17. scripts/meterpreter/keylogrecorder.rb → scripts/meterpreter/keylogrecorder.py
**Purpose:** Captures and records keystrokes from the target machine.

**Key Features:**
- Can migrate into `explorer.exe` or `winlogon.exe` for stealth and privilege.
- Periodically dumps and saves keystrokes to a log file.
- Translates virtual key codes into readable text.
- Can optionally lock the screen to capture login credentials.

**Usage:**
```bash
python3 scripts/meterpreter/keylogrecorder.py --help
```

## Translation Notes

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
