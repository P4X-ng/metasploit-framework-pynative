# Quick Start Guide for Python Translations

This guide provides quick examples for using the translated Python files.

## 🚀 Quick Examples

### 1. Ruby Base64 Encoder

Encode Ruby payloads with Base64:

```bash
# Basic usage
python3 modules/encoders/ruby/ruby_base64_encoder.py 'puts "hello"'

# With Python import
python3 -c "
from modules.encoders.ruby.ruby_base64_encoder import encode
print(encode('puts \"test\"'))
"
```

### 2. SMB Utils

```python
# Import the utilities
from lib.rex.proto.smb.utils import Utils

# NetBIOS encoding
encoded = Utils.nbname_encode('WORKGROUP')
print(encoded)  # FHEPFCELEHFCEPFFFACACACACACACACA

# Decode it back
decoded = Utils.nbname_decode(encoded)
print(decoded)  # WORKGROUP (with padding)

# Time conversion
import time
unix_time = int(time.time())
hi, lo = Utils.time_unix_to_smb(unix_time)
back = Utils.time_smb_to_unix(hi, lo)
print(f"Round trip: {unix_time} -> {back}")

# File mode conversion
access = Utils.open_mode_to_access('rw')
mode = Utils.open_mode_to_mode('cto')
```

### 3. Module Rank Tool

```bash
# Show help
python3 tools/modules/module_rank.py --help

# Filter by rank range
python3 tools/modules/module_rank.py -m Good -M Excellent

# Sort by rank
python3 tools/modules/module_rank.py -s

# Filter by module type
python3 tools/modules/module_rank.py -f Exploit

# Combine filters
python3 tools/modules/module_rank.py -m Normal -s -f Auxiliary
```

### 4. Module Count

```bash
# Get module counts as CSV
python3 tools/modules/module_count.py
# Output: exploit,auxiliary,post,payload,encoder,nop
#         0,0,0,0,0,0
```

### 5. Object Dump to C Converter

```bash
# Convert objdump output to C arrays
objdump -dM suffix myfile.o | python3 external/source/unixasm/objdumptoc.py

# Or with a file
objdump -dM suffix myfile.o > dump.txt
cat dump.txt | python3 external/source/unixasm/objdumptoc.py
```

### 6. AIX PowerPC Syscall Generator

```bash
# Generate AIX syscall definitions
python3 external/source/unixasm/aix-power.py template_file.erb
```

### 7. Get Local Subnets (Meterpreter)

```bash
# Show help
python3 scripts/meterpreter/get_local_subnets.py -h

# Note: Requires active meterpreter client connection
# This is a framework script and needs integration
```

## 📝 Testing Your Translations

### Syntax Check
```bash
# Check all Python files
python3 -m py_compile path/to/file.py

# Check multiple files
find . -name "*.py" -path "*/tools/*" -exec python3 -m py_compile {} \;
```

### Import Test
```python
# Test imports work
import sys
sys.path.insert(0, '/path/to/metasploit-framework-pynative')

from lib.rex.proto.smb.utils import Utils
from modules.encoders.ruby.ruby_base64_encoder import encode

# Test functionality
assert Utils.nbname_encode('TEST')
assert encode('puts "test"')
print("✓ All imports working!")
```

## 🔧 Common Patterns

### Ruby → Python Equivalents

| Ruby | Python |
|------|--------|
| `attr_accessor :var` | `@property` decorator |
| `#{variable}` | f-string: `f"{variable}"` |
| `:symbol` | String: `"symbol"` |
| `var.each { }` | `for item in var:` |
| `[1].pack('n')` | `struct.pack('>H', 1)` |
| `str.unpack('nn')` | `struct.unpack('>HH', str)` |
| `File.new(path)` | `open(path)` |
| `puts` | `print()` |
| `nil` | `None` |
| `true/false` | `True/False` |

### Error Handling

```python
# Ruby: raise SomeError
# Python: raise SomeError()

# Ruby: rescue Exception => e
# Python: except Exception as e

# Ruby: ensure
# Python: finally
```

## 🐛 Troubleshooting

### Module Import Errors

If you get import errors:
```python
import sys
sys.path.insert(0, '/home/runner/work/metasploit-framework-pynative/metasploit-framework-pynative')
```

### Name Conflicts

Some files were renamed to avoid conflicts with Python stdlib:
- `base64.rb` → `ruby_base64_encoder.py` (avoided conflict with `base64` module)

### Framework Integration

Many scripts include placeholder comments like:
```python
# NOTE: This would need actual framework initialization
```

These indicate where Metasploit framework integration is needed.

## 📚 Further Reading

- See `PYTHON_TRANSLATIONS.md` for detailed translation notes
- Check individual file docstrings for usage information
- Ruby originals are preserved alongside Python versions for reference
