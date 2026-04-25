import os
import re

def fix_file(filepath):
    if not os.path.exists(filepath):
        return
    with open(filepath, 'r') as f:
        content = f.read()

    # fallocate with libc:: constants
    content = re.sub(
        r'(\.fallocate\([^,]+,\s*[^,]+,\s*[^,]+,\s*[^,]+,\s*)(libc::[A-Z_]+(?:\s*\|\s*libc::[A-Z_]+)*)(\s*\))',
        r'\1(\2).try_into().unwrap()\3',
        content
    )

    # read with u32::try_from -> needs u64::from
    content = re.sub(
        r'(\.read\([^,]+,\s*[^,]+,\s*[^,]+,\s*)(u32::try_from\([^)]+\)\.unwrap\(\))',
        r'\1u64::from(\2)',
        content
    )
    
    # read with read_len -> needs u64::from(read_len)
    content = re.sub(
        r'(\.read\([^,]+,\s*[^,]+,\s*[^,]+,\s*)(read_len)(\s*\))',
        r'\1u64::from(\2)\3',
        content
    )

    with open(filepath, 'w') as f:
        f.write(content)

fix_file('crates/ffs-core/src/lib.rs')
print("Fixes applied.")
