import re
import sys

def modify_function(content, func_name, add_scope=True):
    # Find the function definition
    pattern = r'(fn\s+' + func_name + r'\s*\(\s*&self\s*,\s*cx:\s*&Cx\s*,)'
    match = re.search(pattern, content)
    if not match:
        print(f"Could not find {func_name}")
        return content

    if add_scope:
        # Check if scope is already there
        scope_pattern = r'(fn\s+' + func_name + r'\s*\(\s*&self\s*,\s*cx:\s*&Cx\s*,\s*scope:\s*&mut\s*RequestScope)'
        if not re.search(scope_pattern, content):
            content = content[:match.end()] + '\n        scope: &mut RequestScope,' + content[match.end():]
            print(f"Added scope to {func_name}")
    
    return content

def add_tx_dev(content, func_name):
    # Find the function body start
    # Let's find let block_dev = ... inside the function
    # A bit tricky. We can extract the function body first.
    start_idx = content.find(f"fn {func_name}(")
    if start_idx == -1:
        return content
    
    # We will just do a regex replace inside the function body
    pass

with open("crates/ffs-core/src/lib.rs", "r") as f:
    content = f.read()

funcs_to_add_scope = [
    "ext4_mkdir",
    "ext4_link",
    "ext4_rename",
    "ext4_unlink_impl",
    "ext4_fallocate",
]

for func in funcs_to_add_scope:
    content = modify_function(content, func, True)

with open("crates/ffs-core/src/lib.rs", "w") as f:
    f.write(content)
