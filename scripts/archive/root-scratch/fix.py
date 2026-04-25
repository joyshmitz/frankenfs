import sys
import re

def process_file(path):
    with open(path, 'r') as f:
        content = f.read()

    # 1. Remove RequestScope from read_dir, read_inode_attr, read, write, lookup, getattr, readdir, readlink
    # Match `.function(arg1, &RequestScope::empty(),` or `.function(arg1, &mut RequestScope::empty(),`
    # Also handle newlines between arguments.
    # We can use a simpler approach: replace `, &RequestScope::empty()` with empty string if it's the second arg.
    # Actually, let's use regex with DOTALL or just simple string replacements.
    
    # We can just match `.func(\n    cx,\n    &RequestScope::empty(),` etc.
    # Let's use re.sub with robust patterns.
    
    # Remove:
    content = re.sub(
        r'\b(read_dir|read_inode_attr|read|write|lookup|getattr|readdir|readlink)\s*\(\s*([^,]+?)\s*,\s*&(?:mut\s*)?RequestScope::empty\(\)\s*(,|\))',
        r'\1(\2\3',
        content
    )
    
    # Sometimes it is called with `cx` instead of `&cx`. `([^,]+?)` matches the first argument.

    # 2. Add &RequestScope::empty() as second argument for resolve_extent, read_file_data, read_file, resolve_path
    # But only if it's not already there. First arg is usually `&cx` or `cx`.
    # Let's match `\b(resolve_extent|read_file_data|read_file|resolve_path)\s*\(\s*(&?cx)\s*,` 
    # where the next thing is not `&RequestScope` or `scope`.
    content = re.sub(
        r'\b(resolve_extent|read_file_data|read_file|resolve_path)\s*\(\s*(&?cx)\s*,\s*(?!&?RequestScope|scope)([^)]+)\)',
        r'\1(\2, &RequestScope::empty(), \3)',
        content
    )
    
    # 3. Add &mut RequestScope::empty() as second argument for fsync, fsyncdir, flush, setxattr, removexattr, link, symlink, setattr, mkdir
    content = re.sub(
        r'\b(fsync|fsyncdir|flush|setxattr|removexattr|link|symlink|setattr|mkdir)\s*\(\s*(&?cx)\s*,\s*(?!&?mut RequestScope|scope|&?RequestScope)([^)]+)\)',
        r'\1(\2, &mut RequestScope::empty(), \3)',
        content
    )
    
    # Additional cases where parameters are spread across multiple lines:
    # e.g., 
    # .getattr(
    #     &cx,
    #     &mut RequestScope::empty(),
    #     InodeNumber(1)
    # )
    
    content = re.sub(
        r'\b(read_dir|read_inode_attr|read|write|lookup|getattr|readdir|readlink)\s*\(\s*(&?cx)\s*,\s*&(?:mut\s*)?RequestScope::empty\(\)\s*,',
        r'\1(\2,',
        content,
        flags=re.MULTILINE
    )
    
    content = re.sub(
        r'\b(resolve_extent|read_file_data|read_file|resolve_path)\s*\(\s*(&?cx)\s*,\s*(?!&?RequestScope|scope)',
        r'\1(\2, &RequestScope::empty(), ',
        content,
        flags=re.MULTILINE
    )
    
    content = re.sub(
        r'\b(fsync|fsyncdir|flush|setxattr|removexattr|link|symlink|setattr|mkdir)\s*\(\s*(&?cx)\s*,\s*(?!&?mut RequestScope|scope|&?RequestScope)',
        r'\1(\2, &mut RequestScope::empty(), ',
        content,
        flags=re.MULTILINE
    )
    
    with open(path, 'w') as f:
        f.write(content)

process_file('crates/ffs-core/src/lib.rs')
process_file('crates/ffs-core/src/vfs.rs')
process_file('crates/ffs-fuse/src/lib.rs')
print("Done")
