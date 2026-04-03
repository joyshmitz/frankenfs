import os
import re

def find_unwraps():
    for root, _, files in os.walk('crates'):
        for file in files:
            if not file.endswith('.rs'):
                continue
            path = os.path.join(root, file)
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # split by #[cfg(test)]
            parts = content.split('#[cfg(test)]')
            prod_code = parts[0]
            
            lines = prod_code.split('\n')
            for i, line in enumerate(lines):
                if '.unwrap(' in line or '.expect(' in line:
                    print(f"{path}:{i+1}: {line.strip()}")

find_unwraps()
