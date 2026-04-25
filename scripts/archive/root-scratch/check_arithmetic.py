import os
import re

def check_arithmetic():
    pattern = re.compile(r'\b(as usize|as u32|as u64|as i32|as i64)\b')
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
                if pattern.search(line):
                    print(f"{path}:{i+1}: {line.strip()}")

check_arithmetic()
