import os
if os.path.exists("rust-bug-scan.txt"):
    with open("rust-bug-scan.txt", "r") as f:
        content = f.read()
        with open("critical_warnings.txt", "w") as out:
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if 'CRITICAL' in line or 'Warning' in line:
                    start = max(0, i-2)
                    end = min(len(lines), i+5)
                    out.write('\n'.join(lines[start:end]) + '\n---\n')
