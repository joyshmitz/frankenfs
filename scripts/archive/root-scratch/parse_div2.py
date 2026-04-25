import sys
with open('rust-bug-scan.txt', 'r') as f:
    text = f.read()
idx = text.find('Division by variable (check non-zero)')
if idx != -1:
    end = text.find('\n•', idx)
    if end == -1: end = len(text)
    with open('div2.txt', 'w') as out:
        out.write(text[idx:end])
