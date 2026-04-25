import re
import sys

def main():
    if not __import__('os').path.exists('rust-bug-scan.txt'):
        return
    with open('rust-bug-scan.txt', 'r') as f:
        lines = f.readlines()

    printing = False
    count = 0
    for line in lines:
        if 'Division by variable (check non-zero)' in line:
            printing = True
        elif printing and line.strip().startswith('•'):
            printing = False
        if printing:
            print(line, end='')
            count += 1
            if count > 50:
                break

if __name__ == '__main__':
    main()
