import os
with open("critical_bugs.txt", "w") as f:
    result = os.popen('grep -n -A 5 "CRITICAL" rust-bug-scan.txt').read()
    f.write(result)
