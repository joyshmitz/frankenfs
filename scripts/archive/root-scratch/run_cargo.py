import subprocess
import time

try:
    with open('test_out.txt', 'w') as f:
        res = subprocess.run(['cargo', 'test', '--workspace'], stdout=f, stderr=subprocess.STDOUT)
        f.write(f"\nExit code: {res.returncode}\n")
except Exception as e:
    with open('test_out.txt', 'w') as f:
        f.write(str(e))
