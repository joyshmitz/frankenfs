import subprocess
import os

try:
    with open('/data/projects/frankenfs/test_out.rs', 'w') as f:
        res = subprocess.run(
            ['/home/ubuntu/.cargo/bin/cargo', 'test', '--workspace'],
            stdout=f, stderr=subprocess.STDOUT,
            cwd='/data/projects/frankenfs',
            env=os.environ.copy()
        )
        f.write(f"\nExit code: {res.returncode}\n")
except Exception as e:
    with open('/data/projects/frankenfs/test_out.rs', 'w') as f:
        f.write(str(e))
