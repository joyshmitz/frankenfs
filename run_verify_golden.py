import subprocess
with open("verify_golden_out.txt", "w") as f:
    result = subprocess.run("./scripts/verify_golden.sh", shell=True, capture_output=True, text=True)
    f.write(result.stdout)
    f.write(result.stderr)
