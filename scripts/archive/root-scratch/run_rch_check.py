import subprocess
with open("rch_check.txt", "w") as f:
    result = subprocess.run("rch check", shell=True, capture_output=True, text=True)
    f.write(result.stdout)
    f.write(result.stderr)
