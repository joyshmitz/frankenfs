import subprocess
with open("rch_check_log.txt", "w") as f:
    result = subprocess.run("rch exec -- cargo check --workspace --all-targets", shell=True, capture_output=True, text=True)
    f.write(result.stdout)
    f.write(result.stderr)
