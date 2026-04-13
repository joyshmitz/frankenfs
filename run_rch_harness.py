import subprocess
with open("rch_harness.txt", "w") as f:
    result = subprocess.run("rch exec -- cargo test -p ffs-harness", shell=True, capture_output=True, text=True)
    f.write(result.stdout)
    f.write(result.stderr)
