import subprocess
with open("rch_test_xattr.txt", "w") as f:
    result = subprocess.run("rch exec -- cargo test -p ffs-xattr", shell=True, capture_output=True, text=True)
    f.write(result.stdout)
    f.write(result.stderr)
