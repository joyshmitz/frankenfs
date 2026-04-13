import subprocess
with open("rch_test_xattr_2.txt", "w") as f:
    result = subprocess.run(["rch", "exec", "--", "cargo", "test", "-p", "ffs-xattr"], capture_output=True, text=True)
    f.write(result.stdout)
    f.write(result.stderr)
