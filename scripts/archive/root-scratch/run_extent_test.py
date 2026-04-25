import subprocess

with open("rch_test_out.txt", "w") as f:
    result = subprocess.run(
        "cargo test -p ffs-extent",
        shell=True,
        capture_output=True,
        text=True
    )
    f.write(result.stdout)
    f.write(result.stderr)
