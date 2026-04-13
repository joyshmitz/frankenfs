import subprocess

with open("test_ondisk2.txt", "w") as f:
    result = subprocess.run(
        "cargo test -p ffs-ondisk",
        shell=True,
        capture_output=True,
        text=True
    )
    f.write(result.stdout)
    f.write(result.stderr)
