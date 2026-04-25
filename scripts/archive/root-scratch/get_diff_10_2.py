import subprocess
with open("git_diff_10.txt", "w") as f:
    result = subprocess.run("git log -n 10 -p", shell=True, capture_output=True, text=True)
    f.write(result.stdout)
    f.write(result.stderr)
