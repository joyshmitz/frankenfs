import subprocess
with open("git_show.txt", "w") as f:
    result = subprocess.run("git show 03465f8", shell=True, capture_output=True, text=True)
    f.write(result.stdout)
