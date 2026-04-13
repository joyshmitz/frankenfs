import subprocess
with open("git_show_2.txt", "w") as f:
    result = subprocess.run("git show 2b990a4", shell=True, capture_output=True, text=True)
    f.write(result.stdout)
