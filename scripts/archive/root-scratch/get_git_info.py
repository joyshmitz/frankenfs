import subprocess

def run_cmd(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout + result.stderr

with open("git_log_output.txt", "w") as f:
    f.write(run_cmd("git log -n 20 --oneline --stat"))
    f.write("\n\n")
    f.write(run_cmd("git diff HEAD~5 HEAD"))
