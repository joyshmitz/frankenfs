import subprocess
with open("check2.out", "w") as f:
    subprocess.run(["cargo", "check", "--workspace", "--all-targets"], stdout=f, stderr=subprocess.STDOUT)
