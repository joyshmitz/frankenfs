import subprocess

with open("/data/projects/frankenfs/clippy_agent.out", "w") as f:
    subprocess.run(["cargo", "clippy", "--workspace", "--all-targets", "--message-format=short"], stdout=f, stderr=subprocess.STDOUT)

with open("/data/projects/frankenfs/test_agent.out", "w") as f:
    subprocess.run(["cargo", "test", "--workspace"], stdout=f, stderr=subprocess.STDOUT)
