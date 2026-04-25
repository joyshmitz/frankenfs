import os
with open("git_log_output.txt", "w") as f:
    f.write(os.popen("git log -n 10 --oneline").read())
    f.write("\n\n=== DIFF ===\n\n")
    f.write(os.popen("git diff HEAD~5 HEAD").read())
