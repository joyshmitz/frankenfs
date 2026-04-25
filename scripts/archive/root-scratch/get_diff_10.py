import os
with open("git_diff_10.txt", "w") as f:
    f.write(os.popen("git diff HEAD~10 HEAD").read())
