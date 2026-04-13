import os
if os.path.exists("test_out.txt"):
    with open("test_out.txt", "r") as f:
        lines = f.readlines()
        with open("test_tail.txt", "w") as out:
            out.writelines(lines[-40:])
