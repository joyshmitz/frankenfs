import os
if os.path.exists("test_ondisk.txt"):
    with open("test_ondisk.txt") as f:
        content = f.read()
        if "FAILED" in content:
            print("Tests FAILED")
            print(content[-2000:])
        elif "ok" in content:
            print("Tests PASSED")
            print(content[-500:])
        else:
            print("Still running or empty")
