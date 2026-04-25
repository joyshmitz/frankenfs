import os
print("PATH:", os.environ.get("PATH"))
print("rch available:", any(os.access(os.path.join(p, "rch"), os.X_OK) for p in os.environ.get("PATH", "").split(":")))
