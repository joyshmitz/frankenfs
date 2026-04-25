import json
import os

if os.path.exists("clippy_out.json"):
    with open("clippy_out.json", "r") as f:
        with open("clippy.txt", "w") as out:
            for line in f:
                try:
                    obj = json.loads(line)
                    if "message" in obj and obj["message"]:
                        rendered = obj["message"].get("rendered")
                        if rendered:
                            out.write(rendered + "\n")
                except:
                    pass
