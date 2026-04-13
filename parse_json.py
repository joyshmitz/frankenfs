import json
import os

if os.path.exists("clippy.json"):
    with open("clippy.json", "r") as f:
        with open("parsed.txt", "w") as out:
            for line in f:
                try:
                    obj = json.loads(line)
                    if "message" in obj and obj["message"]:
                        rendered = obj["message"].get("rendered")
                        if rendered:
                            out.write(rendered + "\n")
                except:
                    pass
