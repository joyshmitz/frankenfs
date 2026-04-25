import subprocess
import os

def run_rch():
    cmd = ["rch", "exec", "--", "cargo", "test", "-p", "ffs-dir"]
    print(f"Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        with open("rch_output.txt", "w") as f:
            f.write("STDOUT:\n")
            f.write(result.stdout)
            f.write("\nSTDERR:\n")
            f.write(result.stderr)
            f.write(f"\nRETURN CODE: {result.returncode}\n")
    except Exception as e:
        with open("rch_output.txt", "w") as f:
            f.write(f"EXCEPTION: {str(e)}\n")

if __name__ == "__main__":
    run_rch()
