"""Adversarial child processes for the real bounded execution boundary."""
import json
import os
import subprocess
import sys
import time

mode = sys.argv[1]
children = []
if mode in ("fork_hang", "escaped_hang", "background"):
    children.append(subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                     start_new_session=mode == "escaped_hang").pid)
if len(sys.argv) > 2:
    with open(sys.argv[2], "w") as f:
        json.dump([os.getpid()] + children, f)
if mode in ("hang", "fork_hang", "escaped_hang"):
    time.sleep(60)
elif mode == "cpu":
    while True:
        pass
elif mode == "memory":
    bytearray(1024 * 1024 * 1024)
elif mode == "output":
    os.write(1, b"x" * (1024 * 1024))
    os.write(2, b"y" * 65536)
elif mode == "error":
    print("partial output must be discarded")
    print("parser failed", file=sys.stderr)
    sys.exit(1)
elif mode == "policy_load_error":
    print("Invalid policy: policy.35. A binary policy must be specified.")
    sys.exit(1)
elif mode == "malformed":
    print("progress is not JSON")
elif mode == "invalid_encoding":
    os.write(1, b"\xff")
else:
    print(json.dumps({"domains": [] if mode == "empty" else ["rhcd_t", "postgresql_t", "rhcd_t"],
                      "evaluator_version": "SETools fixture"}))
