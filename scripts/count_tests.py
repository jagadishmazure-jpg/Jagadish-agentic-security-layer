#!/usr/bin/env python3
"""Print the real test total (CI consumes this; no quiet flags)."""
import subprocess
import sys

out = subprocess.run(
    [sys.executable, "-m", "pytest", "tests/", "--collect-only", "-q"],
    capture_output=True, text=True, cwd=".",
)
last = [l for l in out.stdout.splitlines() if "test" in l][-1]
print(last)
