"""Backwards-compatible entry point. Prefer: python -m agent_safety run configs/<name>.yaml"""
import sys

from agent_safety.__main__ import main

if __name__ == "__main__":
    sys.exit(main(["run", *(sys.argv[1:] or ["configs/smoke.yaml"])]))
