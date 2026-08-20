#!/usr/bin/env python3
"""Ensure the SkillLeakBench sandbox image is built with CRLF-safe context.

Windows checkouts with core.autocrlf may turn entrypoint.sh into CRLF,
which makes the container fail with 'bad interpreter: /bin/bash^M'.
This script normalizes the build context to LF before building.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CTX = ROOT / "cache/datasets_v3/raw/skillleakbench_pipeline/code/phase3_dynamic"
IMAGE = "skill-leakbench"

FIX_FILES = ["entrypoint.sh", "sandbox_monitor.sh", "exfil_collector.py", "mock_creds.py"]


def normalize() -> None:
    for name in FIX_FILES:
        p = CTX / name
        if not p.exists():
            continue
        data = p.read_bytes()
        if b"\r\n" in data:
            p.write_bytes(data.replace(b"\r\n", b"\n"))
            print(f"[fix] CRLF -> LF: {name}")


def build() -> int:
    normalize()
    if not (CTX / "Dockerfile").exists():
        print(f"missing Dockerfile at {CTX}", file=sys.stderr)
        return 1
    print(f"[build] docker build -t {IMAGE} {CTX}")
    proc = subprocess.run(["docker", "build", "-t", IMAGE, str(CTX)])
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(build())
