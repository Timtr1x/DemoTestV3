#!/usr/bin/env python
"""Ensure the SkillLeakBench sandbox image is built with CRLF-safe context + python shim.

Windows checkouts with core.autocrlf may turn entrypoint.sh into CRLF,
which makes the container fail with 'bad interpreter: /bin/bash^M'.
This script normalizes the build context to LF and ensures the image
exposes `python` (not only `python3`) so host/Windows callers can use a
single entry_command `python /skills/...` — the shim is created at image
build time via --build-arg or a temporary Dockerfile patch, without
mutating the pinned upstream checkout.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
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
    orig_dockerfile = CTX / "Dockerfile"
    if not orig_dockerfile.exists():
        print(f"missing Dockerfile at {CTX}", file=sys.stderr)
        return 1
    # Do not mutate the pinned checkout — use a temp build context that adds
    # a `python -> python3` shim at image build time.
    with tempfile.TemporaryDirectory() as tmp:
        tmp_ctx = Path(tmp) / "ctx"
        shutil.copytree(CTX, tmp_ctx, symlinks=False)
        df = tmp_ctx / "Dockerfile"
        text = df.read_text(encoding="utf-8")
        shim_snippet = (
            "\n# DemoTest shim: expose `python` as `python3` for Windows/host\n"
            "# compatibility (does not alter upstream logic; pinned revision still recorded).\n"
            "RUN ln -sf /usr/bin/python3 /usr/local/bin/python && \\\n"
            "    ln -sf /usr/bin/python3 /usr/bin/python && \\\n"
            "    python --version && python3 --version\n"
        )
        # Insert before the final ENTRYPOINT/CMD (right after the chmod layer) to keep caching
        if "chmod +x /usr/local/bin/sandbox_monitor.sh" in text:
            text = text.replace(
                "RUN chmod +x /usr/local/bin/sandbox_monitor.sh /usr/local/bin/entrypoint.sh",
                "RUN chmod +x /usr/local/bin/sandbox_monitor.sh /usr/local/bin/entrypoint.sh" + shim_snippet,
            )
        else:
            text += shim_snippet
        df.write_text(text, encoding="utf-8")
        print(f"[build] docker build -t {IMAGE} {tmp_ctx} (with python shim)")
        proc = subprocess.run(["docker", "build", "-t", IMAGE, str(tmp_ctx)])
        return proc.returncode


if __name__ == "__main__":
    raise SystemExit(build())
