#!/usr/bin/env python
"""Ensure the SkillLeakBench sandbox image is built with CRLF-safe context + python shim.

Windows checkouts with core.autocrlf may turn entrypoint.sh into CRLF,
which makes the container fail with 'bad interpreter: /bin/bash^M'.
This script normalizes the build context to LF and ensures the image
exposes `python` (not only `python3`) so host/Windows callers can use a
single entry_command `python /skills/...`.

The pinned upstream checkout is NEVER modified: CRLF normalization and the
python shim are applied only inside a temporary build context copy.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CTX = ROOT / "cache/datasets_v3/raw/skillleakbench_pipeline/code/phase3_dynamic"
IMAGE = "skill-leakbench"

FIX_FILES = ["entrypoint.sh", "sandbox_monitor.sh", "exfil_collector.py", "mock_creds.py"]

SHIM_SNIPPET = (
    "\n# DemoTest shim: expose `python` as `python3` for Windows/host\n"
    "# compatibility (does not alter upstream logic; pinned revision still recorded).\n"
    "RUN ln -sf /usr/bin/python3 /usr/local/bin/python && \\\n"
    "    ln -sf /usr/bin/python3 /usr/bin/python && \\\n"
    "    python --version && python3 --version\n"
)


def normalize(root: Path) -> None:
    """CRLF -> LF on known shell/py entry files under *root* (a temp copy)."""
    for name in FIX_FILES:
        p = root / name
        if not p.exists():
            continue
        data = p.read_bytes()
        if b"\r\n" in data:
            p.write_bytes(data.replace(b"\r\n", b"\n"))
            print(f"[fix] CRLF -> LF: {name}")


def prepare_build_context(ctx: Path, work_dir: Path) -> Path:
    """Copy *ctx* into a temp build context, then normalize + add python shim.

    The source checkout is only read, never written.
    """
    tmp_ctx = work_dir / "ctx"
    shutil.copytree(ctx, tmp_ctx, symlinks=False)
    normalize(tmp_ctx)
    df = tmp_ctx / "Dockerfile"
    if not df.exists():
        raise FileNotFoundError(f"missing Dockerfile at {ctx}")
    text = df.read_text(encoding="utf-8")
    # Insert before the final ENTRYPOINT/CMD (right after the chmod layer) to keep caching
    if "chmod +x /usr/local/bin/sandbox_monitor.sh" in text:
        text = text.replace(
            "RUN chmod +x /usr/local/bin/sandbox_monitor.sh /usr/local/bin/entrypoint.sh",
            "RUN chmod +x /usr/local/bin/sandbox_monitor.sh /usr/local/bin/entrypoint.sh" + SHIM_SNIPPET,
        )
    else:
        text += SHIM_SNIPPET
    df.write_text(text, encoding="utf-8")
    return tmp_ctx


def build() -> int:
    if not (CTX / "Dockerfile").exists():
        print(f"missing Dockerfile at {CTX}", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory() as tmp:
        tmp_ctx = prepare_build_context(CTX, Path(tmp))
        print(f"[build] docker build -t {IMAGE} {tmp_ctx} (with python shim)")
        proc = subprocess.run(["docker", "build", "-t", IMAGE, str(tmp_ctx)])
        return proc.returncode


if __name__ == "__main__":
    raise SystemExit(build())
