"""Deprecated: samples_per_project=500 pad is removed. Use resample_real.py."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.resample_real import main  # noqa: E402

if __name__ == "__main__":
    print("NOTE: pad-to-500 removed; running real-n resample.", flush=True)
    raise SystemExit(main())
