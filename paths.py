"""Repo-root paths for the LineMod E1–E12 guardrail framework."""
from __future__ import annotations

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
CONFIG_DIR = REPO_ROOT / "config"
CACHE_DIR = REPO_ROOT / "cache"
DATASETS_DIR = CACHE_DIR / "datasets"
MANIFEST_DIR = CACHE_DIR / "sample_manifests"
RESULTS_DIR = CACHE_DIR / "results"

LEGACY_DEMOTEST_ROOT = Path(
    os.environ.get("LEGACY_DEMOTEST_ROOT", r"D:\KMG\Coding\DemoTest")
)

for _d in (CONFIG_DIR, CACHE_DIR, DATASETS_DIR, MANIFEST_DIR, RESULTS_DIR):
    _d.mkdir(parents=True, exist_ok=True)
