"""Filesystem paths for the V3 framework.

V3 reuses the V2 cache layout (``cache/sample_manifests``, ``cache/results``,
``cache/datasets``) unchanged — the refactor freezes the data layer (plan §49).
V3 writes its own results under ``cache/results_v3`` so V2/V3 runs never collide
and regression comparisons stay clean.
"""
from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = REPO_ROOT / "config"
CACHE_DIR = REPO_ROOT / "cache"
DATASETS_DIR = CACHE_DIR / "datasets"
# V2 manifest store — READ ONLY in V3 (plan §48)
MANIFEST_DIR = CACHE_DIR / "sample_manifests"
# V2 results — read-only reference for regression
RESULTS_DIR_V2 = CACHE_DIR / "results"
# V3 results — append-only store (plan §23)
RESULTS_DIR = CACHE_DIR / "results_v3"
# V3 manifests (fixtures / generated) — separate from frozen V2 manifests
MANIFEST_DIR_V3 = CACHE_DIR / "manifests_v3"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures"
REPORTS_DIR = REPO_ROOT / "reports"
LEGACY_DIR = REPO_ROOT / "legacy"

for _d in (
    CONFIG_DIR,
    CACHE_DIR,
    DATASETS_DIR,
    MANIFEST_DIR,
    RESULTS_DIR,
    MANIFEST_DIR_V3,
    FIXTURES_DIR,
    REPORTS_DIR,
):
    _d.mkdir(parents=True, exist_ok=True)
