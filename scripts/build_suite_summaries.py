"""Generate benchmarks/suites/*.json suite summaries (guide §1, §36).

A suite summary aggregates the frozen per-project manifests of one suite into
a single committed file: the manifest paths, total case count, source locks,
seed, split, and the manifest sha256s. It is benchmark identity, committed to
git alongside the manifests.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from demotest.config import get_suite, load_suites
from demotest.datasets.manifest_builder import load_manifest
from demotest.datasets.source_lock import load_source_lock


def _suite_config_hash(suite_id: str) -> str:
    import yaml
    from demotest.paths import V3_CONFIG_DIR
    p = V3_CONFIG_DIR / "suites.yaml"
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    suite_cfg = (data.get("suites") or {}).get(suite_id, {})
    blob = json.dumps(suite_cfg, sort_keys=True, ensure_ascii=False, default=str)
    return "sha256:" + hashlib.sha256(blob.encode("utf-8")).hexdigest()


def build_suite_summary(suite_id: str) -> dict:
    suite = get_suite(suite_id)
    projects = {}
    total = 0
    for pid, ptarget in suite.projects.items():
        mpath = Path(ptarget.manifest)
        manifest = load_manifest(mpath) if mpath.exists() else {}
        n = manifest.get("n", 0)
        total += n
        projects[pid] = {
            "manifest": ptarget.manifest,
            "manifest_sha256": manifest.get("manifest_sha256", ""),
            "n": n,
            "target": ptarget.target,
            "split": manifest.get("split", []),
            "benchmark_track": manifest.get("benchmark_track", getattr(ptarget, "track", "core")),
            "headline_eligible": manifest.get("headline_eligible", getattr(ptarget, "headline_eligible", True)),
        }
    from demotest.config import load_datasets as _ld2
    try:
        _all_ds = _ld2()
    except Exception:
        _all_ds = {}
    locks = {}
    for pid, ptarget in suite.projects.items():
        # only enabled + strata-referenced datasets
        strata_ds = {str(s.get("dataset") or "") for s in (ptarget.strata or []) if s.get("dataset")}
        for ds_id in (__import__("demotest.cli.manifest", fromlist=["_DATASETS_BY_PROJECT"])._DATASETS_BY_PROJECT.get(pid, [])):
            if ds_id in locks:
                continue
            ds_cfg = _all_ds.get(ds_id)
            if ds_cfg is not None and not ds_cfg.enabled:
                continue
            if strata_ds and ds_id not in strata_ds:
                continue
            try:
                lk = load_source_lock(ds_id)
                locks[ds_id] = {"revision": lk.revision, "raw_sha256": lk.raw_sha256,
                                "adapter": lk.adapter_name, "adapter_version": lk.adapter_version}
            except Exception:
                pass
    return {
        "suite_id": suite_id,
        "seed": suite.seed,
        "split": suite.split,
        "total_cases": total,
        "projects": projects,
        "source_locks": locks,
        "suite_config_hash": _suite_config_hash(suite_id),
        "track": getattr(suite, "track", "core"),
        "headline_eligible": getattr(suite, "headline_eligible", True),
    }


def main() -> int:
    out_dir = Path("benchmarks/suites")
    out_dir.mkdir(parents=True, exist_ok=True)
    for sid in load_suites():
        summary = build_suite_summary(sid)
        p = out_dir / f"{sid}.json"
        p.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"wrote {p}: total_cases={summary['total_cases']} projects={len(summary['projects'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
