"""Build frozen manifests for p4e-* suites from the frozen split_manifest."""
from __future__ import annotations
import hashlib
import json
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(REPO_ROOT / "src"))

from demotest.config import get_suite
from demotest.datasets.manifest_builder import manifest_sha256, write_manifest
from demotest.datasets.source_lock import load_source_lock

FROZEN_DIR = REPO_ROOT / "benchmarks" / "frozen" / "datasets" / "p4_credential_exposure"
SPLIT_MANIFEST = FROZEN_DIR / "split_manifest.json"
MANIFEST_JSONL = FROZEN_DIR / "manifest.jsonl"

SUITES = ["p4e-smoke-v1", "p4e-standard-v1", "p4e-holdout-v1", "p4e-dev-v1"]

def load_rows() -> list[dict]:
    return [json.loads(l) for l in MANIFEST_JSONL.read_text(encoding="utf-8").splitlines() if l.strip()]

def load_split() -> dict:
    return json.loads(SPLIT_MANIFEST.read_text(encoding="utf-8"))

def build_one(suite_id: str, rows: list[dict], split_map: dict[str,str]) -> dict:
    suite = get_suite(suite_id)
    ptarget = suite.projects["P4_credential_flow"]
    target = ptarget.target
    strata = ptarget.strata
    split = suite.split
    allowed = set(split)
    eligible = [r for r in rows if split_map.get(r["case_id"], "") in allowed]
    import hashlib as hl
    def rank_key(r: dict) -> str:
        raw = "|".join([suite_id, str(suite.seed), "p4_credential_exposure", r["source_id"], r["group_id"]])
        return hl.sha256(raw.encode()).hexdigest()
    from demotest.config import get_dataset
    from demotest.cli._dataset_pipeline import load_normalized
    ds = get_dataset("p4_credential_exposure")
    cases = {c.case_id: c for c in load_normalized(ds)}
    def fp_for(r: dict) -> str:
        c = cases.get(r["case_id"])
        if c is not None:
            return c.fingerprint()
        return "fp-" + hl.sha256(r["content"].encode()).hexdigest()[:16]
    selected: list[dict] = []
    strata_report: dict[str, dict] = {}
    for st in strata:
        sid = str(st.get("id") or st.get("name") or "stratum")
        count_raw = st.get("count", 0)
        is_all = isinstance(count_raw, str) and count_raw.lower() == "all"
        target_n = 0 if is_all else int(count_raw or 0)
        filt = list(eligible)
        ea = st.get("expected_action")
        if ea:
            filt = [r for r in filt if r["expected_action"] == ea]
        ch = st.get("channel")
        if ch:
            filt = [r for r in filt if r.get("channel","tool_result") == ch]
        filt = [r for r in filt if r not in selected]
        filt.sort(key=rank_key)
        if is_all:
            chosen = filt
        else:
            chosen = filt[:target_n]
        if not is_all and len(chosen) < target_n:
            print(f"WARN {suite_id} {sid}: wanted {target_n} got {len(chosen)} (filtered {len(filt)})")
        selected.extend(chosen)
        strata_report[sid] = {"target": count_raw, "actual": len(chosen), "filtered": len(filt)}
    entries = []
    for r in selected:
        entries.append({
            "case_id": r["case_id"],
            "case_fingerprint": fp_for(r),
            "dataset_id": "p4_credential_exposure",
            "source_id": r["source_id"],
            "split": split_map.get(r["case_id"], split[0]),
            "group_id": r["group_id"],
        })
    entries.sort(key=lambda e: e["case_id"])
    try:
        lk = load_source_lock("p4_credential_exposure")
        created_from = {
            "p4_credential_exposure": {
                "revision": lk.revision,
                "raw_sha256": lk.raw_sha256,
                "adapter": lk.adapter_name,
                "adapter_version": lk.adapter_version,
            }
        }
    except Exception:
        created_from = {}
    manifest = {
        "manifest_version": "v3.2",
        "suite": suite_id,
        "project": "P4_credential_flow",
        "seed": suite.seed,
        "split": sorted(allowed),
        "target": target,
        "benchmark_track": ptarget.track,
        "headline_eligible": ptarget.headline_eligible,
        "created_from": created_from,
        "selection_policy": {
            "algorithm": "hash_rank_v1",
            "split_algorithm": "group_aware_case_count_v2",
            "split_ratios": {"dev": 0.15, "smoke": 0.125, "eval": 0.60, "holdout": 0.125},
            "split_version": suite.split_version,
            "note": "split from frozen split_manifest.json stratified by expected_action; hash-rank within split for strata",
        },
        "n": len(entries),
        "cases": entries,
    }
    if strata_report:
        manifest["strata"] = strata_report
    manifest["manifest_sha256"] = manifest_sha256(manifest)
    return manifest


def main() -> int:
    rows = load_rows()
    split_data = load_split()
    split_map = split_data.get("cases", {})
    for suite_id in SUITES:
        manifest = build_one(suite_id, rows, split_map)
        suite = get_suite(suite_id)
        out = Path(suite.projects["P4_credential_flow"].manifest)
        write_manifest(manifest, out)
        print(f"built {out}: n={manifest['n']} split={manifest['split']} sha256={manifest['manifest_sha256'][:16]}...")
        by_split = Counter(e["split"] for e in manifest["cases"])
        print(f"  by_split={dict(by_split)}")
    from build_suite_summaries import build_suite_summary
    import json as js
    out_dir = REPO_ROOT / "benchmarks" / "suites"
    for sid in SUITES:
        summary = build_suite_summary(sid)
        p = out_dir / f"{sid}.json"
        p.write_text(js.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"wrote suite {p} total={summary['total_cases']}")
    return 0

if __name__ == "__main__":
    main()
