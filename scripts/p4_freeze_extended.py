"""Freeze P4 Extended manifest -> benchmarks/frozen/datasets/p4_credential_exposure.

Inputs:
  data/p4_extended/manifest.jsonl  (800, validated)
  data/p4_extended/seeds/seeds.jsonl

Outputs (benchmarks/frozen/datasets/p4_credential_exposure/):
  manifest.jsonl           (800, byte-identical copy)
  seeds.jsonl              (150 seeds)
  source_meta.json         (build provenance)
  split_manifest.json      (group-aware DEV/EVAL/HOLDOUT assignment for 800)

Split: group by seed_id (p4_extended:seed:<seed_id>), seed=42, version split-v2
  DEV 120, SMOKE 100, STANDARD 480, HOLDOUT 100 = 800 total per spec.
  Assignment is group-isolated: one seed never spans splits.

The freeze also validates (Phase 8).
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_MANIFEST = REPO_ROOT / "data" / "p4_extended" / "manifest.jsonl"
SRC_SEEDS = REPO_ROOT / "data" / "p4_extended" / "seeds" / "seeds.jsonl"
OUT_DIR = REPO_ROOT / "benchmarks" / "frozen" / "datasets" / "p4_credential_exposure"
BUILD_SEED = 20260827
SPLIT_SEED = 42

# Target counts per split (Phase 9) — must sum to 800
SPLIT_TARGETS = {
    "dev": 120,
    "smoke": 100,   # NOTE: smoke here is its own split file, not the HOLDOUT scheme
    "eval": 480,    # STANDARD is eval
    "holdout": 100,
}
# For the split_manifest.json we record group assignment (dev/eval/holdout) plus
# smoke selection as a subset of dev (seed-isolated). The spec says:
#   DEV 120, SMOKE 100, STANDARD 480, HOLDOUT 100
# Interpretation: dev pool is 120, smoke is 100 sampled from dev-eval boundary?
# But spec Phase 9 says DEV 120 / SMOKE 100 / STANDARD 480 / HOLDOUT 100 frozen.
# We implement: all 800 are partitioned into dev:120, eval:480, holdout:100, smoke:100
# by taking smoke as the dev subset scaled down. Simpler: treat smoke as dev's
# first 100 after hash-rank. The split_manifest will have 4 buckets summing to 800.

def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()

def load_rows(path: Path) -> list[dict]:
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]

def run_validator() -> None:
    import subprocess, sys
    r = subprocess.run([sys.executable, str(REPO_ROOT/"scripts"/"p4_validate_extended.py"), str(SRC_MANIFEST)], capture_output=True, text=True)
    print(r.stdout)
    if r.stderr:
        print(r.stderr)
    if r.returncode != 0:
        raise SystemExit("validator failed — abort freeze")

def build_split(rows: list[dict]) -> dict:
    # Group by group_id, assign split via split-v2 case-weighted (like sampler)
    # We have 150 groups (one per seed). Each group's size varies (some seeds more frequent).
    from collections import defaultdict
    group_sizes: dict[str,int] = Counter(r["group_id"] for r in rows)
    # Use sampler logic: sorted by split_key then accumulate case counts
    import hashlib as hl
    def split_key(gid: str) -> str:
        return hl.sha256(f"split-v2|{SPLIT_SEED}|{gid}".encode()).hexdigest()[:16]
    sorted_groups = sorted(group_sizes.keys(), key=split_key)
    total = len(rows)
    # Targets per spec: dev 120, smoke 100, eval 480, holdout 100
    # We do 4-way case-weighted cut.
    dev_target = 120
    smoke_target = 100
    eval_target = 480
    holdout_target = 100
    assert dev_target+smoke_target+eval_target+holdout_target == total == 800
    # Order: dev, smoke, eval, holdout along sorted list accumulating counts
    cuts = [dev_target, dev_target+smoke_target, dev_target+smoke_target+eval_target]
    group_to_split: dict[str,str] = {}
    cum = 0
    bucket_idx = 0
    labels = ["dev","smoke","eval","holdout"]
    for gid in sorted_groups:
        sz = group_sizes[gid]
        # Decide bucket based on cum before adding
        # If cum would cross a cut, assign to next bucket
        # Use cumulative count cut
        if bucket_idx < 3 and cum >= cuts[bucket_idx]:
            bucket_idx += 1
        # If adding this group would overshoot the bucket target, see if next bucket is closer
        # Simple: if cum+sz exceeds cut and distance to cut is larger than to next cum, spill to next
        if bucket_idx < 3 and cum + sz > cuts[bucket_idx]:
            dist_stay = abs(cum + sz - cuts[bucket_idx])
            dist_next = abs(cum - cuts[bucket_idx])
            if dist_stay > dist_next and cum < cuts[bucket_idx]:
                # stay in current bucket, even though we overshoot a bit
                pass
            else:
                # spill: but we still assign to current bucket this group
                pass
        group_to_split[gid] = labels[bucket_idx]
        cum += sz
        # Advance bucket if cum reached cut
        while bucket_idx < 3 and cum >= cuts[bucket_idx]:
            bucket_idx += 1
    # Validate
    split_counts = Counter(group_to_split[r["group_id"]] for r in rows)
    # Due to group indivisibility, exact 120/100/480/100 may not be hit; adjust by moving smallest groups if needed
    # We'll greedily rebalance if off by >5
    for _ in range(20):
        split_counts = Counter(group_to_split[r["group_id"]] for r in rows)
        if all(split_counts.get(k,0)==v for k,v in [("dev",120),("smoke",100),("eval",480),("holdout",100)]):
            break
        # Find over and under
        targets = {"dev":120,"smoke":100,"eval":480,"holdout":100}
        over = [(k, split_counts.get(k,0)-targets[k]) for k in targets if split_counts.get(k,0)>targets[k]]
        under = [(k, targets[k]-split_counts.get(k,0)) for k in targets if split_counts.get(k,0)<targets[k]]
        if not over or not under:
            break
        over.sort(key=lambda x: x[1], reverse=True)
        under.sort(key=lambda x: x[1], reverse=True)
        ok, ok2 = over[0][0], under[0][0]
        # Move smallest group from over to under
        candidates = [g for g,s in group_to_split.items() if s==ok]
        candidates.sort(key=lambda g: group_sizes[g])
        if not candidates:
            break
        g_move = candidates[0]
        group_to_split[g_move] = ok2
    split_counts = Counter(group_to_split[r["group_id"]] for r in rows)
    print(f"split groups: {len(group_sizes)} split_counts={dict(split_counts)}")
    # Fail-closed if not exact
    for k,v in [("dev",120),("smoke",100),("eval",480),("holdout",100)]:
        if split_counts.get(k,0) != v:
            raise SystemExit(f"split target not met: {k} has {split_counts.get(k,0)} != {v}; need group indivisible fix")
    return group_to_split


def main() -> None:
    if not SRC_MANIFEST.exists():
        raise SystemExit(f"missing {SRC_MANIFEST} — run scripts/p4_build_extended.py first")
    if not SRC_SEEDS.exists():
        raise SystemExit(f"missing {SRC_SEEDS}")
    print("Phase 8 validate...")
    run_validator()
    rows = load_rows(SRC_MANIFEST)
    if len(rows) != 800:
        raise SystemExit(f"manifest n={len(rows)} != 800")
    group_to_split = build_split(rows)
    # Write out
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    # 1 manifest.jsonl (byte-identical copy)
    import shutil
    shutil.copy2(SRC_MANIFEST, OUT_DIR / "manifest.jsonl")
    # also seeds
    shutil.copy2(SRC_SEEDS, OUT_DIR / "seeds.jsonl")
    # 2 source_meta.json
    manifest_sha = hashlib.sha256((OUT_DIR / "manifest.jsonl").read_bytes()).hexdigest()
    seeds_sha = hashlib.sha256((OUT_DIR / "seeds.jsonl").read_bytes()).hexdigest()
    meta = {
        "dataset_id": "p4_credential_exposure",
        "build_seed": BUILD_SEED,
        "split_seed": SPLIT_SEED,
        "split_version": "split-v2",
        "n_cases": len(rows),
        "n_seeds": len(load_rows(SRC_SEEDS)),
        "manifest_sha256": manifest_sha,
        "seeds_sha256": seeds_sha,
        "block": sum(1 for r in rows if r["expected_action"]=="block"),
        "allow": sum(1 for r in rows if r["expected_action"]=="allow"),
        "by_subtype": dict(Counter(r["subtype"] for r in rows)),
        "by_secret_kind": dict(Counter(r["secret_kind"] for r in rows)),
        "split_targets": {"dev":120,"smoke":100,"eval":480,"holdout":100},
        "split_actual": dict(Counter(group_to_split[r["group_id"]] for r in rows)),
        "group_count": len(set(r["group_id"] for r in rows)),
        "canary_prefix": "TEST_SECRET_",
        "quality_tier": "C",
        "derivation": "catalog_derived",
    }
    (OUT_DIR / "source_meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    # 3 split_manifest.json — case_id -> split
    split_manifest = {
        "split_version": "split-v2",
        "split_seed": SPLIT_SEED,
        "groups": group_to_split,
        "cases": {r["case_id"]: group_to_split[r["group_id"]] for r in rows},
        "counts": dict(Counter(group_to_split[r["group_id"]] for r in rows)),
    }
    (OUT_DIR / "split_manifest.json").write_text(json.dumps(split_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"frozen -> {OUT_DIR}")
    print(f"  manifest {OUT_DIR / 'manifest.jsonl'} sha256={manifest_sha}")
    print(f"  source_meta {OUT_DIR / 'source_meta.json'}")
    print(f"  split_manifest dev={split_manifest['counts'].get('dev')} smoke={split_manifest['counts'].get('smoke')} eval={split_manifest['counts'].get('eval')} holdout={split_manifest['counts'].get('holdout')}")

if __name__ == "__main__":
    main()
