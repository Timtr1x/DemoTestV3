"""Freeze P4 Extended manifest -> benchmarks/frozen/datasets/p4_credential_exposure (P4E-v2).

Inputs:
  data/p4_extended/manifest.jsonl  (800, validated)
  data/p4_extended/seeds/seeds.jsonl

Outputs (benchmarks/frozen/datasets/p4_credential_exposure/):
  manifest.jsonl           (800, byte-identical copy)
  seeds.jsonl              (150 seeds)
  source_meta.json         (build provenance)
  split_manifest.json      (group-aware DEV/EVAL/HOLDOUT assignment for 800)

Split: group by seed_id (p4_extended:seed:<seed_id>), seed=42, version split-v2
  Stratified by expected_action: BLOCK groups (80) and ALLOW groups (70) are
  split independently to hit per-split block/allow quotas.
  DEV 65B+55A=120, SMOKE 53B+47A=100, EVAL 240B+240A=480, HOLDOUT 55B+45A=100.
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

SPLIT_TARGETS = {
    "dev": 120,
    "smoke": 100,
    "eval": 480,
    "holdout": 100,
}

# Per-split block/allow quotas (must sum to totals 413B/387A and to SPLIT_TARGETS)
PER_SPLIT_BLOCK = {"dev": 65, "smoke": 53, "eval": 240, "holdout": 55}
PER_SPLIT_ALLOW = {"dev": 55, "smoke": 47, "eval": 240, "holdout": 45}


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
    group_sizes: dict[str,int] = Counter(r["group_id"] for r in rows)
    group_to_ea: dict[str,str] = {}
    for r in rows:
        gid = r["group_id"]
        ea = r["expected_action"]
        if gid in group_to_ea:
            assert group_to_ea[gid] == ea, f"mixed group {gid}"
        else:
            group_to_ea[gid] = ea
    block_groups = {g: sz for g, sz in group_sizes.items() if group_to_ea[g] == "block"}
    allow_groups = {g: sz for g, sz in group_sizes.items() if group_to_ea[g] == "allow"}
    print(f"groups: block {len(block_groups)} allow {len(allow_groups)} (total {len(group_sizes)})")

    def split_one(sizes: dict[str,int], targets: dict[str,int], seed: int) -> dict[str,str]:
        order = ["dev","smoke","eval","holdout"]
        cuts = []
        cum = 0
        for lab in order:
            cum += targets[lab]
            cuts.append(cum)
        sorted_groups = sorted(sizes.keys(), key=lambda gid: hashlib.sha256(f"split-v2|{seed}|{gid}".encode()).hexdigest()[:16])
        g2s: dict[str,str] = {}
        cum = 0
        bucket_idx = 0
        for gid in sorted_groups:
            sz = sizes[gid]
            if bucket_idx < 3 and cum >= cuts[bucket_idx]:
                bucket_idx += 1
            g2s[gid] = order[bucket_idx]
            cum += sz
            while bucket_idx < 3 and cum >= cuts[bucket_idx]:
                bucket_idx += 1
        # Greedy rebalance to hit exact case counts
        for _ in range(30):
            case_cnt = Counter()
            for g in sizes:
                case_cnt[g2s[g]] += sizes[g]
            if all(case_cnt.get(k,0) == v for k,v in targets.items()):
                break
            over = [(k, case_cnt.get(k,0)-targets[k]) for k in targets if case_cnt.get(k,0) > targets[k]]
            under = [(k, targets[k]-case_cnt.get(k,0)) for k in targets if case_cnt.get(k,0) < targets[k]]
            if not over or not under:
                break
            over.sort(key=lambda x: x[1], reverse=True)
            under.sort(key=lambda x: x[1], reverse=True)
            ok, ok2 = over[0][0], under[0][0]
            cands = [g for g,s in g2s.items() if s == ok]
            cands.sort(key=lambda g: sizes[g])
            if not cands:
                break
            g2s[cands[0]] = ok2
        return g2s

    bg = split_one(block_groups, PER_SPLIT_BLOCK, SPLIT_SEED)
    ag = split_one(allow_groups, PER_SPLIT_ALLOW, SPLIT_SEED)
    merged = {**bg, **ag}
    # Validate totals
    actual = Counter(merged[r["group_id"]] for r in rows)
    print(f"split groups: {len(group_sizes)} split_counts={dict(actual)} (stratified)")
    for k,v in [("dev",120),("smoke",100),("eval",480),("holdout",100)]:
        if actual.get(k,0) != v:
            raise SystemExit(f"split target not met: {k} has {actual.get(k,0)} != {v}")
    # Validate per-split block/allow
    for sp in ["dev","smoke","eval","holdout"]:
        b = sum(1 for r in rows if merged[r["group_id"]] == sp and r["expected_action"] == "block")
        a = sum(1 for r in rows if merged[r["group_id"]] == sp and r["expected_action"] == "allow")
        if b != PER_SPLIT_BLOCK[sp] or a != PER_SPLIT_ALLOW[sp]:
            raise SystemExit(f"stratified split mismatch {sp}: block {b}!={PER_SPLIT_BLOCK[sp]} allow {a}!={PER_SPLIT_ALLOW[sp]}")
    return merged


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
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    import shutil
    shutil.copy2(SRC_MANIFEST, OUT_DIR / "manifest.jsonl")
    shutil.copy2(SRC_SEEDS, OUT_DIR / "seeds.jsonl")
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
        "by_benign_subtype": dict(Counter(r.get("benign_subtype","") for r in rows if r.get("expected_action")=="allow")),
        "split_targets": {"dev":120,"smoke":100,"eval":480,"holdout":100},
        "split_actual": dict(Counter(group_to_split[r["group_id"]] for r in rows)),
        "split_block": dict(PER_SPLIT_BLOCK),
        "split_allow": dict(PER_SPLIT_ALLOW),
        "group_count": len(set(r["group_id"] for r in rows)),
        "canary_mode": "per_row_demo_marker",
        "quality_tier": "C",
        "derivation": "catalog_derived",
    }
    (OUT_DIR / "source_meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    split_manifest = {
        "split_version": "split-v2",
        "split_seed": SPLIT_SEED,
        "groups": group_to_split,
        "cases": {r["case_id"]: group_to_split[r["group_id"]] for r in rows},
        "counts": dict(Counter(group_to_split[r["group_id"]] for r in rows)),
        "counts_by_action": {
            sp: {"block": sum(1 for r in rows if group_to_split[r["group_id"]] == sp and r["expected_action"]=="block"),
                 "allow": sum(1 for r in rows if group_to_split[r["group_id"]] == sp and r["expected_action"]=="allow")}
            for sp in ["dev","smoke","eval","holdout"]
        },
    }
    (OUT_DIR / "split_manifest.json").write_text(json.dumps(split_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"frozen -> {OUT_DIR}")
    print(f"  manifest {OUT_DIR / 'manifest.jsonl'} sha256={manifest_sha}")
    print(f"  source_meta {OUT_DIR / 'source_meta.json'}")
    print(f"  split_manifest {split_manifest['counts']} by_action={split_manifest['counts_by_action']}")

if __name__ == "__main__":
    main()
