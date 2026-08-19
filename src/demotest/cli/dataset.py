"""demotest dataset — acquire / verify-source / prepare / verify / stats / hash
(guide §30-§34, §43-§45).

acquire:        resolve revision -> download raw -> hash -> write source lock.
                 No adapter, no normalization (guide §33).
verify-source:  check revision / file list / snapshot hash / clean tree / parseable.
prepare:        read raw via adapter -> normalize -> dedup -> write normalized
                 snapshot. No sampling (guide §43).
verify:         re-hash normalized, check case_id unique + fingerprint stable +
                 metadata complete + expected_action legal.
stats:          by phase / scenario / goal / team / style + duplicate counts +
                 length distribution (guide §45).
hash:           print the raw snapshot sha256 only.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from ..config import get_dataset, load_dataset_projection
from ..core.exceptions import DatasetSourceError
from ..paths import DATASETS_V3_METADATA_DIR
from . import _dataset_pipeline as pipeline


def add_parser(sub) -> None:
    p = sub.add_parser("dataset", help="Acquire + prepare + verify external datasets")
    sp = p.add_subparsers(dest="dataset_cmd", required=True)

    a = sp.add_parser("acquire", help="Download pinned raw snapshot + write source lock")
    a.add_argument("--dataset", required=True)
    a.add_argument("--force", action="store_true", help="re-download even if raw dir exists")
    a.set_defaults(func=cmd_acquire)

    v = sp.add_parser("verify-source", help="Verify raw snapshot against the source lock")
    v.add_argument("--dataset", required=True)
    v.set_defaults(func=cmd_verify_source)

    pr = sp.add_parser("prepare", help="Raw -> normalized SecurityCase (no sampling)")
    pr.add_argument("--dataset", required=True)
    pr.add_argument("--max", type=int, default=0, help="cap cases (0 = all; for smoke)")
    pr.add_argument("--full", action="store_true", help="[deprecated alias for --full-source] write the full 148K candidate pool")
    pr.add_argument("--full-source", action="store_true", help="full source evidence mode: write 148K raw evidence (no near-dup O(N^2), not for manifest build)")
    pr.set_defaults(func=cmd_prepare)

    ve = sp.add_parser("verify", help="Verify normalized snapshot integrity")
    ve.add_argument("--dataset", required=True)
    ve.set_defaults(func=cmd_verify)

    st = sp.add_parser("stats", help="Print dataset statistics")
    st.add_argument("--dataset", required=True)
    st.set_defaults(func=cmd_stats)

    h = sp.add_parser("hash", help="Print the raw snapshot sha256")
    h.add_argument("--dataset", required=True)
    h.set_defaults(func=cmd_hash)


# --------------------------------------------------------------------------
def cmd_acquire(args) -> int:
    ds = get_dataset(args.dataset)
    raw = ds.raw_path
    if raw.exists() and any(raw.iterdir()) and not args.force:
        print(f"raw already present at {raw} (use --force to re-download)")
    else:
        if ds.source_type == "huggingface_dataset":
            _acquire_hf(ds)
        elif ds.source_type == "github":
            _acquire_github(ds)
        else:
            print(f"FAIL: unknown source_type {ds.source_type!r}", file=sys.stderr)
            return 1
    # hash + write lock
    globs = ds.hash_globs or None
    file_hashes, snap = pipeline.hash_raw_snapshot(raw, relative_globs=globs)
    lock = pipeline.build_source_lock(ds, snap)
    lock_path = pipeline.write_source_lock(lock)
    print(f"acquired {ds.name}: revision={lock.revision} files={len(file_hashes)}")
    print(f"  raw_sha256={snap}")
    print(f"  lock -> {lock_path}")
    return 0


def _acquire_hf(ds) -> None:
    try:
        from huggingface_hub import snapshot_download
    except ImportError as e:
        raise DatasetSourceError(f"huggingface_hub not installed: {e}") from e
    print(f"downloading {ds.source_uri} @ {ds.revision} -> {ds.raw_path}")
    snapshot_download(
        repo_id=ds.source_uri,
        repo_type="dataset",
        revision=ds.revision,
        local_dir=str(ds.raw_path),
        allow_patterns=ds.allow_patterns or None,
    )


def _acquire_github(ds) -> None:
    ds.raw_path.parent.mkdir(parents=True, exist_ok=True)
    url = f"https://github.com/{ds.source_uri}.git"
    if not (ds.raw_path / ".git").exists():
        print(f"cloning {url} -> {ds.raw_path}")
        subprocess.run(["git", "clone", "--quiet", url, str(ds.raw_path)], check=True)
    subprocess.run(
        ["git", "checkout", "--quiet", ds.revision], cwd=str(ds.raw_path), check=True
    )
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=str(ds.raw_path), capture_output=True, text=True, check=True
    ).stdout.strip()
    if head != ds.revision:
        raise DatasetSourceError(f"clone HEAD {head} != pinned {ds.revision}")
    dirty = subprocess.run(
        ["git", "status", "--porcelain"], cwd=str(ds.raw_path), capture_output=True, text=True, check=True
    ).stdout.strip()
    if dirty:
        raise DatasetSourceError(f"clone working tree dirty:\n{dirty}")


def cmd_verify_source(args) -> int:
    ds = get_dataset(args.dataset)
    problems = pipeline.verify_source(ds)
    if problems:
        for p in problems:
            print(f"FAIL: {p}", file=sys.stderr)
        return 1
    print(f"OK: {ds.name} source verified (revision + snapshot hash + clean tree)")
    return 0


def cmd_prepare(args) -> int:
    ds = get_dataset(args.dataset)
    full = bool(getattr(args, "full", False) or getattr(args, "full_source", False))
    report = pipeline.prepare_dataset(ds, max_cases=args.max or None, full=full)
    print(f"prepared {ds.name}: cases={report.n_cases} kept={report.n_kept}")
    print(f"  exact_dup={report.n_exact} normalized_dup={report.n_norm} clusters={report.n_clusters}")
    print(f"  normalized -> {ds.normalized_path}")
    return 0


def cmd_verify(args) -> int:
    ds = get_dataset(args.dataset)
    problems = pipeline.verify_normalized(ds)
    if problems:
        for p in problems:
            print(f"FAIL: {p}", file=sys.stderr)
        return 1
    print(f"OK: {ds.name} normalized snapshot verified")
    return 0


def cmd_stats(args) -> int:
    ds = get_dataset(args.dataset)
    stats = pipeline.compute_stats(ds)
    print(json.dumps(stats, ensure_ascii=False, indent=2))
    return 0


def cmd_hash(args) -> int:
    ds = get_dataset(args.dataset)
    _, snap = pipeline.hash_raw_snapshot(ds.raw_path, relative_globs=ds.hash_globs or None)
    print(snap)
    return 0
