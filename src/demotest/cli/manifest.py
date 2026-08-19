"""demotest manifest — build / verify frozen benchmark manifests (guide §46-§48).

build:   load normalized snapshots for every dataset feeding a project,
         select cases for the requested suite+project+split deterministically,
         write the frozen manifest (committed to git).
verify:  re-open a manifest and check self-hash, unique ids, no group spans
         splits, and (when the normalized snapshots are present) that every
         entry resolves to a case with a matching fingerprint.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..config import get_suite, load_datasets, load_projects
from ..core.exceptions import ConfigError
from ..datasets.manifest_builder import (
    build_manifest,
    load_manifest,
    manifest_sha256,
    verify_manifest,
    write_manifest,
)
from . import _dataset_pipeline as pipeline
from .dataset import cmd_hash  # noqa: F401  (re-export parity)


# which datasets feed which project (mirror of config/v3/projects.yaml channels,
# kept here as a single source of truth for manifest building).
_DATASETS_BY_PROJECT = {
    "P1_external_instruction": ["llmail", "agentdojo"],
    "P2_tool_action": ["agentdojo"],
}


def add_parser(sub) -> None:
    p = sub.add_parser("manifest", help="Build / verify frozen benchmark manifests")
    sp = p.add_subparsers(dest="manifest_cmd", required=True)

    b = sp.add_parser("build", help="Build a frozen manifest for one suite+project")
    b.add_argument("--suite", required=True)
    b.add_argument("--project", required=True)
    b.add_argument("--target", type=int, default=0, help="override suite target size")
    b.add_argument("--out", default="", help="override output path")
    b.set_defaults(func=cmd_build)

    v = sp.add_parser("verify", help="Verify a frozen manifest")
    v.add_argument("manifest", help="path to manifest json")
    v.add_argument("--strict", action="store_true", help="also resolve cases + check fingerprints")
    v.set_defaults(func=cmd_verify)


def _project_cases(project_id: str):
    """Load + concat normalized cases for every dataset feeding a project."""
    all_cases = []
    datasets = load_datasets()
    for ds_id in _DATASETS_BY_PROJECT.get(project_id, []):
        ds = datasets.get(ds_id)
        if ds is None or not ds.enabled:
            continue
        try:
            cases = pipeline.load_normalized(ds)
        except Exception as e:
            print(f"WARN: cannot load normalized for {ds_id}: {e}", file=sys.stderr)
            continue
        # filter to this project's cases
        all_cases.extend(c for c in cases if (c.project_id or "") == project_id)
    return all_cases


def _source_locks_block(project_id: str) -> dict[str, dict[str, str]]:
    from ..datasets.source_lock import load_source_lock

    blocks: dict[str, dict[str, str]] = {}
    for ds_id in _DATASETS_BY_PROJECT.get(project_id, []):
        try:
            lock = load_source_lock(ds_id)
            blocks[ds_id] = {"revision": lock.revision, "raw_sha256": lock.raw_sha256}
        except Exception:
            continue
    return blocks


def cmd_build(args) -> int:
    suite = get_suite(args.suite)
    if args.project not in suite.projects:
        print(f"FAIL: project {args.project!r} not in suite {args.suite!r}", file=sys.stderr)
        return 1
    ptarget = suite.projects[args.project]
    target = args.target or ptarget.target
    cases = _project_cases(args.project)
    if not cases:
        print(f"FAIL: no normalized cases for project {args.project!r} (run 'dataset prepare')", file=sys.stderr)
        return 1
    manifest = build_manifest(
        suite_id=args.suite,
        project_id=args.project,
        cases=cases,
        seed=suite.seed,
        split=suite.split,
        target=target,
        source_locks=_source_locks_block(args.project),
    )
    out = Path(args.out) if args.out else Path(ptarget.manifest)
    if not args.out and not out.parent.exists():
        out.parent.mkdir(parents=True, exist_ok=True)
    write_manifest(manifest, out)
    # source distribution + split summary
    by_ds: dict[str, int] = {}
    by_split: dict[str, int] = {}
    for e in manifest["cases"]:
        by_ds[e["dataset_id"]] = by_ds.get(e["dataset_id"], 0) + 1
        by_split[e["split"]] = by_split.get(e["split"], 0) + 1
    print(f"built manifest: {out}")
    print(f"  n={manifest['n']} target={target} split={manifest['split']}")
    print(f"  by_dataset={by_ds}")
    print(f"  by_split={by_split}")
    print(f"  manifest_sha256={manifest['manifest_sha256']}")
    return 0


def cmd_verify(args) -> int:
    manifest = load_manifest(args.manifest)
    resolved = None
    if args.strict:
        cases = _project_cases(manifest.get("project", ""))
        from ..datasets.manifest_builder import resolve_manifest_cases

        resolved = resolve_manifest_cases(manifest, cases)
    problems = verify_manifest(manifest, resolved_cases=resolved)
    # also verify the stored self-hash
    recomputed = manifest_sha256(manifest)
    if manifest.get("manifest_sha256") != recomputed:
        problems.append(f"manifest_sha256 drift: stored={manifest.get('manifest_sha256')} computed={recomputed}")
    if problems:
        for p in problems:
            print(f"FAIL: {p}", file=sys.stderr)
        return 1
    print(f"OK: {args.manifest} verified (n={manifest.get('n')} sha256={manifest.get('manifest_sha256')})")
    return 0
