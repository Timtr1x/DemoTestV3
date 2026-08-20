"""demotest manifest — build / verify frozen benchmark manifests (fix round v3.2)."""
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
from .dataset import cmd_hash  # noqa: F401


_DATASETS_BY_PROJECT = {
    "P1_external_instruction": ["llmail"],
    "P2_tool_action": ["agentdojo"],
    "P4_credential_flow": ["credential_catalog_synthetic", "credential_traces"],
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

    sv = sp.add_parser("suite-verify", help="Verify a suite snapshot binds correct manifest hashes")
    sv.add_argument("suite", help="suite id (e.g. phase1-standard-v2)")
    sv.set_defaults(func=cmd_suite_verify)


def _project_cases(project_id: str):
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
        all_cases.extend(c for c in cases if (c.project_id or "") == project_id)
    return all_cases


def _source_locks_block(project_id: str) -> dict[str, dict[str, Any]]:
    from ..datasets.source_lock import load_source_lock

    blocks: dict[str, dict[str, Any]] = {}
    for ds_id in _DATASETS_BY_PROJECT.get(project_id, []):
        try:
            lock = load_source_lock(ds_id)
            blocks[ds_id] = {
                "revision": lock.revision,
                "raw_sha256": lock.raw_sha256,
                "adapter": lock.adapter_name,
                "adapter_version": lock.adapter_version,
                "benchmark_version": lock.extra.get("benchmark_version") if lock.extra else None,
            }
            # prune None
            blocks[ds_id] = {k: v for k, v in blocks[ds_id].items() if v is not None}
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
    strata = getattr(ptarget, "strata", None)
    max_cluster_share = getattr(ptarget, "max_cluster_share", None)
    split_version = getattr(suite, "split_version", "split-v1") or "split-v1"
    # Guard: full-source evidence (148K, near-dup not_computed) must not be used for manifest
    for ds_id in _DATASETS_BY_PROJECT.get(args.project, []):
        try:
            from ..config import get_dataset as _gd
            _ds = _gd(ds_id)
            _prep = _ds.normalized_path / "prepare.json"
            if _prep.exists():
                import json as _js
                _meta = _js.loads(_prep.read_text(encoding="utf-8"))
                _nd = _meta.get("dedup", {}).get("near_duplicate", {})
                if isinstance(_nd, dict) and _nd.get("status") == "not_computed":
                    print(f"FAIL: {ds_id} normalized is full-source evidence (near-dup not_computed) — not for manifest build. Re-run 'dataset prepare --dataset {ds_id}' without --full-source.", file=sys.stderr)
                    return 1
        except SystemExit:
            raise
        except Exception:
            pass
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
        strata=strata,
        max_cluster_share=max_cluster_share,
        split_version=split_version,
    )
    out = Path(args.out) if args.out else Path(ptarget.manifest)
    if not args.out and not out.parent.exists():
        out.parent.mkdir(parents=True, exist_ok=True)
    write_manifest(manifest, out)
    by_ds: dict[str, int] = {}
    by_split: dict[str, int] = {}
    for e in manifest["cases"]:
        by_ds[e["dataset_id"]] = by_ds.get(e["dataset_id"], 0) + 1
        by_split[e["split"]] = by_split.get(e["split"], 0) + 1
    print(f"built manifest: {out}")
    print(f"  n={manifest['n']} target={target} split={manifest['split']}")
    print(f"  by_dataset={by_ds}")
    print(f"  by_split={by_split}")
    if manifest.get("strata"):
        print(f"  strata={manifest['strata']}")
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
    recomputed = manifest_sha256(manifest)
    if manifest.get("manifest_sha256") != recomputed:
        problems.append(f"manifest_sha256 drift: stored={manifest.get('manifest_sha256')} computed={recomputed}")
    if problems:
        for p in problems:
            print(f"FAIL: {p}", file=sys.stderr)
        return 1
    print(f"OK: {args.manifest} verified (n={manifest.get('n')} sha256={manifest.get('manifest_sha256')})")
    return 0


def cmd_suite_verify(args) -> int:
    from pathlib import Path as _P
    from ..paths import BENCHMARKS_SUITES_DIR

    suite = get_suite(args.suite)
    suite_path = BENCHMARKS_SUITES_DIR / f"{args.suite}.json"
    if not suite_path.exists():
        print(f"FAIL: suite snapshot not found: {suite_path}", file=sys.stderr)
        return 1
    snap = json.loads(suite_path.read_text(encoding="utf-8"))
    problems: list[str] = []
    # check suite_config_hash drift if snapshot has it
    try:
        import hashlib as _hl2, json as _js2, yaml as _yl2
        from ..paths import V3_CONFIG_DIR as _V3
        _cfg2 = _yl2.safe_load((_V3 / "suites.yaml").read_text(encoding="utf-8")) or {}
        _sc2 = (_cfg2.get("suites") or {}).get(args.suite, {})
        _exp2 = "sha256:" + _hl2.sha256(_js2.dumps(_sc2, sort_keys=True, ensure_ascii=False, default=str).encode()).hexdigest()
        if snap.get("suite_config_hash") and snap["suite_config_hash"] != _exp2:
            problems.append(f"suite_config_hash drift: snapshot {snap['suite_config_hash'][:16]} != suites.yaml { _exp2[:16]} (re-run build_suite_summaries)")
    except Exception:
        pass
    for pid, ptarget in suite.projects.items():
        mpath = _P(ptarget.manifest)
        if not mpath.exists():
            problems.append(f"{pid}: manifest not found: {mpath}")
            continue
        manifest = load_manifest(str(mpath))
        recomputed = manifest_sha256(manifest)
        if manifest.get("manifest_sha256") != recomputed:
            problems.append(f"{pid}: manifest_sha256 drift")
        # compare with suite snapshot binding if present
        snap_entry = (snap.get("projects") or {}).get(pid) or {}
        snap_sha = snap_entry.get("manifest_sha256")
        if snap_sha and snap_sha != manifest.get("manifest_sha256"):
            problems.append(f"{pid}: suite manifest_sha256 {snap_sha} != manifest {manifest.get('manifest_sha256')}")
        if snap_entry.get("n") and snap_entry["n"] != manifest.get("n"):
            problems.append(f"{pid}: suite n {snap_entry['n']} != manifest n {manifest.get('n')}")
        problems.extend(verify_manifest(manifest))
    if problems:
        for p in problems:
            print(f"FAIL: {p}", file=sys.stderr)
        return 1
    print(f"OK: suite {args.suite} verified")
    return 0
