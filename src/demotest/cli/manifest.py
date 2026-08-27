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
    # P4: credential exposure Extended (p4_credential_exposure, 800, seed-derived)
    # plus legacy/reviewed real P4 datasets kept for history but not required for
    # Extended manifests. Old dynamic P4 stays frozen but is NOT required to run
    # Extended benchmark.
    "P4_credential_flow": [
        "p4_credential_exposure",
        "credential_dynamic_traces",
        "credential_catalog_synthetic",
        "credential_traces",
    ],
    # P5 (Phase 2A): official ASB memory-poisoning source (attack-only proof).
    "P5_memory_write": ["p5_asb_memory"],
    "P3_mcp_definition": ["p3_mcptox"],
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


def _source_locks_block(project_id: str, *, suite_id: str | None = None) -> dict[str, dict[str, Any]]:
    from ..datasets.source_lock import load_source_lock
    from ..config import load_datasets as _ld

    # Only include enabled datasets actually referenced by the suite strata if suite_id given
    strata_datasets: set[str] | None = None
    if suite_id:
        try:
            from ..config import get_suite as _gs2
            suite = _gs2(suite_id)
            pt = suite.projects.get(project_id)
            if pt and pt.strata:
                strata_datasets = {str(s.get("dataset") or "") for s in pt.strata if s.get("dataset")}
                strata_datasets.discard("")
        except Exception:
            pass

    try:
        all_datasets = _ld()
    except Exception:
        all_datasets = {}

    blocks: dict[str, dict[str, Any]] = {}
    for ds_id in _DATASETS_BY_PROJECT.get(project_id, []):
        # skip disabled datasets (review: P4 suite had both synthetic + disabled alias)
        ds_cfg = all_datasets.get(ds_id)
        if ds_cfg is not None and not ds_cfg.enabled:
            continue
        if strata_datasets is not None and ds_id not in strata_datasets:
            continue
        try:
            lock = load_source_lock(ds_id)
            blocks[ds_id] = {
                "revision": lock.revision,
                "raw_sha256": lock.raw_sha256,
                "adapter": lock.adapter_name,
                "adapter_version": lock.adapter_version,
                "benchmark_version": lock.extra.get("benchmark_version") if lock.extra else None,
            }
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
        source_locks=_source_locks_block(args.project, suite_id=args.suite),
        strata=strata,
        max_cluster_share=max_cluster_share,
        split_version=split_version,
        benchmark_track=getattr(ptarget, "track", "core"),
        headline_eligible=getattr(ptarget, "headline_eligible", getattr(ptarget, "track", "core") == "core"),
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
    FROZEN_PROOF_SUITES = {"p5-asb-proof-v0"}
    is_frozen_proof = args.suite in FROZEN_PROOF_SUITES
    if is_frozen_proof:
        # Historical proof: snapshot source_locks must equal manifest created_from (1.0.0),
        # not current lock. Ensures bookkeeping consistency without demanding current version.
        for pid, ptarget in suite.projects.items():
            mpath_tmp = _P(ptarget.manifest)
            if not mpath_tmp.exists():
                continue
            try:
                m_tmp = load_manifest(str(mpath_tmp))
            except Exception:
                continue
            strata_ds_tmp = {str(s.get("dataset") or "") for s in (ptarget.strata or []) if s.get("dataset")}
            for ds_id in _DATASETS_BY_PROJECT.get(pid, []):
                if strata_ds_tmp and ds_id not in strata_ds_tmp:
                    continue
                cf_tmp = (m_tmp.get("created_from") or {}).get(ds_id)
                if not cf_tmp:
                    continue
                snap_locks_tmp = snap.get("source_locks") or {}
                snap_lock_tmp = snap_locks_tmp.get(ds_id)
                if not snap_lock_tmp:
                    problems.append(f"{pid}: frozen proof snapshot missing source_locks[{ds_id!r}]")
                    continue
                for k in ("adapter_version", "raw_sha256", "revision"):
                    if snap_lock_tmp.get(k) != cf_tmp.get(k):
                        problems.append(
                            f"{pid}: frozen proof snapshot source_locks[{ds_id}].{k} {snap_lock_tmp.get(k)!r} "
                            f"!= manifest created_from[{ds_id}].{k} {cf_tmp.get(k)!r}"
                        )
    else:
        try:
            from ..datasets.source_lock import load_source_lock as _ld_lock
            from ..config import load_datasets as _ld2
            _all_ds = _ld2()
            for pid, ptarget in suite.projects.items():
                strata_ds = {str(s.get("dataset") or "") for s in (ptarget.strata or []) if s.get("dataset")}
                for ds_id in _DATASETS_BY_PROJECT.get(pid, []):
                    if strata_ds and ds_id not in strata_ds:
                        continue
                    ds_cfg = _all_ds.get(ds_id)
                    if ds_cfg is not None and not ds_cfg.enabled:
                        continue
                    try:
                        cur_lock = _ld_lock(ds_id)
                    except Exception:
                        continue
                    snap_locks = snap.get("source_locks") or {}
                    snap_lock = snap_locks.get(ds_id)
                    if not snap_lock:
                        problems.append(f"{pid}: snapshot missing source_locks[{ds_id!r}] (re-run build_suite_summaries)")
                        continue
                    for k in ("adapter_version", "raw_sha256", "revision"):
                        cur_v = getattr(cur_lock, k, None)
                        snap_v = snap_lock.get(k)
                        if cur_v and snap_v != cur_v:
                            problems.append(
                                f"{pid}: snapshot source_locks[{ds_id}].{k} {snap_v!r} != current lock {cur_v!r} "
                                f"(re-run build_suite_summaries after lock bump)"
                            )
        except Exception as _e:
            problems.append(f"source_locks gate error: {_e}")
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
        # Hard gate: manifest target must match suite project target
        if manifest.get("target") != ptarget.target:
            problems.append(
                f"{pid}: manifest target {manifest.get('target')!r} != suite project target {ptarget.target!r} "
                f"(re-run manifest build after suites.yaml edit)"
            )
        # Hard gate: manifest strata count must match suite strata count
        if ptarget.strata:
            m_strata = manifest.get("strata") or {}
            for s in ptarget.strata:
                sid = str(s.get("id") or s.get("name") or "")
                if not sid:
                    continue
                exp_count = s.get("count")
                m_entry = m_strata.get(sid)
                if m_entry is None:
                    problems.append(f"{pid}: manifest missing strata {sid!r} (re-run manifest build)")
                    continue
                # for count=='all', manifest stores target=='all' — only check numerics
                if isinstance(exp_count, str) and exp_count.lower() == "all":
                    if str(m_entry.get("target", "")).lower() != "all":
                        problems.append(f"{pid}: strata {sid!r} target expected 'all', got {m_entry.get('target')!r}")
                elif exp_count is not None:
                    try:
                        if int(m_entry.get("target", -1)) != int(exp_count):
                            problems.append(
                                f"{pid}: strata {sid!r} target {m_entry.get('target')!r} != suite count {exp_count!r}"
                            )
                    except (TypeError, ValueError):
                        pass
        # Hard gate: manifest created_from must match current source lock
        # FROZEN proof suites keep their original 1.0.0 provenance — skip gate for them
        if args.suite not in FROZEN_PROOF_SUITES:
            try:
                from ..datasets.source_lock import load_source_lock as _ld3
                from ..config import load_datasets as _ld4
                _all_ds2 = _ld4()
                strata_ds2 = {str(s.get("dataset") or "") for s in (ptarget.strata or []) if s.get("dataset")}
                for ds_id in _DATASETS_BY_PROJECT.get(pid, []):
                    if strata_ds2 and ds_id not in strata_ds2:
                        continue
                    ds_cfg = _all_ds2.get(ds_id)
                    if ds_cfg is not None and not ds_cfg.enabled:
                        continue
                    try:
                        cur_lock2 = _ld3(ds_id)
                    except Exception:
                        continue
                    cf = (manifest.get("created_from") or {}).get(ds_id)
                    if not cf:
                        problems.append(f"{pid}: manifest missing created_from[{ds_id!r}] (re-run manifest build)")
                        continue
                    for k, attr in (("adapter_version", "adapter_version"), ("raw_sha256", "raw_sha256"), ("revision", "revision")):
                        cur_v = getattr(cur_lock2, attr, None)
                        cf_v = cf.get(k)
                        if cur_v and cf_v != cur_v:
                            problems.append(
                                f"{pid}: manifest created_from[{ds_id}].{k} {cf_v!r} != current lock {cur_v!r} "
                                f"(re-run manifest build after lock bump)"
                            )
            except Exception as _e2:
                problems.append(f"created_from gate error for {pid}: {_e2}")
        problems.extend(verify_manifest(manifest))
        # Phase 2.1: suite <-> manifest track consistency (review)
        m_track = str(manifest.get("benchmark_track") or "core").strip().lower() or "core"
        m_hl = bool(manifest.get("headline_eligible", m_track == "core"))
        # missing in old manifests => legacy core (backward-compat), but if present enforce
        if manifest.get("benchmark_track") is not None or manifest.get("headline_eligible") is not None:
            if m_track != ptarget.track:
                problems.append(f"{pid}: manifest benchmark_track {m_track!r} != suite track {ptarget.track!r}")
            if m_hl != ptarget.headline_eligible:
                problems.append(f"{pid}: manifest headline_eligible {m_hl!r} != suite headline_eligible {ptarget.headline_eligible!r}")
            if m_track == "extended" and m_hl:
                problems.append(f"{pid}: extended track cannot be headline_eligible=true")
    if problems:
        for p in problems:
            print(f"FAIL: {p}", file=sys.stderr)
        return 1
    print(f"OK: suite {args.suite} verified")
    return 0
