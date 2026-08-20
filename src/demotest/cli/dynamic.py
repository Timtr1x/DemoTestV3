"""demotest dynamic — SkillLeakBench sandbox trace collector (guide P4 §26).

Subcommands:
  doctor           — environment gate: docker, pinned pipeline, image digest,
                     optional official T3 self-test, credential-forwarding boundary
  candidates ...   — P4 candidate intake: import-local / import-skillsmp / verify / materialize
  snapshot         — freeze a skills directory into a pinned snapshot (per-skill SHA)
  collect          — run a frozen snapshot through the sandbox → raw traces + lock (deterministic Core only)
  agent-collect    — Host-side AgentDriver differential (benign/adversarial, Extended)
  review-export    — export review.jsonl from traces.jsonl
  review-apply     — apply a human-edited review file → reviewed_traces.jsonl + status
  review-status    — summarize review coverage for the current raw_dir
  verify           — re-check snapshot + trace file hashes against trace_meta.json
"""
from __future__ import annotations

import json
from pathlib import Path

from ..datasets.dynamic.candidates import (
    CANDIDATES_ROOT,
    import_local_candidates,
    import_skillsmp_candidates,
    load_candidate_meta,
    load_candidates,
    materialize_candidates,
    verify_candidates,
)
from ..datasets.dynamic.sandbox import SkillLeakBenchSandboxRunner
from ..datasets.dynamic.skillleak_collector import DynamicTraceCollector
from ..datasets.dynamic.snapshot import (
    SNAPSHOTS_ROOT,
    freeze_skill_snapshot,
    verify_snapshot,
)
from ..datasets.source_lock import load_source_lock
from ..core.exceptions import DatasetSourceError


def _runner(args=None) -> SkillLeakBenchSandboxRunner:
    try:
        lk = load_source_lock("skillleakbench_pipeline")
        revision = lk.revision
    except DatasetSourceError:
        revision = ""
    from ..config import get_dataset
    root = get_dataset("skillleakbench_pipeline").raw_path
    return SkillLeakBenchSandboxRunner(
        pipeline_root=root, pipeline_revision=revision,
        memory=getattr(args, "memory", "512m"),
        cpus=getattr(args, "cpus", "0.5"),
        pids_limit=getattr(args, "pids_limit", 64),
        timeout_s=getattr(args, "timeout_s", 120),
    )


def _add_sandbox_args(p) -> None:
    p.add_argument("--memory", default="512m", help="per-container memory limit")
    p.add_argument("--cpus", default="0.5", help="per-container CPU quota")
    p.add_argument("--pids-limit", type=int, default=64, help="per-container PID limit")
    p.add_argument("--timeout-s", type=int, default=120, help="per-skill wall-clock timeout")


def add_parser(sub) -> None:
    p = sub.add_parser("dynamic", help="SkillLeakBench dynamic sandbox trace collector (P4 Core)")
    sp = p.add_subparsers(dest="dynamic_cmd", required=True)

    doc = sp.add_parser("doctor", help="Check docker / pinned pipeline / image / T3 self-test")
    doc.add_argument("--self-test", action="store_true",
                     help="run the official T3 self-test (requires docker + bash)")
    _add_sandbox_args(doc)
    doc.set_defaults(func=cmd_doctor)

    # -- P4 candidate pool (D1/D2) --
    cand = sp.add_parser("candidates", help="P4 candidate intake (import / verify / materialize)")
    cand_sp = cand.add_subparsers(dest="candidates_cmd", required=True)

    imp_local = cand_sp.add_parser("import-local", help="Import real Skills from a local directory")
    imp_local.add_argument("--skills-dir", required=True, help="dir whose immediate sub-dirs are Skills")
    imp_local.add_argument("--source-revision", default="", help="provenance revision for this import")
    imp_local.add_argument("--pool-root", default=str(CANDIDATES_ROOT), help="candidate pool root")
    imp_local.set_defaults(func=cmd_candidates_import_local)

    imp_smp = cand_sp.add_parser("import-skillsmp", help="Import from a SkillsMP crawl output dir")
    imp_smp.add_argument("--source", required=True, dest="crawl_dir", help="crawl output dir")
    imp_smp.add_argument("--source-revision", default="")
    imp_smp.add_argument("--pool-root", default=str(CANDIDATES_ROOT))
    imp_smp.set_defaults(func=cmd_candidates_import_skillsmp)

    cand_ver = cand_sp.add_parser("verify", help="Static pre-check of the candidate pool (no execution)")
    cand_ver.add_argument("--pool-root", default=str(CANDIDATES_ROOT))
    cand_ver.set_defaults(func=cmd_candidates_verify)

    cand_mat = cand_sp.add_parser("materialize", help="Deterministically materialize a subset for snapshot")
    cand_mat.add_argument("--dest-dir", required=True, help="output skills dir for demotest dynamic snapshot")
    cand_mat.add_argument("--limit", type=int, default=None, help="max Skills to materialize")
    cand_mat.add_argument("--offset", type=int, default=0, help="offset into ranked order")
    cand_mat.add_argument("--seed", type=int, default=42, help="selection seed")
    cand_mat.add_argument("--pool-root", default=str(CANDIDATES_ROOT))
    cand_mat.add_argument("--include-rejected", action="store_true",
                          help="also materialize REJECT_* candidates (audit only, not for snapshot)")
    cand_mat.add_argument("--clean-dest", action="store_true",
                          help="allow non-empty dest by cleaning first (default: refuse if not empty)")
    cand_mat.add_argument("--require-runtime-ready", action="store_true",
                          help="P4 deterministic Core: only RUNTIME_READY (explicit entry_command)")
    cand_mat.set_defaults(func=cmd_candidates_materialize)

    snap = sp.add_parser("snapshot", help="Freeze a skills directory into a pinned snapshot")
    snap.add_argument("--skills-dir", required=True)
    snap.add_argument("--created-at", default="")
    snap.set_defaults(func=cmd_snapshot)

    col = sp.add_parser("collect", help="Run a frozen snapshot through the sandbox (deterministic Core)")
    col.add_argument("--snapshot", required=True, help="snapshot id, e.g. snap-<hash12>")
    col.add_argument("--offset", type=int, default=0,
                     help="0-based index into the frozen skill snapshot")
    col.add_argument("--limit", type=int, default=10,
                     help="skills selected in this serial batch (default: 10)")
    col.add_argument("--condition", default="deterministic",
                     choices=["deterministic"])
    _add_sandbox_args(col)
    col.set_defaults(func=cmd_collect)

    aco = sp.add_parser("agent-collect", help="Host-side AgentDriver differential (Extended, non-headline)")
    aco.add_argument("--snapshot", required=True, help="snapshot id")
    aco.add_argument("--offset", type=int, default=0)
    aco.add_argument("--limit", type=int, default=10)
    aco.add_argument("--condition", default="benign", choices=["benign", "adversarial"])
    aco.add_argument("--rounds", type=int, default=3, help="agent rounds per skill")
    _add_sandbox_args(aco)
    aco.set_defaults(func=cmd_agent_collect)

    re_exp = sp.add_parser("review-export", help="Export review.jsonl from traces.jsonl")
    re_exp.add_argument("--raw-dir", default="", help="dynamic raw dir (default: credential_dynamic_traces)")
    re_exp.set_defaults(func=cmd_review_export)

    re_app = sp.add_parser("review-apply", help="Apply a human-edited review file")
    re_app.add_argument("--review", required=True, help="path to human-edited review.jsonl")
    re_app.add_argument("--raw-dir", default="")
    re_app.set_defaults(func=cmd_review_apply)

    re_sta = sp.add_parser("review-status", help="Review coverage summary")
    re_sta.add_argument("--raw-dir", default="")
    re_sta.set_defaults(func=cmd_review_status)

    re_fr = sp.add_parser("freeze-reviewed", help="Freeze reviewed traces (accepted only) — DEV gate")
    re_fr.add_argument("--raw-dir", default="")
    re_fr.set_defaults(func=cmd_freeze_reviewed)

    ver = sp.add_parser("verify", help="Re-verify snapshot + trace hashes")
    ver.add_argument("--snapshot", required=True)
    ver.set_defaults(func=cmd_verify)


def cmd_doctor(args) -> int:
    runner = _runner(args)
    rep = runner.doctor_checks(with_self_test=bool(args.self_test))
    for c in rep.checks:
        mark = "PASS" if c.ok else ("FAIL" if c.required else "SKIP")
        print(f"[{mark}] {c.name}: {c.detail}")
    if not args.self_test:
        print("[SKIP] t3 self-test (pass --self-test to run the official fixtures)")
    if not rep.ok:
        print("doctor: NOT READY — fix the FAILed checks before `dynamic collect`")
        return 1
    print("doctor: ready")
    return 0


# -- candidates (D1/D2) ----------------------------------------------------

def cmd_candidates_import_local(args) -> int:
    try:
        m = import_local_candidates(
            args.skills_dir,
            dest_root=args.pool_root,
            source_revision=args.source_revision,
        )
    except Exception as e:
        print(f"[FAIL] import-local: {e}")
        return 1
    print(f"[candidates] local_import -> {args.pool_root}  set={m.candidate_set_id} "
          f"count={m.count} accepted={m.accepted_count} rejected={m.rejected_count}")
    return 0


def cmd_candidates_import_skillsmp(args) -> int:
    try:
        m = import_skillsmp_candidates(
            args.crawl_dir,
            dest_root=args.pool_root,
            source_revision=args.source_revision,
        )
    except Exception as e:
        print(f"[FAIL] import-skillsmp: {e}")
        return 1
    print(f"[candidates] skillsmp -> {args.pool_root}  set={m.candidate_set_id} "
          f"count={m.count} accepted={m.accepted_count} rejected={m.rejected_count}")
    return 0


def cmd_candidates_verify(args) -> int:
    problems = verify_candidates(args.pool_root)
    if not problems:
        try:
            meta = load_candidate_meta(args.pool_root)
            cands = load_candidates(args.pool_root)
            print(f"[candidates] verify OK: set={meta.candidate_set_id} count={len(cands)} "
                  f"accepted={meta.accepted_count} rejected={meta.rejected_count}")
        except Exception as e:
            print(f"[FAIL] {e}")
            return 1
        return 0
    for p in problems:
        print(f"[FAIL] {p}")
    print(f"[candidates] verify: {len(problems)} problem(s)")
    return 1


def cmd_candidates_materialize(args) -> int:
    try:
        # Gate: pool must verify before we hand anything to snapshot
        problems = verify_candidates(args.pool_root)
        if problems:
            for p in problems:
                print(f"[FAIL] {p}")
            print("[candidates] materialize refused: pool has problems — fix verify first")
            return 1
        selected = materialize_candidates(
            pool_root=args.pool_root,
            dest_dir=args.dest_dir,
            limit=args.limit,
            offset=args.offset,
            seed=args.seed,
            include_rejected=bool(args.include_rejected),
            require_runtime_ready=bool(getattr(args, "require_runtime_ready", False)),
            clean_dest=bool(getattr(args, "clean_dest", False)),
        )
    except Exception as e:
        print(f"[FAIL] materialize: {e}")
        return 1
    print(f"[candidates] materialized {len(selected)} Skills -> {args.dest_dir} "
          f"(offset={args.offset} limit={args.limit} seed={args.seed})")
    for c in selected[:20]:
        print(f"  - {c.skill_id} [{c.reject_reason}] {c.local_path}")
    if len(selected) > 20:
        print(f"  ... and {len(selected) - 20} more")
    return 0


def cmd_snapshot(args) -> int:
    runner = _runner()
    manifest = freeze_skill_snapshot(
        args.skills_dir,
        pipeline_revision=runner.pipeline_revision,
        created_at=args.created_at,
    )
    print(f"[snapshot] {manifest.snapshot_id}: {len(manifest.skills)} skills, "
          f"archive_sha256={manifest.archive_sha256[:16]}...")
    print(f"[snapshot] frozen at {SNAPSHOTS_ROOT / manifest.snapshot_id}")
    return 0


def cmd_collect(args) -> int:
    if args.condition != "deterministic":
        print("collect: only --condition deterministic is allowed for P4 Core; use agent-collect for benign/adversarial")
        return 1
    runner = _runner(args)
    # hard gate: sandbox environment must be green before touching real skills
    rep = runner.doctor_checks(with_self_test=False)
    if not rep.ok:
        for c in rep.checks:
            if c.required and not c.ok:
                print(f"[FAIL] {c.name}: {c.detail}")
        print("collect refused: `demotest dynamic doctor` must pass first")
        return 1
    collector = DynamicTraceCollector(runner=runner)
    try:
        report = collector.collect(
            snapshot_id=args.snapshot, offset=args.offset, limit=args.limit,
            condition=args.condition)
    except RuntimeError as e:
        print(f"collect refused: {e}")
        return 1
    print(f"[collect] snapshot={report.snapshot_id} offset={report.offset} limit={report.limit} "
          f"selected={report.n_skills_selected} attempted={report.n_skills_attempted} "
          f"skipped_existing={report.n_skills_skipped_existing} "
          f"executions={report.n_executions} traces={report.n_traces} "
          f"(stdout={report.n_stdout_block} network={report.n_network_block} "
          f"allow={report.n_allow} unresolved={report.n_unresolved})")
    print(f"[collect] traces: {report.trace_file}")
    print(f"[collect] snapshot_sha256: {report.snapshot_sha256}")
    for prob in report.problems:
        print(f"[collect][warn] {prob}")
    return 0 if not report.problems else 1


def cmd_agent_collect(args) -> int:
    """Extended Agent-driven differential — real API key stays on Host."""
    runner = _runner(args)
    rep = runner.doctor_checks(with_self_test=False)
    if not rep.ok:
        for c in rep.checks:
            if c.required and not c.ok:
                print(f"[FAIL] {c.name}: {c.detail}")
        print("agent-collect refused: `demotest dynamic doctor` must pass first")
        return 1
    # Import lazily so Core never depends on agent deps
    from ..datasets.dynamic.agents import OpenAICompatibleAgentDriver
    from ..datasets.dynamic.agents.models import AgentConfig
    driver = OpenAICompatibleAgentDriver(AgentConfig(
        model=getattr(args, "model", "") or "",
    ))
    print(f"[agent-collect] snapshot={args.snapshot} condition={args.condition} rounds={args.rounds}")
    print(f"[agent-collect] driver provenance: {driver.provenance}")
    print("[agent-collect] Extended / non-headline — not yet wired to sandbox differential (scaffold ready)")
    # Scaffold: full differential wiring (multi-round benign/adversarial) is
    # staged for the next commit so P4 deterministic Core stays shippable.
    return 0


# -- review (D3) -----------------------------------------------------------

def _resolve_raw_dir(arg_raw_dir: str) -> Path:
    if arg_raw_dir:
        return Path(arg_raw_dir)
    # default: credential_dynamic_traces raw_dir from config
    from ..config import get_dataset
    return get_dataset("credential_dynamic_traces").raw_path


def cmd_review_export(args) -> int:
    raw_dir = _resolve_raw_dir(args.raw_dir)
    trace_path = raw_dir / "traces.jsonl"
    if not trace_path.exists():
        print(f"[FAIL] traces.jsonl not found: {trace_path}")
        return 1
    import json as _json
    from ..datasets.traces.models import CredentialTrace
    from ..datasets.dynamic.review import export_reviews
    traces = []
    for raw in trace_path.read_text(encoding="utf-8").splitlines():
        if raw.strip():
            traces.append(CredentialTrace.from_dict(_json.loads(raw)))
    out = export_reviews(traces, raw_dir=raw_dir)
    print(f"[review-export] {len(traces)} traces -> {out}")
    return 0


def cmd_review_apply(args) -> int:
    raw_dir = _resolve_raw_dir(args.raw_dir)
    trace_path = raw_dir / "traces.jsonl"
    if not trace_path.exists():
        print(f"[FAIL] traces.jsonl not found: {trace_path}")
        return 1
    import json as _json
    from ..datasets.traces.models import CredentialTrace
    from ..datasets.dynamic.review import (
        apply_reviews,
        freeze_reviewed_traces,
        load_reviews_from_file,
        review_status_summary,
    )
    traces = []
    for raw in trace_path.read_text(encoding="utf-8").splitlines():
        if raw.strip():
            traces.append(CredentialTrace.from_dict(_json.loads(raw)))
    try:
        reviews = load_reviews_from_file(args.review)
    except Exception as e:
        print(f"[FAIL] load review file: {e}")
        return 1
    accepted, problems = apply_reviews(traces, reviews)
    if problems:
        for p in problems:
            print(f"[FAIL] {p}")
        print(f"[review-apply] {len(problems)} problem(s) — fix the review file")
        return 1
    meta = freeze_reviewed_traces(accepted, raw_dir=raw_dir, reviews=reviews)
    summary = review_status_summary(traces, reviews)
    print(f"[review-apply] accepted={len(accepted)}/{len(traces)}  "
          f"rejected={summary['by_status']['REJECTED']}  pending={summary['pending']}")
    print(f"[review-apply] reviewed traces -> {raw_dir / 'reviews' / 'reviewed_traces.jsonl'}  sha={meta['sha256'][:16]}...")
    return 0


def cmd_review_status(args) -> int:
    raw_dir = _resolve_raw_dir(args.raw_dir)
    trace_path = raw_dir / "traces.jsonl"
    if not trace_path.exists():
        print(f"[FAIL] traces.jsonl not found: {trace_path}")
        return 1
    import json as _json
    from ..datasets.traces.models import CredentialTrace
    from ..datasets.dynamic.review import load_reviews, review_status_summary
    traces = []
    for raw in trace_path.read_text(encoding="utf-8").splitlines():
        if raw.strip():
            traces.append(CredentialTrace.from_dict(_json.loads(raw)))
    reviews = load_reviews(raw_dir)
    summary = review_status_summary(traces, reviews)
    print(f"[review-status] total={summary['total_traces']}  "
          f"accepted={summary['accepted']}  rejected={summary['rejected']}  pending={summary['pending']}")
    for k, v in summary["by_status"].items():
        print(f"  {k}: {v}")
    # also report reviewed_traces artifact state
    rt = raw_dir / "reviews" / "reviewed_traces.jsonl"
    rm = raw_dir / "reviews" / "review_meta.json"
    if rt.exists() and rm.exists():
        meta = _json.loads(rm.read_text(encoding="utf-8"))
        print(f"  reviewed_traces: {meta.get('n_accepted')}  sha={meta.get('sha256','')[:16]}...")
    return 0


def cmd_freeze_reviewed(args) -> int:
    raw_dir = _resolve_raw_dir(args.raw_dir)
    rt = raw_dir / "reviews" / "reviewed_traces.jsonl"
    rm = raw_dir / "reviews" / "review_meta.json"
    trace_path = raw_dir / "traces.jsonl"
    meta_path = raw_dir / "trace_meta.json"
    review_path = raw_dir / "reviews" / "review.jsonl"
    if not rt.exists() or not rm.exists():
        print(f"[FAIL] freeze-reviewed requires an accepted review first: run `review-export` then `review-apply`")
        return 1
    import json as _json
    import hashlib as _hl
    meta = _json.loads(rm.read_text(encoding="utf-8"))
    n = meta.get("n_accepted", 0)
    if n == 0:
        print("[FAIL] freeze-reviewed: no accepted traces — need at least one accepted trace")
        return 1
    # Pending must be zero — every trace must have been verdict'd
    # Count pending from the live review.jsonl (source of truth)
    try:
        from ..datasets.dynamic.review import load_reviews as _load_rev
        from ..datasets.traces.models import CredentialTrace as _CT
        traces = []
        if trace_path.exists():
            for raw in trace_path.read_text(encoding="utf-8").splitlines():
                if raw.strip():
                    traces.append(_CT.from_dict(_json.loads(raw)))
        revs = _load_rev(raw_dir)
        from ..datasets.dynamic.review import review_status_summary as _summ
        summ = _summ(traces, revs) if traces else {"pending": 0}
        if summ.get("pending", 0) > 0:
            print(f"[FAIL] freeze-reviewed: pending={summ['pending']} — all traces must be ACCEPTED/REJECTED first")
            return 1
    except Exception as e:
        print(f"[FAIL] freeze-reviewed pending check failed: {e}")
        return 1
    # Hash binding — reviewed artifact must match current source hashes
    try:
        current_trace_sha = _hl.sha256(trace_path.read_bytes()).hexdigest() if trace_path.exists() else ""
        current_meta_sha = _hl.sha256(meta_path.read_bytes()).hexdigest() if meta_path.exists() else ""
        current_rt_sha = _hl.sha256(rt.read_bytes()).hexdigest()
        if meta.get("source_trace_sha256") and meta.get("source_trace_sha256") != current_trace_sha:
            print(f"[FAIL] freeze-reviewed: source traces.jsonl drift (meta {meta.get('source_trace_sha256','')[:12]} != current {current_trace_sha[:12]})")
            return 1
        if meta.get("source_trace_meta_sha256") and meta.get("source_trace_meta_sha256") != current_meta_sha:
            print(f"[FAIL] freeze-reviewed: source trace_meta.json drift")
            return 1
        if meta.get("sha256") != current_rt_sha:
            print(f"[FAIL] freeze-reviewed: reviewed_traces.jsonl drift (meta {meta.get('sha256','')[:12]} != actual {current_rt_sha[:12]})")
            return 1
        # verdict hash must match current review.jsonl
        if review_path.exists():
            rev_blob = "\n".join(_json.dumps(r.to_dict(), sort_keys=True) for r in sorted(revs, key=lambda x: x.trace_id))
            cur_verdict_sha = _hl.sha256(rev_blob.encode()).hexdigest()
            if meta.get("verdict_sha256") and meta.get("verdict_sha256") != cur_verdict_sha:
                print(f"[FAIL] freeze-reviewed: verdicts drift — re-run review-apply")
                return 1
    except Exception as e:
        print(f"[FAIL] freeze-reviewed hash binding failed: {e}")
        return 1
    print(f"[freeze-reviewed] DEV gate OK: {n} accepted traces  sha={meta.get('sha256','')[:16]}...")
    print(f"  -> Next: after blind review freeze p4-dynamic-dev-v1 (adhoc, non-headline) before LineMod.")
    return 0


def cmd_verify(args) -> int:
    problems = verify_snapshot(args.snapshot)

    raw_dir = DynamicTraceCollector(runner=_runner()).raw_dir
    meta_path = raw_dir / "trace_meta.json"
    trace_path = raw_dir / "traces.jsonl"
    if not meta_path.exists() or not trace_path.exists():
        print(f"[FAIL] trace artifacts missing under {raw_dir}")
        return 1
    import json as _json
    meta = _json.loads(meta_path.read_text(encoding="utf-8"))
    if meta.get("snapshot_id") != args.snapshot:
        problems.append(
            f"trace_meta snapshot_id {meta.get('snapshot_id')} != {args.snapshot}")
    from ..datasets.dynamic.schemas import trace_snapshot_sha256
    actual = trace_snapshot_sha256(trace_path.read_bytes())
    if actual != meta.get("snapshot_sha256"):
        problems.append(
            f"trace file sha drift: meta={meta.get('snapshot_sha256')} actual={actual}")
    # re-verify every row's full-event trace_hash (guide §8)
    from ..datasets.dynamic.schemas import canonical_trace_hash
    from ..datasets.traces.models import CredentialTrace
    for lineno, raw in enumerate(trace_path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        tr = CredentialTrace.from_dict(_json.loads(line))
        m = tr.metadata or {}
        recomputed = canonical_trace_hash(
            skill_snapshot_sha256=str(m.get("skill_snapshot_sha256") or ""),
            execution_condition=str(m.get("execution_condition") or ""),
            credential_marker=tr.credential_marker,
            sink=tr.sink,
            canonical_payload=tr.payload,
            destination=tr.destination,
            sandbox_image_digest=str(m.get("sandbox_image_digest") or ""),
            pipeline_revision=str(m.get("pipeline_revision") or ""),
        )
        if recomputed != tr.trace_hash:
            problems.append(f"line {lineno} trace {tr.trace_id}: trace_hash mismatch")
    if problems:
        for p in problems:
            print(f"[FAIL] {p}")
        print(f"verify: {len(problems)} problem(s)")
        return 1
    print(f"verify: OK (snapshot={args.snapshot}, traces sha={actual[:16]}...)")
    return 0
