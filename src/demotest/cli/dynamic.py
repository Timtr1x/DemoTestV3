"""demotest dynamic — SkillLeakBench sandbox trace collector (guide P4 §26).

Subcommands:
  doctor    — environment gate: docker, pinned pipeline, image digest,
              optional official T3 self-test, credential-forwarding boundary
  snapshot  — freeze a skills directory into a pinned snapshot (per-skill SHA)
  collect   — run a frozen snapshot through the sandbox → raw traces + lock
  verify    — re-check snapshot + trace file hashes against trace_meta.json
"""
from __future__ import annotations

from ..datasets.dynamic.sandbox import SkillLeakBenchSandboxRunner
from ..datasets.dynamic.skillleak_collector import DynamicTraceCollector
from ..datasets.dynamic.snapshot import (
    SNAPSHOTS_ROOT,
    freeze_skill_snapshot,
    verify_snapshot,
)
from ..datasets.source_lock import load_source_lock
from ..core.exceptions import DatasetSourceError


def _runner() -> SkillLeakBenchSandboxRunner:
    try:
        lk = load_source_lock("skillleakbench_pipeline")
        revision = lk.revision
    except DatasetSourceError:
        revision = ""
    from ..config import get_dataset
    root = get_dataset("skillleakbench_pipeline").raw_path
    return SkillLeakBenchSandboxRunner(pipeline_root=root, pipeline_revision=revision)


def add_parser(sub) -> None:
    p = sub.add_parser("dynamic", help="SkillLeakBench dynamic sandbox trace collector (P4 Core)")
    sp = p.add_subparsers(dest="dynamic_cmd", required=True)

    doc = sp.add_parser("doctor", help="Check docker / pinned pipeline / image / T3 self-test")
    doc.add_argument("--self-test", action="store_true",
                     help="run the official T3 self-test (requires docker + bash)")
    doc.set_defaults(func=cmd_doctor)

    snap = sp.add_parser("snapshot", help="Freeze a skills directory into a pinned snapshot")
    snap.add_argument("--skills-dir", required=True)
    snap.add_argument("--created-at", default="")
    snap.set_defaults(func=cmd_snapshot)

    col = sp.add_parser("collect", help="Run a frozen snapshot through the sandbox")
    col.add_argument("--snapshot", required=True, help="snapshot id, e.g. snap-<hash12>")
    col.add_argument("--limit", type=int, default=None)
    col.add_argument("--condition", default="deterministic",
                     choices=["deterministic", "benign", "adversarial"])
    col.set_defaults(func=cmd_collect)

    ver = sp.add_parser("verify", help="Re-verify snapshot + trace hashes")
    ver.add_argument("--snapshot", required=True)
    ver.set_defaults(func=cmd_verify)


def cmd_doctor(args) -> int:
    runner = _runner()
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
    runner = _runner()
    # hard gate: sandbox environment must be green before touching real skills
    rep = runner.doctor_checks(with_self_test=False)
    if not rep.ok:
        for c in rep.checks:
            if c.required and not c.ok:
                print(f"[FAIL] {c.name}: {c.detail}")
        print("collect refused: `demotest dynamic doctor` must pass first")
        return 1
    collector = DynamicTraceCollector(runner=runner)
    report = collector.collect(
        snapshot_id=args.snapshot, limit=args.limit, condition=args.condition)
    print(f"[collect] snapshot={report.snapshot_id} skills={report.n_skills_attempted} "
          f"executions={report.n_executions} traces={report.n_traces} "
          f"(stdout={report.n_stdout_block} network={report.n_network_block} "
          f"allow={report.n_allow} unresolved={report.n_unresolved})")
    print(f"[collect] traces: {report.trace_file}")
    print(f"[collect] snapshot_sha256: {report.snapshot_sha256}")
    for prob in report.problems:
        print(f"[collect][warn] {prob}")
    return 0 if not report.problems else 1


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
