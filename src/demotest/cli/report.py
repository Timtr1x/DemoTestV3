"""demotest report — write SUMMARY.md (plan §53)."""
from __future__ import annotations

import json
from pathlib import Path

from ..analysis import analyze
from ..cases import load_cases
from ..config import get_project
from ..paths import REPORTS_DIR, RESULTS_DIR
from ..reporting.markdown import write_markdown
from ..storage.results import ResultStore


def add_parser(sub) -> None:
    p = sub.add_parser("report", help="Write SUMMARY.md")
    p.add_argument("--project", required=True)
    p.add_argument("--source", required=True)
    p.add_argument("--target", default="linemod")
    p.add_argument("--run-version", required=True)
    p.add_argument("--out-dir", default=None)
    p.set_defaults(func=run)


def run(args) -> int:
    project = get_project(args.project)
    cases = load_cases(args.source, project=args.project)
    base = RESULTS_DIR / args.project / args.target / args.run_version
    stores = sorted(p for p in base.glob("*.jsonl") if not p.name.startswith("_"))
    if not stores:
        print(f"no result files at {base}")
        return 1
    combined = base / "_combined.jsonl"
    combined.write_text("", encoding="utf-8")
    store = ResultStore(combined)
    from ..core.contracts import CaseResult
    for sf in stores:
        for row in ResultStore(sf).load():
            store.append(CaseResult.from_dict(row))
    # Use the SAME resolver as analyze — P0 fix: report must not default to core
    from ..datasets.context import resolve_benchmark_context
    ctx = resolve_benchmark_context(args.source, project=args.project)
    try:
        meta_path = base / "_run_meta.json"
        if meta_path.exists():
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            exp_sha = meta.get("manifest_sha256")
            if exp_sha and ctx.manifest_sha256 and exp_sha != ctx.manifest_sha256:
                print(f"FAIL: manifest SHA mismatch: run meta {exp_sha} != --source {ctx.manifest_sha256}")
                return 1
    except Exception:
        pass
    rep = analyze(
        cases, store, project=args.project, run_id=args.run_version,
        target=args.target, thresholds=project.thresholds, caveats=project.caveats,
        benchmark_track=ctx.benchmark_track, headline_eligible=ctx.headline_eligible,
        manifest_name=ctx.manifest_path or args.source,
    )
    out_dir = Path(args.out_dir) if args.out_dir else (REPORTS_DIR / args.project / args.run_version)
    p = write_markdown(rep, out_dir)
    print(f"[report] wrote {p} track={rep.benchmark_track} headline_eligible={rep.headline_eligible}")
    return 0
