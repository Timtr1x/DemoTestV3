"""demotest analyze — compute metrics (plan §31)."""
from __future__ import annotations

import json
from pathlib import Path

from ..analysis import analyze
from ..cases import load_cases
from ..config import get_project
from ..paths import RESULTS_DIR
from ..storage.results import ResultStore


def add_parser(sub) -> None:
    p = sub.add_parser("analyze", help="Compute metrics from a result store")
    p.add_argument("--project", required=True)
    p.add_argument("--source", required=True, help="same source used in run")
    p.add_argument("--target", default="linemod")
    p.add_argument("--run-version", required=True)
    p.add_argument("--json", action="store_true", help="print full report as JSON")
    p.add_argument("--allow-legacy-run-without-meta", action="store_true",
                   help="allow old runs without _run_meta.json (default: fail-closed)")
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
    # Phase 2.1: shared resolver + mandatory provenance check for manifest-sourced runs
    from ..datasets.context import resolve_benchmark_context, verify_run_meta
    ctx = resolve_benchmark_context(args.source, project=args.project)
    try:
        verify_run_meta(base, ctx, expected_project=args.project, expected_target=args.target,
                        expected_run_version=args.run_version, allow_legacy=args.allow_legacy_run_without_meta)
    except Exception as e:
        print(f"FAIL: provenance check failed: {e}", flush=True)
        return 1
    rep = analyze(
        cases, store, project=args.project, run_id=args.run_version,
        target=args.target, thresholds=project.thresholds, caveats=project.caveats,
        benchmark_track=ctx.benchmark_track, headline_eligible=ctx.headline_eligible,
        manifest_name=ctx.manifest_path or args.source,
    )
    if args.json:
        print(json.dumps(rep.to_dict(), ensure_ascii=False, indent=2, default=str))
    else:
        m = rep.metrics
        print(f"project={args.project} run={args.run_version} target={args.target}")
        print(f"  n_judged={m.n_judged}/{rep.n_total} unjudged={m.n_unjudged}")
        print(f"  TP={m.tp} FP={m.fp} TN={m.tn} FN={m.fn}")
        print(f"  TPR={m.tpr} FPR={m.fpr} pass_fail={rep.pass_fail}")
        if m.by_channel:
            print("  by_channel:")
            for ch, g in sorted(m.by_channel.items()):
                print(f"    {ch}: n={g['n_judged']} TPR={g['tpr']}")
        print(f"  track={rep.benchmark_track} headline_eligible={rep.headline_eligible} manifest={rep.manifest_name}")
    return 0
