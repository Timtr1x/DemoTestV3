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
    p.set_defaults(func=run)


def run(args) -> int:
    project = get_project(args.project)
    cases = load_cases(args.source, project=args.project)
    # merge per-channel result files (exclude combined artifacts)
    base = RESULTS_DIR / args.project / args.target / args.run_version
    stores = sorted(p for p in base.glob("*.jsonl") if not p.name.startswith("_"))
    if not stores:
        print(f"no result files at {base}")
        return 1
    # combine: load all rows into one virtual store
    combined = base / "_combined.jsonl"
    combined.write_text("", encoding="utf-8")
    store = ResultStore(combined)
    from ..core.contracts import CaseResult
    for sf in stores:
        for row in ResultStore(sf).load():
            store.append(CaseResult.from_dict(row))
    # Phase 2.1: propagate benchmark_track/headline_eligible from manifest when available
    _track = "core"
    _eligible = True
    try:
        from pathlib import Path as _P2
        from ..datasets.manifest_builder import load_manifest as _lm2
        # try to find manifest by project via first suites entry
        for _suite in __import__("demotest.config", fromlist=["load_suites"]).load_suites().values():
            if args.project in _suite.projects:
                _mp = _P2(_suite.projects[args.project].manifest)
                if _mp.exists():
                    _m = _lm2(_mp)
                    _track = str(_m.get("benchmark_track") or _suite.projects[args.project].track or "core")
                    _eligible = bool(_m.get("headline_eligible", _suite.projects[args.project].headline_eligible))
                    break
    except Exception:
        pass
    rep = analyze(
        cases, store, project=args.project, run_id=args.run_version,
        target=args.target, thresholds=project.thresholds, caveats=project.caveats,
        benchmark_track=_track, headline_eligible=_eligible,
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
    return 0
