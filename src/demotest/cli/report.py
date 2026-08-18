"""demotest report — write SUMMARY.md (plan §53)."""
from __future__ import annotations

from pathlib import Path

from ..analysis import analyze
from ..cases import load_cases
from ..config import get_project
from ..paths import REPORTS_DIR, RESULTS_DIR
from ..reporting.markdown import write_markdown
from ..storage.results import ResultStore
from .analyze import run as _analyze  # reuse merging logic


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
    stores = sorted(base.glob("*.jsonl"))
    combined = base / "_combined.jsonl"
    combined.write_text("", encoding="utf-8")
    store = ResultStore(combined)
    from ..core.contracts import CaseResult
    for sf in stores:
        for row in ResultStore(sf).load():
            store.append(CaseResult.from_dict(row))
    rep = analyze(
        cases, store, project=args.project, run_id=args.run_version,
        target=args.target, thresholds=project.thresholds, caveats=project.caveats,
        manifest_name=args.source,
    )
    out_dir = Path(args.out_dir) if args.out_dir else (REPORTS_DIR / args.project / args.run_version)
    p = write_markdown(rep, out_dir)
    print(f"[report] wrote {p}")
    return 0
