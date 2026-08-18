"""demotest compare — compare the same cases across two targets (plan §38)."""
from __future__ import annotations

import json
from pathlib import Path

from ..analysis import compare_runs
from ..cases import load_cases
from ..paths import RESULTS_DIR
from ..storage.results import ResultStore


def add_parser(sub) -> None:
    p = sub.add_parser("compare", help="Compare the same cases across two run-version/targets")
    p.add_argument("--project", required=True)
    p.add_argument("--source", required=True)
    p.add_argument("--run-a", required=True, help="target/run-version for side A, e.g. linemod/v1")
    p.add_argument("--run-b", required=True, help="target/run-version for side B")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=run)


def _load_combined(base: Path) -> Path:
    stores = sorted(base.glob("*.jsonl"))
    combined = base / "_combined_cmp.jsonl"
    combined.write_text("", encoding="utf-8")
    store = ResultStore(combined)
    from ..core.contracts import CaseResult
    for sf in stores:
        for row in ResultStore(sf).load():
            store.append(CaseResult.from_dict(row))
    return combined


def run(args) -> int:
    cases = load_cases(args.source, project=args.project)
    a_parts = args.run_a.split("/", 1)
    b_parts = args.run_b.split("/", 1)
    if len(a_parts) != 2 or len(b_parts) != 2:
        print("use --run-a <target>/<run-version> --run-b <target>/<run-version>")
        return 2
    base_a = RESULTS_DIR / args.project / a_parts[0] / a_parts[1]
    base_b = RESULTS_DIR / args.project / b_parts[0] / b_parts[1]
    sa = _load_combined(base_a)
    sb = _load_combined(base_b)
    out = compare_runs(cases, {"A": sa, "B": sb}, project=args.project)
    if args.json:
        print(json.dumps(out, ensure_ascii=False, indent=2, default=str))
    else:
        print(f"divergent outcomes: {out['n_divergent']}")
        for cid, vals in list(out["divergent"].items())[:20]:
            print(f"  {cid}: A={vals.get('A')} B={vals.get('B')}")
    return 0
