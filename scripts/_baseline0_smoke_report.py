"""Baseline-0 real-smoke report (Phase 1.5 GO round).

Usage:
    python scripts/_baseline0_smoke_report.py <project> <manifest> <run-version>

Prints the review table requested for the Smoke STOP gate: official
analyzer confusion matrix + transport noise + latency distribution, and for
P2_tool_action the three decisive numbers —
    attack_implementing TPR / contextual_read(off-task) TPR / authorized ALLOW FPR.
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from demotest.analysis.analyzer import analyze  # noqa: E402
from demotest.cases import load_frozen_manifest_cases  # noqa: E402


def _pct(vals: list[int], p: float) -> float:
    if not vals:
        return float("nan")
    s = sorted(vals)
    k = (len(s) - 1) * p
    f, c = int(k), min(int(k) + 1, len(s) - 1)
    return float(s[f] if f == c else s[f] + (s[c] - s[f]) * (k - f))


def main() -> int:
    project, manifest, run_version = sys.argv[1], Path(sys.argv[2]), sys.argv[3]
    cases = load_frozen_manifest_cases(str(manifest), project=project)
    run_dir = ROOT / "cache" / "results_v3" / project / "linemod" / run_version
    rep = analyze(
        list(cases), run_dir / "_combined.jsonl",
        project=project, run_id=run_version, target="linemod",
        benchmark_track="core", headline_eligible=False,
    )
    m = rep.metrics
    print(f"=== {project} run={run_version} ===")
    print(f"n_total={rep.n_total} n_judged={m.n_judged} unjudged={m.n_unjudged} "
          f"cooldown={m.n_cooldown}")
    print(f"TP={m.tp} FN={m.fn} TN={m.tn} FP={m.fp} "
          f"TPR={m.tpr} FPR={m.fpr}")

    # raw-record taxonomy -------------------------------------------------
    recs = []
    for line in (run_dir / "_combined.jsonl").read_text(encoding="utf-8").splitlines():
        recs.append(json.loads(line))
    lat = [r["latency_ms"] for r in recs if isinstance(r.get("latency_ms"), int)]
    http = Counter(r.get("http_status") for r in recs)
    outcomes = Counter(r.get("outcome") for r in recs)
    scanners = Counter(r.get("scanner") for r in recs if r.get("outcome") == "blocked")
    policies = Counter(r.get("policy") for r in recs if r.get("outcome") == "blocked")
    print(f"records={len(recs)} latency_ms p50={_pct(lat, .5):.0f} "
          f"p90={_pct(lat, .9):.0f} p99={_pct(lat, .99):.0f} max={max(lat) if lat else '-'}")
    print(f"http_status: {dict(http)}")
    err5xx = sum(v for k, v in http.items() if isinstance(k, int) and k >= 500)
    print(f"transport noise: 429={http.get(429, 0)} 5xx={err5xx} "
          f"error_outcome={outcomes.get('error', 0)} "
          f"rate_limited={outcomes.get('rate_limited', 0)} "
          f"cooldown={outcomes.get('upstream_cooldown', 0)}")
    print(f"blocked scanner dist: {dict(scanners)}")
    print(f"blocked policy dist: {dict(policies)}")

    # per-project breakdowns from MANIFEST-RESOLVED cases (pinned provenance:
    # immune to future normalized rebuilds, unlike reading cache snapshots) ---
    case_meta = {}
    for c in cases:
        md = dict(c.metadata or {})
        md["_expected"] = c.expected_action.value
        md["presentation_style"] = c.presentation_style
        case_meta[c.case_id] = md
    if project == "P2_tool_action":
        agg: Counter = Counter()
        for r in recs:
            md = case_meta.get(r["case_id"]) or {}
            kind, cls = md.get("ground_truth_kind"), md.get("attack_step_class")
            blocked = r.get("outcome") == "blocked"
            if (kind, cls) == ("injection_attack", "attack_implementing"):
                agg["ai_block" if blocked else "ai_pass"] += 1
            elif (kind, cls) == ("injection_attack", "contextual_read"):
                agg["cr_block" if blocked else "cr_pass"] += 1
            elif kind == "user_authorized":
                agg["au_block" if blocked else "au_pass"] += 1

        def tpr(b, p):
            d = b + p
            return f"{b}/{d} = {b / d:.2%}" if d else "n/a"

        print("--- P2 decision numbers ---")
        print(f"attack_implementing TPR : {tpr(agg['ai_block'], agg['ai_pass'])}")
        print(f"contextual_read   TPR : {tpr(agg['cr_block'], agg['cr_pass'])}")
        print(f"authorized ALLOW FPR  : {tpr(agg['au_block'], agg['au_pass'])}")
    elif project == "P1_external_instruction":
        for field in ("label_source", "presentation_style", "source_phase"):
            rows: dict[str, list[tuple[bool, str]]] = {}
            for r in recs:
                md = case_meta.get(r["case_id"]) or {}
                key = str(md.get(field) or "<none>")
                rows.setdefault(key, []).append(
                    (r.get("outcome") == "blocked", str(md.get("_expected"))))
            print(f"--- P1 by {field} ---")
            for key in sorted(rows):
                blk = sum(1 for b, _ in rows[key] if b)
                atk = sum(1 for _, ea in rows[key] if ea == "block")
                n = len(rows[key])
                t = sum(1 for b, ea in rows[key] if b and ea == "block")
                f = sum(1 for b, ea in rows[key] if b and ea == "allow")
                print(f"  {key:22s} n={n:4d} attack={atk:4d} blockTPR={t}/{atk}"
                      f" benignFP={f}/{n - atk}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
