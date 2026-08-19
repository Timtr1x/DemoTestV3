"""Analyzer + breakdown tests (Commit 12-13)."""
from __future__ import annotations

from pathlib import Path

from demotest.analysis import analyze, compare_runs
from demotest.core import SecurityCase, Verdict
from demotest.reporting.markdown import render_markdown
from demotest.storage import ResultStore


def _case(sid, channel="user_prompt", op="chat", expected="block", style="explicit", markers=None):
    return SecurityCase.build(
        dataset_id="ds", source_id=sid, channel=channel, operation=op,
        content=f"content-{sid}", expected_action=expected,
        presentation_style=style, credential_markers=markers or [],
        project_id="P1",
    )


def _resolved_row(outcome, verdict, scanner="", score=None, latency=10, response=""):
    return {
        "outcome": outcome, "verdict": verdict,
        "scanner": scanner, "score": score, "latency_ms": latency,
        "response_text": response,
    }


def _seed_store(tmp_path, cases, rows):
    """Write one result row per case (zipped by index), keyed by case.case_id."""
    store = ResultStore(tmp_path / "r.jsonl")
    from demotest.core.contracts import CaseResult
    assert len(cases) == len(rows), "cases and rows must align"
    for case, r in zip(cases, rows):
        # Mimic what the runner stamps: a pre-redaction leakage summary in
        # metadata, plus the credential_markers list for the store to redact.
        response_text = r.get("response_text", r.get("response", ""))
        markers = list(case.credential_markers or [])
        if markers and r["outcome"] == "passed":
            leaked_count = sum(1 for m in markers if m and m in (response_text or ""))
            leakage = {"has_markers": True, "leaked": leaked_count > 0,
                       "leaked_count": leaked_count}
        elif markers:
            leakage = {"has_markers": True, "leaked": False, "leaked_count": 0}
        else:
            leakage = {"has_markers": False, "leaked": False, "leaked_count": 0}
        store.append(CaseResult(
            case_id=case.case_id, run_id="t1", project="P1",
            channel=case.channel.value, expected=case.expected_action.value,
            target="linemod", request_hash="h", http_status=403,
            outcome=r["outcome"], scanner=r.get("scanner", ""),
            score=r.get("score"), security_flag="", attempt=1,
            latency_ms=r.get("latency_ms", 10), verdict=r["verdict"],
            response_text=response_text,
            renderer_name="user_prompt", renderer_version="v1",
            metadata={"credential_markers": markers, "leakage": leakage},
        ))
    return store


def test_analyzer_confusion_matrix(tmp_path):
    cases = [
        _case("a1"), _case("a2"),  # attacks
        _case("b1", expected="allow"), _case("b2", expected="allow"),  # benign
    ]
    rows = [
        _resolved_row("blocked", "TP", scanner="prompt_injection", score=0.9, latency=11),
        _resolved_row("passed", "FN", latency=12),
        _resolved_row("blocked", "FP", latency=13),
        _resolved_row("passed", "TN", latency=14),
    ]
    store = _seed_store(tmp_path, cases, rows)
    rep = analyze(cases, store, project="P1", run_id="t1", target="linemod")
    m = rep.metrics
    assert m.tp == 1 and m.fn == 1 and m.fp == 1 and m.tn == 1
    assert m.tpr == 0.5
    assert m.fpr == 0.5
    assert m.n_judged == 4
    assert m.n_unjudged == 0


def test_channel_breakdown(tmp_path):
    """plan §32: TPR by channel."""
    cases = [
        _case("e1", channel="email"),
        _case("e2", channel="email"),
        _case("t1", channel="tool_result", op="read"),
        _case("t2", channel="tool_result", op="read"),
    ]
    rows = [
        _resolved_row("blocked", "TP"),
        _resolved_row("passed", "FN"),
        _resolved_row("blocked", "TP"),
        _resolved_row("blocked", "TP"),
    ]
    store = _seed_store(tmp_path, cases, rows)
    rep = analyze(cases, store)
    bc = rep.metrics.by_channel
    assert "email" in bc and "tool_result" in bc
    assert bc["email"]["tpr"] == 0.5
    assert bc["tool_result"]["tpr"] == 1.0


def test_scanner_breakdown(tmp_path):
    """plan §33: which scanner actually caught it."""
    cases = [_case("a1"), _case("a2"), _case("a3")]
    rows = [
        _resolved_row("blocked", "TP", scanner="prompt_injection", score=0.9),
        _resolved_row("blocked", "TP", scanner="abuse_detection", score=0.7),
        _resolved_row("passed", "FN"),
    ]
    store = _seed_store(tmp_path, cases, rows)
    rep = analyze(cases, store)
    bs = rep.metrics.by_scanner
    assert bs["prompt_injection"]["tp"] == 1
    assert bs["abuse_detection"]["tp"] == 1
    assert rep.metrics.scanner_counts["prompt_injection"] == 1


def test_score_distribution(tmp_path):
    """plan §34: min/p10/.../max not just median."""
    cases = [_case(f"a{i}") for i in range(5)]
    rows = [
        _resolved_row("blocked", "TP", score=0.51),
        _resolved_row("blocked", "TP", score=0.55),
        _resolved_row("blocked", "TP", score=0.70),
        _resolved_row("blocked", "TP", score=0.80),
        _resolved_row("blocked", "TP", score=0.99),
    ]
    store = _seed_store(tmp_path, cases, rows)
    rep = analyze(cases, store)
    sd = rep.metrics.score_distribution
    assert sd["min"] == 0.51
    assert sd["max"] == 0.99
    assert sd["p50"] is not None


def test_style_breakdown(tmp_path):
    """plan §35: explicit vs stealth TPR divergence."""
    cases = [
        _case("e1", style="explicit"),
        _case("s1", style="stealth"),
        _case("s2", style="stealth"),
    ]
    rows = [
        _resolved_row("blocked", "TP"),
        _resolved_row("passed", "FN"),
        _resolved_row("passed", "FN"),
    ]
    store = _seed_store(tmp_path, cases, rows)
    rep = analyze(cases, store)
    bs = rep.metrics.by_style
    assert bs["explicit"]["tpr"] == 1.0
    assert bs["stealth"]["tpr"] == 0.0


def test_canary_leakage(tmp_path):
    cases = [_case("c1", markers=["TEST_SECRET_7B021C"])]
    rows = [
        _resolved_row("passed", "FN", response="here is TEST_SECRET_7B021C"),
    ]
    store = _seed_store(tmp_path, cases, rows)
    rep = analyze(cases, store)
    assert rep.leakage["canary_echo_num"] == 1
    assert rep.leakage["canary_echo_rate"] == 1.0
    # raw marker values are never exposed in the report (plan §24)
    assert rep.leakage["leaked_markers"] == []
    # and the raw marker must not survive in the persisted store
    blob = store.path.read_text(encoding="utf-8")
    assert "TEST_SECRET_7B021C" not in blob


def test_thresholds_pass_fail(tmp_path):
    # 2 attacks: one blocked (TP), one passed (FN) -> TPR=0.5
    cases = [_case("a1"), _case("a2"), _case("b1", expected="allow")]
    rows = [
        _resolved_row("blocked", "TP"),
        _resolved_row("passed", "FN"),
        _resolved_row("passed", "TN"),
    ]
    store = _seed_store(tmp_path, cases, rows)
    rep_pass = analyze(cases, store, thresholds={"tpr_min": 0.5, "fpr_max": 0.5})
    assert rep_pass.pass_fail == "PASS"
    rep_fail = analyze(cases, store, thresholds={"tpr_min": 0.99})
    assert rep_fail.pass_fail == "FAIL"


def test_markdown_contains_channel_breakdown(tmp_path):
    cases = [_case("e1", channel="email"), _case("t1", channel="tool_result", op="read")]
    rows = [_resolved_row("blocked", "TP"), _resolved_row("blocked", "TP")]
    store = _seed_store(tmp_path, cases, rows)
    rep = analyze(cases, store, project="P1")
    md = render_markdown(rep)
    assert "按 Channel 分 TPR" in md
    assert "email" in md and "tool_result" in md


def test_compare_runs_divergence(tmp_path):
    cases = [_case("a1"), _case("a2")]
    s1 = _seed_store(tmp_path / "s1", cases, [
        _resolved_row("blocked", "TP"),
        _resolved_row("blocked", "TP"),
    ])
    s2 = _seed_store(tmp_path / "s2", cases, [
        _resolved_row("passed", "FN"),
        _resolved_row("blocked", "TP"),
    ])
    out = compare_runs(cases, {"linemod": s1, "qwen": s2}, project="P1")
    assert out["n_divergent"] == 1
    # divergent keyed by case_id (hash); ensure exactly one divergence exists
    assert len(out["divergent"]) == 1
