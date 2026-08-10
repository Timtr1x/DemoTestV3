"""T8 auditability checklist + T15 human_manip / goal bucketing."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from adapters.legacy import infer_t15_goal_from_prompt, t15_goal_bucket  # noqa: E402
from core.auditability import (  # noqa: E402
    evaluate_result_records,
    prompt_hash,
    render_auditability_markdown,
)
from core.analyzer import compute_metrics  # noqa: E402
from core.report import render_summary  # noqa: E402
from core.schema import Sample  # noqa: E402
from generators.human_manip_gen import generate_human_manip_samples  # noqa: E402


def test_t8_checklist_on_result_records():
    rows = [
        {
            "sample_id": f"e1:x:{i}",
            "manifest_name": "demo",
            "run_version": "rv1",
            "http_status": 403,
            "outcome": "blocked",
            "security_flag": "SECURITY_BLOCKED",
            "latency_ms": 10 + i,
            "attempts": 1,
            "ts": "2026-01-01T00:00:00Z",
        }
        for i in range(25)
    ]
    rep = evaluate_result_records(rows, max_check=20)
    assert rep.n_records_checked == 20
    assert rep.n_records_total == 25
    assert rep.overall in ("PASS", "PARTIAL")
    auto_pass = [i for i in rep.items if i.auto and i.status == "pass"]
    assert len(auto_pass) >= 2
    md = render_auditability_markdown(rep)
    assert "T8" in md
    assert "可审计性" in md


def test_t8_empty_is_manual():
    rep = evaluate_result_records([], max_check=20)
    assert rep.overall == "MANUAL"
    assert any(i.status == "n_a" for i in rep.items)


def test_prompt_hash_stable():
    assert prompt_hash("hello") == prompt_hash("hello")
    assert prompt_hash("hello") != prompt_hash("world")


def test_human_manip_unique_deterministic():
    # unique curated cases only — n is a cap, never pads beyond CASES
    a = generate_human_manip_samples(100, project="e6")
    b = generate_human_manip_samples(100, project="e6")
    assert len(a) >= 20
    assert len(a) == len(b)
    assert [s.sample_id for s in a] == [s.sample_id for s in b]
    assert all(s.label == "attack" and s.expected == "blocked" for s in a)
    assert all((s.generator_meta or {}).get("threat") == "T15" for s in a)
    goals = {s.category for s in a}
    assert "transfer_coercion" in goals or "credential_harvest" in goals
    # no index-only padding: all prompts distinct
    assert len({s.prompt_text for s in a}) == len(a)


def test_t15_goal_bucket():
    assert t15_goal_bucket("download and execute a malicious attachment") == "malware_download"
    assert t15_goal_bucket("steal VPN password") == "credential_harvest"
    assert t15_goal_bucket("wire transfer payment to account") == "transfer_coercion"
    g = infer_t15_goal_from_prompt(
        "Write email.\n\nGoal: Convince the target to download malware\n\nTarget:"
    )
    assert g == "malware_download"


def test_t15_metrics_and_summary_section():
    samples = generate_human_manip_samples(5, project="e6")
    resolved = {
        s.sample_id: {
            "sample_id": s.sample_id,
            "outcome": "blocked",
            "security_flag": "SECURITY_BLOCKED",
            "latency_ms": 5,
            "ts": "t",
            "manifest_name": "human_manip_100",
            "run_version": "t",
            "http_status": 403,
            "attempts": 1,
        }
        for s in samples
    }
    m = compute_metrics(samples, resolved, group_by=["category"])
    assert m.t15_by_goal
    assert m.tpr == 1.0

    from core.analyzer import Report

    rep = Report(
        manifest_name="human_manip_100",
        run_version="t",
        metrics=m,
        project="E6",
        auditability=evaluate_result_records(list(resolved.values()), max_check=20),
    )
    text = render_summary(rep)
    assert "T15" in text
    assert "可审计性" in text
