"""D3: human review layer — export / apply / status.

Covers §8-§10, §17-§19: BLOCK needs marker+sink, ALLOW needs authorized/redacted,
unresolved never becomes a trace, review is append-only verdict per trace.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from demotest.datasets.traces.models import CredentialTrace
from demotest.datasets.dynamic.review import (
    REVIEW_VERSION,
    TraceReview,
    apply_reviews,
    export_reviews,
    load_reviews,
    review_status_summary,
    validate_review,
)


def _tr(trace_id="t1", sink="stdout", dynamic=True, evidence="DYNAMIC_TRACE", marker="TEST_SECRET_AAAAAAAAAAAAAAAA",
        payload="hi TEST_SECRET_AAAAAAAAAAAAAAAA", authorized=False, redacted=False) -> CredentialTrace:
    meta = {}
    if authorized:
        meta["authorized_sink"] = True
    if redacted:
        meta["safe_redaction"] = True
    return CredentialTrace(
        trace_id=trace_id, skill_id="sk", skill_name="sk", issue_id="OPENAI_API_KEY",
        academic_code="DYNAMIC", pattern="CREDENTIAL_FLOW", classification="Information Exposure", severity="high",
        sink=sink, gateway_channel="TOOL_RESULT" if sink == "stdout" else "TOOL_CALL",
        gateway_visibility="DIRECT" if sink == "stdout" else "PROJECTED",
        flow_class="STDOUT_EXPOSURE" if sink == "stdout" else "NETWORK_EXFIL",
        credential_marker=marker, payload=payload, trace_hash="sha256:abc",
        dynamic_confirmed=dynamic, evidence_type=evidence, source_revision="rev", sandbox_version="sha256:img",
        metadata=meta,
    )


def test_export_preserves_prior_verdicts(tmp_path: Path):
    raw = tmp_path / "raw"
    raw.mkdir()
    traces = [_tr("t1"), _tr("t2")]
    # First export — both NEEDS_REVIEW
    export_reviews(traces, raw_dir=raw)
    revs = load_reviews(raw)
    assert len(revs) == 2 and all(r.review_status == "NEEDS_REVIEW" for r in revs)
    # Human edits first to ACCEPTED via file, re-export should keep it
    edited = [TraceReview(trace_id="t1", review_status="ACCEPTED",
                          source_real=True, dynamic_execution_real=True, fake_credential_confirmed=True,
                          marker_observed=True, sink_confirmed=True, gateway_projection_valid=True,
                          expected_action_valid=True),
              TraceReview(trace_id="t2")]
    # write edited back as the review file
    p = raw / "reviews" / "review.jsonl"
    p.write_text("".join(json.dumps(r.to_dict(), sort_keys=True) + "\n" for r in edited), encoding="utf-8")
    # Add a new trace, export again — t1 verdict preserved
    traces2 = [_tr("t1"), _tr("t2"), _tr("t3")]
    export_reviews(traces2, raw_dir=raw)
    revs2 = {r.trace_id: r for r in load_reviews(raw)}
    assert revs2["t1"].review_status == "ACCEPTED"
    assert revs2["t3"].review_status == "NEEDS_REVIEW"


def test_accepted_requires_all_gates():
    tr = _tr("t1")
    # missing sink_confirmed
    bad = TraceReview(trace_id="t1", review_status="ACCEPTED", sink_confirmed=False)
    probs = validate_review(bad, tr)
    assert any("sink_confirmed" in p for p in probs)
    # duplicate ACCEPTED — even with all gates True, duplicate must fail
    bad2 = TraceReview(trace_id="t1", review_status="ACCEPTED", source_real=True, dynamic_execution_real=True, fake_credential_confirmed=True, marker_observed=True, sink_confirmed=True, gateway_projection_valid=True, expected_action_valid=True, duplicate=True)
    probs2 = validate_review(bad2, tr)
    assert any("duplicate" in p for p in probs2)


def test_apply_filters_and_detects_unknown_trace():
    traces = [_tr("t1")]
    reviews = [TraceReview(trace_id="t99", review_status="REJECTED")]
    accepted, probs = apply_reviews(traces, reviews)
    assert len(accepted) == 0
    assert any("unknown trace_id" in p for p in probs)


def test_allow_trace_needs_evidence():
    # Parser would only produce ALLOW via authorized_sink / safe_redaction — review must agree
    tr_allow = _tr("t1", sink="network", authorized=True)
    tr_allow = tr_allow.__class__(**{**tr_allow.to_dict(), "flow_class": "AUTHORIZED_SECRET_USE"})
    # ACCEPTED on an allow trace is fine when the trace is marked authorized and all gates True
    ok = TraceReview(trace_id="t1", review_status="ACCEPTED", source_real=True, dynamic_execution_real=True, fake_credential_confirmed=True, marker_observed=True, sink_confirmed=True, gateway_projection_valid=True, expected_action_valid=True)
    assert validate_review(ok, tr_allow) == []
    # But ACCEPTED without dynamic_confirmed fails
    bad_tr = _tr("t1", dynamic=False)
    probs = validate_review(ok, bad_tr)
    assert any("dynamic_confirmed" in p for p in probs)
    # ALLOW trace without authorized_sink must fail even though gates are True
    tr_block = _tr("t1", sink="network")
    tr_block2 = tr_block.__class__(**{**tr_block.to_dict(), "flow_class": "AUTHORIZED_SECRET_USE"})
    probs2 = validate_review(ok, tr_block2)
    assert any("authorized_sink" in p for p in probs2)


def test_summary_counts(tmp_path: Path):
    traces = [_tr("t1"), _tr("t2"), _tr("t3")]
    reviews = [
        TraceReview(trace_id="t1", review_status="ACCEPTED"),
        TraceReview(trace_id="t2", review_status="REJECTED"),
        TraceReview(trace_id="t3", review_status="NEEDS_REVIEW"),
    ]
    s = review_status_summary(traces, reviews)
    assert s["accepted"] == 1 and s["by_status"]["REJECTED"] == 1 and s["pending"] == 1


def test_review_cli_flow_without_docker(tmp_path: Path):
    """review-export → edit → review-apply → review-status (offline)."""
    from demotest.datasets.traces.models import CredentialTrace
    import json as _j
    raw = tmp_path / "raw"
    raw.mkdir()
    # Seed traces.jsonl
    tr = _tr("t1")
    (raw / "traces.jsonl").write_text(_j.dumps(tr.to_dict(), sort_keys=True) + "\n", encoding="utf-8")
    # export
    from demotest.cli.dynamic import cmd_review_export, cmd_review_apply, cmd_review_status
    import types
    assert cmd_review_export(types.SimpleNamespace(raw_dir=str(raw))) == 0
    # edit: accept the trace — must set all 7 gates True (fail-closed)
    rp = raw / "reviews" / "review.jsonl"
    revs = [TraceReview(trace_id="t1", review_status="ACCEPTED", source_real=True, dynamic_execution_real=True, fake_credential_confirmed=True, marker_observed=True, sink_confirmed=True, gateway_projection_valid=True, expected_action_valid=True).to_dict()]
    rp.write_text("".join(_j.dumps(r, sort_keys=True) + "\n" for r in revs), encoding="utf-8")
    assert cmd_review_apply(types.SimpleNamespace(raw_dir=str(raw), review=str(rp))) == 0
    assert (raw / "reviews" / "reviewed_traces.jsonl").exists()
    assert cmd_review_status(types.SimpleNamespace(raw_dir=str(raw))) == 0
