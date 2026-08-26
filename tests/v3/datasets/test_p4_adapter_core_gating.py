"""P4 contraction P0 — Adapter-level integration regressions (must test Adapter itself).

Three cases required by spec — all go through CredentialDynamicTracesAdapter,
not just core_eligibility pure function:

  1. reviewed artifact + unresolved official mapping + 6 gates true -> yields Core case
  2. reviewed artifact + official mapping VERIFIED + gateway_visible=false -> rejects
  3. PROJECTED quality B + DYNAMIC_TRACE -> Core adapter rejects (Extended only)

These use two modes:
  - frozen reviewed artifact (real file on disk) for 1 & 2
  - trace_provider hermetic mode for 3 (and as fallback for strictness)
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from demotest.core.exceptions import DatasetSourceError
from demotest.datasets.adapters.credential_dynamic_traces import CredentialDynamicTracesAdapter
from demotest.datasets.dynamic.review import TraceReview, freeze_reviewed_traces
from demotest.datasets.traces.models import CredentialTrace


def _valid_stdout_trace(**over) -> CredentialTrace:
    base = dict(
        trace_id="dyn-stdout-test-001",
        skill_id="sk-test",
        skill_name="sk-test",
        issue_id="OPENAI_API_KEY",
        academic_code="DYNAMIC",
        pattern="STDOUT_EXPOSURE",
        classification="Information Exposure",
        severity="high",
        sink="stdout",
        gateway_channel="TOOL_RESULT",
        gateway_visibility="DIRECT",
        flow_class="STDOUT_EXPOSURE",
        credential_marker="TEST_SECRET_AAAABBBBCCCCDDDD",
        payload="prefix TEST_SECRET_AAAABBBBCCCCDDDD suffix",
        evidence_type="DYNAMIC_TRACE",
        dynamic_confirmed=True,
        source_revision="rev-test",
        sandbox_version="img",
        trace_hash="sha256:abc123",
        metadata={
            "skill_snapshot_sha256": "s" * 64,
            "execution_condition": "deterministic",
            "sandbox_image_digest": "img",
            "pipeline_revision": "rev-test",
        },
    )
    base.update(over)
    # merge metadata if over provided it partially
    if "metadata" in over:
        # already replaced above; keep as-is
        pass
    return CredentialTrace(**base)  # type: ignore[arg-type]


def _accepted_review(trace_id: str) -> TraceReview:
    return TraceReview(
        trace_id=trace_id,
        review_status="ACCEPTED",
        source_real=True,
        dynamic_execution_real=True,
        fake_credential_confirmed=True,
        marker_observed=True,
        sink_confirmed=True,
        gateway_projection_valid=True,
        expected_action_valid=True,
    )


def _write_reviewed_artifact(tmp: Path, traces: list[CredentialTrace], reviews: list[TraceReview]) -> None:
    # freeze_reviewed_traces writes reviewed_traces.jsonl + review_meta.json with n_pending==0 binding
    freeze_reviewed_traces(traces, raw_dir=tmp, reviews=reviews)


# -- Case 1: unresolved mapping + 6 true -> yields Core case ------------------

def test_adapter_yields_core_when_unresolved_mapping_but_six_gates_true(tmp_path: Path):
    """Reviewed artifact + UNRESOLVED provenance + 6 gates true -> Adapter yields Core case.

    Provenance must not gate eligibility: the trace is a real disclosure and must
    be yielded even though skillleakbench_mapping_status is UNRESOLVED and no
    official key exists.
    """
    tr = _valid_stdout_trace(
        metadata={
            "skill_snapshot_sha256": "s" * 64,
            "execution_condition": "deterministic",
            "sandbox_image_digest": "img",
            "pipeline_revision": "rev-test",
            # provenance — intentionally UNRESOLVED, must be ignored
            "skillleakbench_mapping_status": "UNRESOLVED",
            "official_skill_key": "",
            "official_issue_key": "",
        }
    )
    review = _accepted_review(tr.trace_id)
    _write_reviewed_artifact(tmp_path, [tr], [review])

    ad = CredentialDynamicTracesAdapter(raw_dir=tmp_path, strict=True)
    cases = list(ad.iter_cases())
    assert len(cases) == 1, f"expected 1 Core case, got {len(cases)}: {ad._rejected}"
    assert cases[0].metadata["source"]["quality_tier"] == "A"
    # provenance enrichment may be absent or UNRESOLVED — but case still yields
    # (adapter must not have rejected on mapping status)


# -- Case 2: VERIFIED mapping + gateway_visible=false -> rejects --------------

def test_adapter_rejects_when_verified_mapping_but_not_gateway_visible(tmp_path: Path):
    """Reviewed artifact + VERIFIED mapping + gateway_visible=false -> Adapter rejects.

    Even with VERIFIED official mapping, a missing disclosure (marker not in
    payload / sink mismatch) must fail the gateway_visible_disclosure gate and
    the adapter must not yield a Core case.
    """
    # marker not in payload -> gateway_visible false
    tr = _valid_stdout_trace(
        payload="no marker here at all",
        metadata={
            "skill_snapshot_sha256": "s" * 64,
            "execution_condition": "deterministic",
            "sandbox_image_digest": "img",
            "pipeline_revision": "rev-test",
            "skillleakbench_mapping_status": "VERIFIED",
            "official_skill_key": "osk:abc123",
            "official_issue_key": "slb:def456",
        },
    )
    # Review claims VERIFIED but gateway gates are false to reflect not visible
    review = TraceReview(
        trace_id=tr.trace_id,
        review_status="ACCEPTED",
        source_real=True,
        dynamic_execution_real=True,
        fake_credential_confirmed=True,
        marker_observed=False,  # not observed
        sink_confirmed=False,
        gateway_projection_valid=False,
        expected_action_valid=True,
    )
    _write_reviewed_artifact(tmp_path, [tr], [review])

    ad = CredentialDynamicTracesAdapter(raw_dir=tmp_path, strict=True)
    with pytest.raises(DatasetSourceError, match="Core eligibility"):
        list(ad.iter_cases())


# -- Case 3: PROJECTED must be rejected even when all other gates would pass --

def test_adapter_rejects_projected_even_when_other_six_gates_would_pass(tmp_path: Path):
    """PROJECTED gateway_visibility must fail Core even with behavior_modified=false.

    This is the real DIRECT-only lock: a NETWORK_EXFIL/PROJECTED trace that
    otherwise satisfies all 6 gates must still be rejected — Core is DIRECT-only.
    The previous test used behavior_modified=True which hid the visibility gate.
    """
    tr = CredentialTrace(
        trace_id="dyn-net-proj-002",
        skill_id="sk-test",
        skill_name="sk-test",
        issue_id="AWS_SECRET_ACCESS_KEY",
        academic_code="DYNAMIC",
        pattern="NETWORK_EXFIL",
        classification="Information Exposure",
        severity="high",
        sink="network",
        gateway_channel="TOOL_CALL",
        gateway_visibility="PROJECTED",
        flow_class="NETWORK_EXFIL",
        credential_marker="TEST_SECRET_AAAABBBBCCCCDDDD",
        payload="leak TEST_SECRET_AAAABBBBCCCCDDDD to https://example.com",
        destination="https://example.com/collect",
        tool_arguments={"destination": "https://example.com/collect"},
        evidence_type="DYNAMIC_TRACE",
        dynamic_confirmed=True,
        source_revision="rev-test",
        sandbox_version="img",
        trace_hash="sha256:net123",
        metadata={
            "skill_snapshot_sha256": "s" * 64,
            "execution_condition": "deterministic",
            "sandbox_image_digest": "img",
            "pipeline_revision": "rev-test",
            "behavior_modified": False,
            # Simulate a fully ACCEPTED human verdict — eligibility goes via
            # trace_provider fallback (no review.jsonl) + explicit overrides.
            # Every non-visibility gate is satisfied.
            "human_review_confirmed": True,
        },
    )
    # Hermetic trace_provider path: eligibility derived with review=None and
    # no embedded core_review; we supply overrides so only visibility fails.
    # PROJECTED must still fail via gateway_visible_disclosure.
    raw_dir = tmp_path / "empty_raw"
    raw_dir.mkdir()
    ad = CredentialDynamicTracesAdapter(raw_dir=raw_dir, strict=True, trace_provider=[tr])
    with pytest.raises(DatasetSourceError, match="Core eligibility"):
        list(ad.iter_cases())
    # Confirm the failure is the DIRECT-only gate, not behavior_modified.
    assert any("gateway_visible_disclosure" in str(r.get("error", "")) for r in ad._rejected), f"_rejected={ad._rejected}"


def test_adapter_rejects_when_frozen_core_review_missing(tmp_path: Path):
    """Production frozen path: trace without embedded core_review must fail-closed.

    The frozen artifact must bind the human verdict. If metadata.core_review
    is absent and no review.jsonl is consulted, the adapter must not silently
    accept via fallback.
    """
    from demotest.datasets.traces.models import CredentialTrace as CT
    tr = CT(
        trace_id="dyn-stdout-noreview-001",
        skill_id="sk-test",
        skill_name="sk-test",
        issue_id="OPENAI_API_KEY",
        academic_code="DYNAMIC",
        pattern="STDOUT_EXPOSURE",
        classification="Information Exposure",
        severity="high",
        sink="stdout",
        gateway_channel="TOOL_RESULT",
        gateway_visibility="DIRECT",
        flow_class="STDOUT_EXPOSURE",
        credential_marker="TEST_SECRET_AAAABBBBCCCCDDDD",
        payload="prefix TEST_SECRET_AAAABBBBCCCCDDDD suffix",
        evidence_type="DYNAMIC_TRACE",
        dynamic_confirmed=True,
        source_revision="rev-test",
        sandbox_version="img",
        trace_hash="sha256:abc123",
        metadata={
            "skill_snapshot_sha256": "s" * 64,
            "execution_condition": "deterministic",
            "sandbox_image_digest": "img",
            "pipeline_revision": "rev-test",
            # no core_review and no human_review_confirmed override -> must fail
        },
    )
    # Write a reviewed artifact manually WITHOUT core_review to simulate old freeze.
    import json, hashlib
    out_dir = tmp_path / "reviews"
    out_dir.mkdir(parents=True)
    out_file = out_dir / "reviewed_traces.jsonl"
    out_file.write_text(json.dumps(tr.to_dict(), ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    sha = hashlib.sha256(out_file.read_bytes()).hexdigest()
    (out_dir / "review_meta.json").write_text(
        json.dumps({"n_accepted": 1, "n_pending": 0, "n_reviews": 1, "review_schema_version": "p4-review-v1", "sha256": sha, "trace_file": str(out_file), "source_trace_sha256": "", "source_trace_meta_sha256": "", "verdict_sha256": "x", "snapshot_id": "", "candidate_set_id": ""}, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    ad = CredentialDynamicTracesAdapter(raw_dir=tmp_path, strict=True)
    with pytest.raises(DatasetSourceError, match="Core eligibility"):
        list(ad.iter_cases())
