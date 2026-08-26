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


# -- Case 3: PROJECTED / quality B + DYNAMIC_TRACE -> Core rejects -----------

def test_adapter_rejects_projected_quality_b_dynamic_trace(tmp_path: Path):
    """PROJECTED quality B + DYNAMIC_TRACE -> Core adapter must reject.

    A network PROJECTED trace that is behavior_modified (or otherwise PROJECTED)
    must not be yielded as Core; it belongs to Extended only. The adapter must
    fail-closed via Core eligibility even though evidence_type is DYNAMIC_TRACE.
    """
    # NETWORK_EXFIL PROJECTED B — but behavior_modified=True makes it PROJECTED
    tr = CredentialTrace(
        trace_id="dyn-net-proj-001",
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
            # behavior_modified beyond canary injection -> PROJECTED
            "behavior_modified": True,
        },
    )
    # Use hermetic trace_provider path (no reviewed artifact needed); eligibility
    # is still enforced via derive_eligibility_input metadata override.
    raw_dir = tmp_path / "empty_raw"
    raw_dir.mkdir()
    ad = CredentialDynamicTracesAdapter(raw_dir=raw_dir, strict=True, trace_provider=[tr])
    with pytest.raises(DatasetSourceError, match="Core eligibility"):
        list(ad.iter_cases())
