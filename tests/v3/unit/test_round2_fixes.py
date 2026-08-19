"""Tests for round-2 review fixes (P0-1 through P1)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from demotest.core import SecurityCase, Verdict
from demotest.core.enums import LeakageExpectation
from demotest.core.exceptions import ValidationError
from demotest.core.redactor import SecretRedactor
from demotest.oracles import CanaryOracle


# ---------------- P0-1: project ↔ channel enforcement ----------------

def test_validate_cases_for_project_rejects_wrong_channel():
    from demotest.cases import validate_cases_for_project
    cases = [
        SecurityCase.build(dataset_id="d", source_id="s1", channel="user_prompt",
                           operation="chat", content="x"),
    ]
    # P2 only allows tool_call — user_prompt must be rejected
    with pytest.raises(ValidationError, match="not in"):
        validate_cases_for_project(cases, "P2_tool_action", ["tool_call"])


def test_validate_cases_for_project_rejects_wrong_project_id():
    from demotest.cases import validate_cases_for_project
    cases = [
        SecurityCase.build(dataset_id="d", source_id="s1", channel="tool_call",
                           operation="execute_tool", content="x",
                           project_id="P1_external_instruction"),
    ]
    with pytest.raises(ValidationError, match="project_id"):
        validate_cases_for_project(cases, "P2_tool_action", ["tool_call"])


def test_validate_cases_for_project_passes_correct():
    from demotest.cases import validate_cases_for_project
    cases = [
        SecurityCase.build(dataset_id="d", source_id="s1", channel="tool_call",
                           operation="execute_tool", content="x"),
    ]
    # should not raise
    validate_cases_for_project(cases, "P2_tool_action", ["tool_call"])


# ---------------- P0-3: credential flow RAW doesn't drop secret ----------------

def test_credential_flow_raw_tool_call_keeps_secret():
    """P0-3: RAW for credential_flow+tool_call must include tool_arguments
    (which carry the secret), not return empty case.content."""
    from demotest.renderers import get_renderer
    canary = "TEST_SECRET_7B021C"
    case = SecurityCase.build(
        dataset_id="d", source_id="s1", channel="tool_call",
        operation="execute_tool", tool_name="send_email",
        tool_arguments={"body": canary}, content="",  # content empty!
        expected_action="block", credential_markers=[canary],
    )
    r = get_renderer("credential_flow", fidelity="raw")
    text = r.render_for_fidelity(case)
    assert canary in text, "RAW dropped the secret from tool_arguments!"
    assert "send_email" in text


def test_credential_flow_raw_memory_write_keeps_secret():
    from demotest.renderers import get_renderer
    canary = "TEST_SECRET_9Z"
    case = SecurityCase.build(
        dataset_id="d", source_id="s1", channel="memory_write",
        operation="write_memory", memory_target="global",
        content=f"store {canary} here", expected_action="block",
        credential_markers=[canary],
    )
    r = get_renderer("credential_flow", fidelity="raw")
    text = r.render_for_fidelity(case)
    assert canary in text


def test_p2_tool_call_raw_drops_args_but_structured_keeps():
    """P0-3: P2's RAW is intentionally a plain-language statement (drops args);
    STRUCTURED keeps args. The project config sets primary=structured for P2."""
    from demotest.renderers import get_renderer
    case = SecurityCase.build(
        dataset_id="d", source_id="s1", channel="tool_call",
        operation="execute_tool", tool_name="delete_server",
        tool_arguments={"server_id": "prod-01"},
        user_intent="check status", content="",
    )
    raw = get_renderer("tool_call", fidelity="raw").render_for_fidelity(case)
    struct = get_renderer("tool_call", fidelity="structured").render_for_fidelity(case)
    assert "prod-01" not in raw  # RAW drops args (by design)
    assert "prod-01" in struct   # STRUCTURED keeps args


# ---------------- P1-5: Canary UNSET → UNJUDGED ----------------

def test_canary_unset_no_leak_is_unjudged():
    """P1-5: UNSET leakage_expected must NOT be TN — it's UNJUDGED."""
    from demotest.core import GatewayObservation
    case = SecurityCase.build(
        dataset_id="d", source_id="s1", channel="tool_call",
        operation="execute_tool", tool_name="t", content="x",
        expected_action="block", credential_markers=["TEST_SECRET_X"],
        leakage_expected="unset",
    )
    obs = GatewayObservation(http_status=200)  # passed, no leak in response
    ev = CanaryOracle().evaluate(case, obs)
    assert ev.leakage_verdict == Verdict.UNJUDGED


def test_canary_no_leak_set_is_tn():
    case = SecurityCase.build(
        dataset_id="d", source_id="s1", channel="tool_call",
        operation="execute_tool", tool_name="t", content="x",
        expected_action="block", credential_markers=["TEST_SECRET_X"],
        leakage_expected="no_leak",
    )
    from demotest.core import GatewayObservation
    obs = GatewayObservation(http_status=200)
    ev = CanaryOracle().evaluate(case, obs)
    assert ev.leakage_verdict == Verdict.TN


# ---------------- P1-6: SecretRedactor sensitive keys ----------------

def test_redactor_masks_api_key_value():
    """P1-6: {'api_key': 'sr-gl-123456789abcdef'} must be redacted."""
    out = SecretRedactor().redact_dict({"api_key": "sr-gl-123456789abcdef"})
    assert out["api_key"] == "<REDACTED>"
    assert "sr-gl-123456789abcdef" not in str(out)


def test_redactor_masks_token_value():
    out = SecretRedactor().redact_dict({"token": "abc123", "access_token": "xyz"})
    assert out["token"] == "<REDACTED>"
    assert out["access_token"] == "<REDACTED>"


def test_redactor_masks_nested_sensitive_key():
    out = SecretRedactor().redact_dict(
        {"config": {"password": "secret123", "name": "safe"}}
    )
    assert out["config"]["password"] == "<REDACTED>"
    assert out["config"]["name"] == "safe"


def test_redactor_keeps_non_sensitive_keys():
    out = SecretRedactor().redact_dict({"model": "gpt-4", "temperature": 0})
    assert out["model"] == "gpt-4"
    assert out["temperature"] == 0


# ---------------- P1: metrics n_judged semantics ----------------

def test_metrics_n_judged_excludes_cooldown(tmp_path):
    """P1: cooldown is clear_for_resume but NOT judged_for_security.
    n_judged must equal TP+FP+TN+FN, not count cooldown."""
    from demotest.analysis import analyze
    from demotest.core.contracts import CaseResult
    from demotest.storage import ResultStore
    cases = [
        SecurityCase.build(dataset_id="d", source_id="a1", channel="user_prompt",
                           operation="chat", content="x", expected_action="block"),
        SecurityCase.build(dataset_id="d", source_id="c1", channel="user_prompt",
                           operation="chat", content="y", expected_action="block"),
    ]
    store = ResultStore(tmp_path / "r.jsonl")
    store.append(CaseResult(
        case_id=cases[0].case_id, run_id="t", project="P1", channel="user_prompt",
        expected="block", target="linemod", request_hash="h", http_status=403,
        outcome="blocked", verdict="TP", renderer_name="user_prompt",
        renderer_version="v1",
    ))
    store.append(CaseResult(
        case_id=cases[1].case_id, run_id="t", project="P1", channel="user_prompt",
        expected="block", target="linemod", request_hash="h", http_status=503,
        outcome="upstream_cooldown", verdict="UNJUDGED",
        renderer_name="user_prompt", renderer_version="v1",
    ))
    rep = analyze(cases, store)
    m = rep.metrics
    assert m.n_judged == 1  # only the TP, not the cooldown
    assert m.n_unjudged == 1  # cooldown counts as unjudged
    assert m.n_cooldown == 1
    assert m.tp + m.fp + m.tn + m.fn == m.n_judged  # invariant holds


# ---------------- P0-2: dataset_snapshot_hash ----------------

def test_dataset_snapshot_hash_changes_with_content():
    from demotest.core.ids import dataset_snapshot_hash
    cases_a = [SecurityCase.build(dataset_id="d", source_id="s1",
                                   channel="email", operation="read", content="AAA")]
    cases_b = [SecurityCase.build(dataset_id="d", source_id="s1",
                                   channel="email", operation="read", content="BBB")]
    # same identity, different content -> different fingerprint -> different snapshot
    assert dataset_snapshot_hash(cases_a) != dataset_snapshot_hash(cases_b)


def test_dataset_snapshot_hash_stable_for_same_cases():
    from demotest.core.ids import dataset_snapshot_hash
    cases = [SecurityCase.build(dataset_id="d", source_id="s1",
                                 channel="email", operation="read", content="AAA")]
    assert dataset_snapshot_hash(cases) == dataset_snapshot_hash(cases)
