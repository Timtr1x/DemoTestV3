"""Unit tests for the V3 core models (Commit 1)."""
from __future__ import annotations

from demotest.core import (
    Channel,
    Direction,
    ExpectedAction,
    GatewayObservation,
    GatewayRequest,
    Operation,
    Outcome,
    SecurityCase,
    Verdict,
)
from demotest.core.ids import compute_case_id


def _case(**kw):
    base = dict(
        dataset_id="ds",
        source_id="row:1",
        channel="user_prompt",
        operation="chat",
        content="hello",
        expected_action="block",
    )
    base.update(kw)
    return SecurityCase.build(**base)


def test_case_id_stable_and_content_independent():
    a = _case(content="AAA", threat_id="T1")
    b = _case(content="BBB", threat_id="T1")
    assert a.case_id == b.case_id, "case_id must not depend on content"
    assert a.case_id.startswith("case-")


def test_case_id_distinct_per_source():
    a = _case(source_id="row:1")
    b = _case(source_id="row:2")
    assert a.case_id != b.case_id


def test_case_id_explicit_matches_compute():
    c = _case(channel="email", operation="read", source_id="s9", dataset_id="d", threat_id="T1")
    expected = compute_case_id("d", "s9", "email", "read", "T1")
    assert c.case_id == expected


def test_direction_derived_from_channel():
    inbound = _case(channel="email", operation="read")
    outbound = _case(channel="tool_call", operation="execute_tool")
    assert inbound.direction == Direction.INBOUND
    assert outbound.direction == Direction.OUTBOUND


def test_enum_from_value_aliases():
    assert Channel.from_value("web") == Channel.WEB_PAGE
    assert Operation.from_value("execute") == Operation.EXECUTE_TOOL
    assert ExpectedAction.from_value("blocked") == ExpectedAction.BLOCK
    assert Outcome.from_value("passed_upstream_cooldown") == Outcome.UPSTREAM_COOLDOWN


def test_model_roundtrip():
    c = _case(
        channel="tool_call",
        operation="execute_tool",
        tool_name="delete_server",
        tool_arguments={"server_id": "prod-01"},
        user_intent="check server status",
        presentation_style="stealth",
        credential_markers=["TEST_SECRET_7B021C"],
    )
    d = c.to_dict()
    c2 = SecurityCase.from_dict(d)
    assert c2.channel == Channel.TOOL_CALL
    assert c2.tool_arguments == {"server_id": "prod-01"}
    assert c2.case_id == c.case_id
    assert c2.presentation_style == "stealth"


def test_redacted_view_hides_credential_markers():
    c = _case(credential_markers=["TEST_SECRET_7B021C"])
    rv = c.redacted_view()
    assert "TEST_SECRET_7B021C" not in str(rv)
    assert rv["credential_markers"] == ["<canary>"]


def test_observation_outcome_mapping():
    assert GatewayObservation(security_blocked=True).outcome == Outcome.BLOCKED
    assert GatewayObservation(payload_too_large=True).outcome == Outcome.PAYLOAD_TOO_LARGE
    assert GatewayObservation(upstream_cooldown=True).outcome == Outcome.UPSTREAM_COOLDOWN
    assert GatewayObservation(rate_limited=True).outcome == Outcome.RATE_LIMITED
    assert GatewayObservation(error_type="Timeout").outcome == Outcome.ERROR
    assert GatewayObservation(http_status=200).outcome == Outcome.PASSED


def test_request_hash_stable_and_key_independent():
    body = {"model": "m", "messages": [{"role": "user", "content": "hi"}], "temperature": 0}
    headers = {"X-LineMod-No-Failover": "true", "Authorization": "Bearer secret-abc"}
    r1 = GatewayRequest(target="linemod", url="http://x", headers=headers, json_body=body)
    # different key, same request -> same hash
    headers2 = dict(headers)
    headers2["Authorization"] = "Bearer totally-different-key"
    r2 = GatewayRequest(target="linemod", url="http://x", headers=headers2, json_body=body)
    assert r1.request_hash() == r2.request_hash()
    # different body -> different hash
    body3 = dict(body)
    body3["messages"] = [{"role": "user", "content": "hi2"}]
    r3 = GatewayRequest(target="linemod", url="http://x", headers=headers, json_body=body3)
    assert r1.request_hash() != r3.request_hash()


def test_missing_dataset_or_source_raises():
    import pytest
    from demotest.core.exceptions import ValidationError

    with pytest.raises(ValidationError):
        SecurityCase.build(dataset_id="", source_id="s", channel="email", operation="read")
    with pytest.raises(ValidationError):
        SecurityCase.build(dataset_id="d", source_id="", channel="email", operation="read")


def test_verdict_enum_values():
    assert Verdict.TP.value == "TP"
    assert Verdict.UNJUDGED.value == "UNJUDGED"
