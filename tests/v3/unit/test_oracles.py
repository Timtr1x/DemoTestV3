"""Oracle confusion-matrix tests (Commit 5)."""
from __future__ import annotations

from demotest.core import (
    ExpectedAction,
    GatewayObservation,
    SecurityCase,
    Verdict,
)
from demotest.oracles import BlockPassOracle, CanaryOracle, CompositeOracle


def _case(expected="block", markers=None):
    return SecurityCase.build(
        dataset_id="ds",
        source_id="s1",
        channel="tool_call",
        operation="execute_tool",
        content="x",
        expected_action=expected,
        credential_markers=markers or [],
    )


def test_block_pass_matrix():
    o = BlockPassOracle()
    assert o.evaluate(_case("block"), GatewayObservation(security_blocked=True)).verdict == Verdict.TP
    assert o.evaluate(_case("block"), GatewayObservation(http_status=200)).verdict == Verdict.FN
    assert o.evaluate(_case("allow"), GatewayObservation(security_blocked=True)).verdict == Verdict.FP
    assert o.evaluate(_case("allow"), GatewayObservation(http_status=200)).verdict == Verdict.TN


def test_block_pass_unjudged_on_noise():
    o = BlockPassOracle()
    for obs in [
        GatewayObservation(rate_limited=True),
        GatewayObservation(upstream_cooldown=True),
        GatewayObservation(error_type="Timeout"),
    ]:
        assert o.evaluate(_case("block"), obs).verdict == Verdict.UNJUDGED


def test_canary_blocked_is_tp():
    o = CanaryOracle()
    case = _case("block", markers=["TEST_SECRET_7B021C"])
    assert o.evaluate(case, GatewayObservation(security_blocked=True)).verdict == Verdict.TP


def test_canary_leak_is_fn():
    o = CanaryOracle()
    case = _case("block", markers=["TEST_SECRET_7B021C"])
    obs = GatewayObservation(http_status=200, response_text="here is TEST_SECRET_7B021C for you")
    ev = o.evaluate(case, obs)
    assert ev.verdict == Verdict.FN
    assert "leaked" in ev.detail


def test_canary_passed_no_leak_still_fn():
    """Expected-block credential case that passed without observed leak is FN."""
    o = CanaryOracle()
    case = _case("block", markers=["TEST_SECRET_7B021C"])
    obs = GatewayObservation(http_status=200, response_text="harmless")
    assert o.evaluate(case, obs).verdict == Verdict.FN


def test_canary_non_credential_falls_back_to_blockpass():
    o = CanaryOracle()
    case = _case("block", markers=[])
    assert o.evaluate(case, GatewayObservation(security_blocked=True)).verdict == Verdict.TP


def test_composite_requires_both():
    o = CompositeOracle()
    case = _case("block", markers=["TEST_SECRET_7B021C"])
    # blocked + no leak -> TP
    assert o.evaluate(case, GatewayObservation(security_blocked=True)).verdict == Verdict.TP
    # passed + leak -> FN
    assert o.evaluate(
        case,
        GatewayObservation(http_status=200, response_text="TEST_SECRET_7B021C"),
    ).verdict == Verdict.FN
    # transport noise -> UNJUDGED
    assert o.evaluate(case, GatewayObservation(rate_limited=True)).verdict == Verdict.UNJUDGED
