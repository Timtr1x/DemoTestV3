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
