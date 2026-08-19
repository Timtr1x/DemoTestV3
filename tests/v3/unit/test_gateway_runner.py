"""GatewayRunner tests (Commit 10-11)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from demotest.core import GatewayObservation, SecurityCase, Verdict
from demotest.oracles import BlockPassOracle
from demotest.renderers import get_renderer
from demotest.runners import GatewayRunner
from demotest.storage import ResultStore
from demotest.targets.base import TargetAdapter, TargetType


class FakeTarget(TargetAdapter):
    target_name = "fake"
    target_type = TargetType.GATEWAY

    def __init__(self, outcomes):
        self._outcomes = list(outcomes)
        self.requests = []

    def build_request(self, *, rendered_text, model=None, temperature=0.0, max_tokens=8):
        from demotest.core import GatewayRequest
        return GatewayRequest(
            target="fake", url="http://fake", method="POST",
            headers={"X-LineMod-No-Failover": "true"},
            json_body={"model": "m", "messages": [{"role": "user", "content": rendered_text}],
                       "temperature": temperature, "max_tokens": max_tokens},
            rendered_text=rendered_text,
        )

    def execute(self, request):
        self.requests.append(request)
        if not self._outcomes:
            return GatewayObservation(http_status=200)
        return self._outcomes.pop(0)


def _case(sid="c1", content="bad", expected="block"):
    return SecurityCase.build(
        dataset_id="ds", source_id=sid, channel="user_prompt",
        operation="chat", content=content, expected_action=expected, project_id="P0",
    )


def test_dry_run_does_not_call_target_or_persist(tmp_path):
    store = ResultStore(tmp_path / "r.jsonl")
    target = FakeTarget([])
    runner = GatewayRunner(
        renderer=get_renderer("user_prompt"), target=target, oracle=BlockPassOracle(),
        store=store, run_id="t1", request_gap=0.0, sleep_fn=lambda s: None,
    )
    rr = runner.run([_case()], dry_run=True)
    assert rr.ran == 1
    assert rr.written == 0
    assert target.requests == []  # target never called
    assert not store.path.exists() or not store.load()
    # dry-run result carries rendered_text for inspection
    assert rr.results[0].metadata["rendered_text"] == "bad"
    assert rr.results[0].outcome == "dry_run"


def test_full_pipeline_blocks_and_appends(tmp_path):
    store = ResultStore(tmp_path / "r.jsonl")
    target = FakeTarget([GatewayObservation(http_status=403, security_blocked=True,
                                             scanner="prompt_injection", score=0.9)])
    runner = GatewayRunner(
        renderer=get_renderer("user_prompt"), target=target, oracle=BlockPassOracle(),
        store=store, run_id="t1", project="P0", request_gap=0.0, sleep_fn=lambda s: None,
    )
    rr = runner.run([_case()])
    assert rr.written == 1
    rows = store.load()
    assert len(rows) == 1
    r = rows[0]
    assert r["outcome"] == "blocked"
    assert r["verdict"] == "TP"
    assert r["scanner"] == "prompt_injection"
    assert r["score"] == 0.9
    assert r["renderer_name"] == "user_prompt"
    assert r["renderer_version"] == "v1"
    assert r["target"] == "fake"
    assert r["project"] == "P0"
    assert r["request_hash"]  # non-empty


def test_resume_skips_clear(tmp_path):
    store = ResultStore(tmp_path / "r.jsonl")
    target = FakeTarget([GatewayObservation(http_status=403, security_blocked=True)])
    runner = GatewayRunner(
        renderer=get_renderer("user_prompt"), target=target, oracle=BlockPassOracle(),
        store=store, run_id="t1", request_gap=0.0, sleep_fn=lambda s: None,
    )
    runner.run([_case()])
    # second run: clear -> skip, no new call
    target2 = FakeTarget([])
    runner2 = GatewayRunner(
        renderer=get_renderer("user_prompt"), target=target2, oracle=BlockPassOracle(),
        store=store, run_id="t1", request_gap=0.0, sleep_fn=lambda s: None,
    )
    rr = runner2.run([_case()])
    assert rr.skipped == 1
    assert rr.ran == 0
    assert target2.requests == []


def test_retry_on_rate_limited_then_clear(tmp_path):
    store = ResultStore(tmp_path / "r.jsonl")
    target = FakeTarget([
        GatewayObservation(http_status=429, rate_limited=True, error_type="429"),
        GatewayObservation(http_status=403, security_blocked=True),
    ])
    runner = GatewayRunner(
        renderer=get_renderer("user_prompt"), target=target, oracle=BlockPassOracle(),
        store=store, run_id="t1", request_gap=0.0, max_attempts=4, sleep_fn=lambda s: None,
    )
    runner.run([_case()])
    r = store.load()[0]
    assert r["outcome"] == "blocked"
    assert r["attempt"] == 2


def test_retest_re_issues_cooldown(tmp_path):
    store = ResultStore(tmp_path / "r.jsonl")
    target = FakeTarget([GatewayObservation(http_status=503, upstream_cooldown=True,
                                            note="guard_passed_model_cooldown")])
    runner = GatewayRunner(
        renderer=get_renderer("user_prompt"), target=target, oracle=BlockPassOracle(),
        store=store, run_id="t1", request_gap=0.0, sleep_fn=lambda s: None,
    )
    runner.run([_case()])
    assert store.load()[0]["outcome"] == "upstream_cooldown"
    # retest with a fresh target that blocks
    target2 = FakeTarget([GatewayObservation(http_status=403, security_blocked=True)])
    runner2 = GatewayRunner(
        renderer=get_renderer("user_prompt"), target=target2, oracle=BlockPassOracle(),
        store=store, run_id="t1", request_gap=0.0, sleep_fn=lambda s: None,
    )
    rr = runner2.retest([_case()])
    assert rr.retested == 1
    rows = store.load()
    assert len(rows) == 2
    # resolved latest clear is blocked
    assert store.resolved()[_case().case_id]["outcome"] == "blocked"


def test_fpr_case_verdict_tn(tmp_path):
    store = ResultStore(tmp_path / "r.jsonl")
    target = FakeTarget([GatewayObservation(http_status=200)])
    runner = GatewayRunner(
        renderer=get_renderer("user_prompt"), target=target, oracle=BlockPassOracle(),
        store=store, run_id="t1", request_gap=0.0, sleep_fn=lambda s: None,
    )
    runner.run([_case(sid="b1", content="hello", expected="allow")])
    r = store.load()[0]
    assert r["verdict"] == "TN"


def test_request_hash_stable_across_runs(tmp_path):
    store = ResultStore(tmp_path / "r.jsonl")
    target = FakeTarget([GatewayObservation(http_status=403, security_blocked=True)])
    runner = GatewayRunner(
        renderer=get_renderer("user_prompt"), target=target, oracle=BlockPassOracle(),
        store=store, run_id="t1", request_gap=0.0, sleep_fn=lambda s: None,
    )
    runner.run([_case()])
    h1 = store.load()[0]["request_hash"]
    # fresh store, same case
    store2 = ResultStore(tmp_path / "r2.jsonl")
    target2 = FakeTarget([GatewayObservation(http_status=403, security_blocked=True)])
    runner2 = GatewayRunner(
        renderer=get_renderer("user_prompt"), target=target2, oracle=BlockPassOracle(),
        store=store2, run_id="t2", request_gap=0.0, sleep_fn=lambda s: None,
    )
    runner2.run([_case()])
    h2 = store2.load()[0]["request_hash"]
    assert h1 == h2
