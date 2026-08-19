"""LineMod TargetAdapter tests (Commit 3)."""
from __future__ import annotations

import json

import pytest

from demotest.core import GatewayObservation
from demotest.core.exceptions import TargetError
from demotest.targets import LineModTargetAdapter
from demotest.targets.linemod import mask_api_key


class FakeResp:
    def __init__(self, status_code, text):
        self.status_code = status_code
        self.text = text


class FakeSession:
    def __init__(self, resp):
        self._resp = resp
        self.last_kwargs = None

    def post(self, url, **kwargs):
        self.last_kwargs = {"url": url, **kwargs}
        return self._resp


def test_build_request_matches_v2_body_shape():
    ad = LineModTargetAdapter(api_key="sr-gl-test", model="deepseek-v4-flash")
    req = ad.build_request(rendered_text="hello")
    assert req.json_body == {
        "model": "deepseek-v4-flash",
        "messages": [{"role": "user", "content": "hello"}],
        "temperature": 0.0,
        "max_tokens": 8,
    }
    assert req.headers["X-LineMod-No-Failover"] == "true"
    assert req.headers["Authorization"] == "Bearer sr-gl-test"
    assert req.headers["Content-Type"] == "application/json"


def test_execute_blocked():
    body = json.dumps({"error": "SECURITY_BLOCKED", "scanner": "prompt_injection", "score": 0.99})
    ad = LineModTargetAdapter(api_key="sr-gl-test")
    ad._session = FakeSession(FakeResp(403, body))
    req = ad.build_request(rendered_text="bad")
    obs = ad.execute(req)
    assert isinstance(obs, GatewayObservation)
    assert obs.outcome.value == "blocked"
    assert obs.scanner == "prompt_injection"
    assert obs.score == 0.99
    assert obs.latency_ms >= 0
    # request actually posted with the built body + headers
    assert ad._session.last_kwargs["json"] == req.json_body


def test_execute_passed():
    body = json.dumps({"choices": [{"message": {"content": "ok"}}]})
    ad = LineModTargetAdapter(api_key="sr-gl-test")
    ad._session = FakeSession(FakeResp(200, body))
    obs = ad.execute(ad.build_request(rendered_text="hi"))
    assert obs.outcome.value == "passed"
    assert obs.response_text == "ok"


def test_benchmark_mode_rejects_missing_no_failover():
    with pytest.raises(TargetError):
        LineModTargetAdapter(api_key="sr-gl-test", extra_headers={"X-LineMod-No-Failover": "false"})


def test_benchmark_mode_off_allows_missing_no_failover():
    ad = LineModTargetAdapter(api_key="sr-gl-test", benchmark_mode=False,
                              extra_headers={"X-LineMod-No-Failover": "false"})
    assert ad.config_summary()["no_failover"] == "false"


def test_mask_api_key():
    assert mask_api_key("sr-gl-fixture0000000000000000000001").startswith("sr-gl-")
    assert mask_api_key(None) == "<missing>"
    assert mask_api_key("ab") == "ab***"
    full = "sr-gl-fixture0000000000000000000001"
    assert full not in mask_api_key(full)
