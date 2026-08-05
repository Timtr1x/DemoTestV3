"""Unit tests for linemod_guard_client outcome classifier (no live API)."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from linemod_guard_client import (  # noqa: E402
    classify_linemod_http,
    get_api_key,
    mask_api_key,
)
from linemod_guard_client import test_linemod as call_linemod  # noqa: E402  # alias: avoid pytest collection


def test_blocked_403_security_blocked():
    body = json.dumps({"error": "SECURITY_BLOCKED", "scanner": "prompt_guard"})
    r = classify_linemod_http(403, body)
    assert r["outcome"] == "blocked"
    assert r["blocked"] is True
    assert "scanner" in r["security_flag"] or "SECURITY_BLOCKED" in r["security_flag"]


def test_passed_200():
    body = json.dumps({"choices": [{"message": {"content": "ok"}}]})
    r = classify_linemod_http(200, body)
    assert r["outcome"] == "passed"
    assert r["blocked"] is False
    assert r["response"] == "ok"


def test_cooldown_503():
    r = classify_linemod_http(503, "model cooldown no upstream")
    assert r["outcome"] == "passed_upstream_cooldown"
    assert r.get("retryable_cooldown") is True


def test_rate_limited_429():
    r = classify_linemod_http(429, "Too Many Requests")
    assert r["outcome"] == "rate_limited"


def test_payload_too_large_413():
    r = classify_linemod_http(413, "Request Entity Too Large")
    assert r["outcome"] == "payload_too_large"


def test_payload_too_large_400_markers():
    r = classify_linemod_http(400, "payload too large for context length")
    assert r["outcome"] == "payload_too_large"


def test_error_other():
    r = classify_linemod_http(500, "internal boom")
    assert r["outcome"] == "error"


def test_mask_api_key():
    # Non-secret fixture only — never embed live keys in tests
    fixture_key = "sr-gl-fixture0000000000000000000001"
    masked = mask_api_key(fixture_key)
    assert masked.startswith("sr-gl-")
    assert fixture_key not in masked
    assert "fixture0000000000000000000001" not in masked
    assert mask_api_key(None) == "<missing>"


def test_get_api_key_from_env_only():
    with mock.patch.dict(os.environ, {}, clear=True):
        os.environ.pop("LINEMOD_API_KEY", None)
        with pytest.raises(RuntimeError):
            get_api_key()
    with mock.patch.dict(os.environ, {"LINEMOD_API_KEY": "sr-gl-testkey"}):
        assert get_api_key() == "sr-gl-testkey"


def test_test_linemod_fake_http_has_latency():
    class FakeResp:
        status_code = 403
        text = json.dumps({"error": "SECURITY_BLOCKED", "scanner": "x"})

    class FakeSession:
        def post(self, *a, **k):
            return FakeResp()

    with mock.patch.dict(os.environ, {"LINEMOD_API_KEY": "sr-gl-unittest"}):
        out = call_linemod("bad prompt", do_throttle=False, session=FakeSession())
    assert out["outcome"] == "blocked"
    assert "latency_ms" in out
    assert isinstance(out["latency_ms"], int)
    assert out["key_masked"] == "sr-gl-..."
