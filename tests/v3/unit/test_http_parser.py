"""V3 HTTP parser regression parity with V2 classify_linemod_http (Commit 3-4)."""
from __future__ import annotations

import json

from demotest.core.enums import Outcome
from demotest.targets.http_parser import (
    is_clear_outcome,
    parse_linemod_response,
)


def _v2_classify(status, body_text):
    """Inline copy of V2 classify_linemod_http for parity testing."""
    body_text = body_text or ""

    def _is_upstream_cooldown(status, body_or_err):
        text = (body_or_err or "").lower()
        if status == 503:
            markers = ("cooldown", "no upstream", "service_unavailable",
                       "service unavailable", "excluded_models")
            if any(m in text for m in markers):
                return True
            if "503" in text or text.strip() == "" or "httperror: 503" in text:
                return True
        if "cooldown" in text and "excluded_models" in text:
            return True
        return False

    if status == 403 and "SECURITY_BLOCKED" in body_text:
        return "blocked"
    if status == 200:
        return "passed"
    if status in (400, 413):
        lower = body_text.lower()
        oversize_markers = ("too large", "too long", "payload", "context length",
                            "maximum context", "request entity too large",
                            "content too long", "token")
        if status == 413 or any(m in lower for m in oversize_markers):
            return "payload_too_large"
    if _is_upstream_cooldown(status, body_text):
        return "passed_upstream_cooldown"
    if status == 429 or "Too Many Requests" in body_text:
        return "rate_limited"
    return "error"


# V2 outcome name -> V3 Outcome value
_V2_TO_V3 = {
    "blocked": Outcome.BLOCKED,
    "passed": Outcome.PASSED,
    "passed_upstream_cooldown": Outcome.UPSTREAM_COOLDOWN,
    "rate_limited": Outcome.RATE_LIMITED,
    "payload_too_large": Outcome.PAYLOAD_TOO_LARGE,
    "error": Outcome.ERROR,
}


PARITY_CASES = [
    (403, json.dumps({"error": "SECURITY_BLOCKED", "scanner": "prompt_guard"})),
    (200, json.dumps({"choices": [{"message": {"content": "ok"}}]})),
    (503, "model cooldown no upstream"),
    (503, ""),
    (503, "service_unavailable"),
    (429, "Too Many Requests"),
    (413, "Request Entity Too Large"),
    (400, "payload too large for context length"),
    (400, "some other 400 error"),
    (500, "internal boom"),
    (403, "SECURITY_BLOCKED"),
    (403, json.dumps({"error": {"code": "SECURITY_BLOCKED", "scanner": "abuse_detection",
                                "score": 0.87, "policy": "standard"}})),
]


def test_parser_parity_with_v2():
    """For every case, V3 outcome must equal V2 outcome (modulo name)."""
    for status, body in PARITY_CASES:
        v2 = _v2_classify(status, body)
        v3 = parse_linemod_response(status, body).outcome
        assert v3 == _V2_TO_V3[v2], (
            f"parity mismatch status={status} body={body!r}: "
            f"v2={v2} v3={v3.value}"
        )


def test_blocked_extracts_scanner_policy_score():
    body = json.dumps({
        "error": {
            "code": "SECURITY_BLOCKED",
            "scanner": "abuse_detection",
            "policy": "standard",
            "score": 0.87,
        }
    })
    obs = parse_linemod_response(403, body)
    assert obs.outcome == Outcome.BLOCKED
    assert obs.security_blocked is True
    assert obs.scanner == "abuse_detection"
    assert obs.policy == "standard"
    assert obs.score == 0.87
    assert "scanner=abuse_detection" in obs.security_flag


def test_passed_extracts_response_content():
    body = json.dumps({"choices": [{"message": {"content": "hello world"}}]})
    obs = parse_linemod_response(200, body)
    assert obs.outcome == Outcome.PASSED
    assert obs.response_text == "hello world"


def test_cooldown_retryable():
    obs = parse_linemod_response(503, "model cooldown excluded_models")
    assert obs.outcome == Outcome.UPSTREAM_COOLDOWN
    assert obs.note == "guard_passed_model_cooldown"


def test_is_clear_outcome_matches_v2():
    assert is_clear_outcome(Outcome.BLOCKED)
    assert is_clear_outcome(Outcome.PASSED)
    assert is_clear_outcome(Outcome.UPSTREAM_COOLDOWN)
    assert is_clear_outcome(Outcome.PAYLOAD_TOO_LARGE)
    assert not is_clear_outcome(Outcome.RATE_LIMITED)
    assert not is_clear_outcome(Outcome.ERROR)
    # string form
    assert is_clear_outcome("blocked")
    assert is_clear_outcome("passed_upstream_cooldown")
