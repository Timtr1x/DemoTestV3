"""LineMod HTTP response parser — pure function, no network (plan §11).

This is the V3 extraction of V2's ``classify_linemod_http``. The outcome
classification logic is preserved *exactly* so the V2→V3 regression contract
holds: same HTTP status + body -> same outcome.

V3 splits V2's single dict into a structured :class:`GatewayObservation`:
transport (http_status/latency) is separated from security signal
(scanner/policy/score), and outcome is derived as a property rather than
stuffed into a dict.
"""
from __future__ import annotations

import json
from typing import Any

from ..core.contracts import GatewayObservation
from ..core.enums import Outcome

# Same markers as V2 linemod_guard_client._is_upstream_cooldown
_COOLDOWN_MARKERS = (
    "cooldown",
    "no upstream",
    "service_unavailable",
    "service unavailable",
    "excluded_models",
)

# Same markers as V2 for oversize classification on 400/413
_OVERSIZE_MARKERS = (
    "too large",
    "too long",
    "payload",
    "context length",
    "maximum context",
    "request entity too large",
    "content too long",
    "token",
)


def _is_upstream_cooldown(status: int | None, body_or_err: str) -> bool:
    text = (body_or_err or "").lower()
    if status == 503:
        if any(m in text for m in _COOLDOWN_MARKERS):
            return True
        if "503" in text or text.strip() == "" or "httperror: 503" in text:
            return True
    if "cooldown" in text and "excluded_models" in text:
        return True
    return False


def _extract_security_flag(body_text: str) -> str:
    """Pull scanner / rule identifiers from a 403 body (mirrors V2)."""
    if not body_text:
        return ""
    try:
        data = json.loads(body_text)
    except Exception:
        if "SECURITY_BLOCKED" in body_text:
            return body_text[:500]
        return body_text[:200]

    parts: list[str] = []
    if isinstance(data, dict):
        for key in ("scanner", "flag", "rule", "rule_name", "security_flag", "code", "error"):
            val = data.get(key)
            if val is not None:
                parts.append(f"{key}={val}")
        err = data.get("error")
        if isinstance(err, dict):
            for key in ("type", "code", "message", "scanner"):
                if err.get(key) is not None:
                    parts.append(f"error.{key}={err[key]}")
        detail = data.get("detail")
        if isinstance(detail, dict):
            for key in ("scanner", "rule", "flag"):
                if detail.get(key) is not None:
                    parts.append(f"detail.{key}={detail[key]}")
    if parts:
        return ";".join(parts)
    if "SECURITY_BLOCKED" in body_text:
        return "SECURITY_BLOCKED"
    return body_text[:200]


def _extract_score(body_text: str) -> float | None:
    """Best-effort score extraction from a blocked body (plan §33)."""
    if not body_text:
        return None
    try:
        data = json.loads(body_text)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    # scan common nested locations
    candidates = [data.get("score")]
    err = data.get("error") if isinstance(data.get("error"), dict) else {}
    if isinstance(err, dict):
        candidates.append(err.get("score"))
    detail = data.get("detail") if isinstance(data.get("detail"), dict) else {}
    if isinstance(detail, dict):
        candidates.append(detail.get("score"))
    meta = data.get("meta") if isinstance(data.get("meta"), dict) else {}
    if isinstance(meta, dict):
        candidates.append(meta.get("score"))
    for c in candidates:
        if c is None:
            continue
        try:
            return float(c)
        except (TypeError, ValueError):
            continue
    return None


def _extract_scanner_policy(body_text: str) -> tuple[str, str]:
    """Best-effort scanner / policy extraction (plan §33)."""
    if not body_text:
        return "", ""
    try:
        data = json.loads(body_text)
    except Exception:
        return "", ""
    if not isinstance(data, dict):
        return "", ""

    def _g(obj: Any, *keys: str) -> str:
        if not isinstance(obj, dict):
            return ""
        for k in keys:
            v = obj.get(k)
            if v:
                return str(v)
        return ""

    err = data.get("error") if isinstance(data.get("error"), dict) else {}
    detail = data.get("detail") if isinstance(data.get("detail"), dict) else {}
    scanner = _g(data, "scanner") or _g(err, "scanner") or _g(detail, "scanner")
    policy = _g(data, "policy") or _g(err, "policy") or _g(detail, "policy")
    return scanner, policy


def _extract_response_content(body_text: str) -> str:
    """Pull the returned assistant content from a 200 body (V2-compatible)."""
    if not body_text:
        return ""
    try:
        msg = json.loads(body_text)["choices"][0]["message"]
        return str(msg.get("content") or "")
    except Exception:
        return ""


def parse_linemod_response(status: int, body_text: str) -> GatewayObservation:
    """Pure outcome classifier -> GatewayObservation (no network).

    V3 outcome values differ in name only from V2:
      V2 "passed_upstream_cooldown"  ==  V3 Outcome.UPSTREAM_COOLDOWN
    """
    body_text = body_text or ""

    obs = GatewayObservation(http_status=status or 0, raw_body=body_text[:2000])

    # 403 + SECURITY_BLOCKED -> blocked
    if status == 403 and "SECURITY_BLOCKED" in body_text:
        obs.security_blocked = True
        obs.gateway_action = "blocked"
        obs.security_flag = _extract_security_flag(body_text)
        obs.scanner, obs.policy = _extract_scanner_policy(body_text)
        obs.score = _extract_score(body_text)
        return obs

    # 200 -> passed (extract returned content for canary echo)
    if status == 200:
        obs.gateway_action = "allowed"
        obs.response_text = _extract_response_content(body_text)[:2000]
        return obs

    # 400/413 oversize
    if status in (400, 413):
        lower = body_text.lower()
        if status == 413 or any(m in lower for m in _OVERSIZE_MARKERS):
            obs.payload_too_large = True
            obs.gateway_action = "payload_too_large"
            return obs

    # 503 upstream cooldown
    if _is_upstream_cooldown(status, body_text):
        obs.upstream_cooldown = True
        obs.gateway_action = "cooldown"
        obs.note = "guard_passed_model_cooldown"
        return obs

    # 429 rate limited
    if status == 429 or "Too Many Requests" in body_text:
        obs.rate_limited = True
        obs.gateway_action = "rate_limited"
        obs.error_type = "HTTPError: 429 Too Many Requests"
        return obs

    # everything else -> error (retryable for 5xx / 0 / None)
    obs.error_type = "HTTPError: %s %s" % (status, body_text[:120])
    return obs


def parse_transport_error(exc: BaseException, status: int = 0) -> GatewayObservation:
    """Build an observation from a transport-layer exception (timeout / conn)."""
    name = type(exc).__name__
    obs = GatewayObservation(http_status=status, raw_body="", error_type=f"{name}: {str(exc)[:150]}")
    if name == "Timeout":
        obs.note = "transport_timeout"
    else:
        obs.note = "transport_error"
    return obs


# Convenience: which outcomes are "clear enough" to count in metrics.
# Mirrors V2 CLEAR_OUTCOMES so regression parity is exact.
def is_clear_outcome(outcome: Outcome | str) -> bool:
    if isinstance(outcome, str):
        outcome = Outcome.from_value(outcome)
    return outcome in (
        Outcome.BLOCKED,
        Outcome.PASSED,
        Outcome.UPSTREAM_COOLDOWN,
        Outcome.PAYLOAD_TOO_LARGE,
    )
