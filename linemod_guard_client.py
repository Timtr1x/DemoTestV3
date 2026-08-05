"""LineMod pure-guard HTTP client — single egress for all projects.

Judgment contract (LINEMOD_TESTING):
  403 + SECURITY_BLOCKED  -> blocked
  200                     -> passed
  503 cooldown/no-upstream-> passed_upstream_cooldown
  429                     -> rate_limited (caller retries)
  400/413 oversize        -> payload_too_large
  else                    -> error

Env:
  LINEMOD_API_KEY (required for live calls; never commit)
  LINEMOD_MODEL, LINEMOD_URL, LINEMOD_REQUEST_GAP, LINEMOD_TIMEOUT, LINEMOD_MAX_ATTEMPTS
"""
from __future__ import annotations

import json
import os
import time
from typing import Any

import requests

LINEMOD_URL = os.environ.get(
    "LINEMOD_URL", "https://api.linemod.ai/v1/chat/completions"
)
LINEMOD_MODEL = os.environ.get("LINEMOD_MODEL", "deepseek-v4-flash")
REQUEST_GAP = float(os.environ.get("LINEMOD_REQUEST_GAP", "3.5"))
TIMEOUT = float(os.environ.get("LINEMOD_TIMEOUT", "60"))
MAX_ATTEMPTS = int(os.environ.get("LINEMOD_MAX_ATTEMPTS", "6"))

_last_call_ts = 0.0


def mask_api_key(key: str | None) -> str:
    """Log-safe key: at most first 6 characters + ellipsis."""
    if not key:
        return "<missing>"
    if len(key) <= 6:
        return key[:2] + "***"
    return key[:6] + "..."


def get_api_key() -> str:
    """Read key only from environment (no hardcoded secret in committed source)."""
    key = os.environ.get("LINEMOD_API_KEY", "").strip()
    if not key:
        raise RuntimeError(
            "LINEMOD_API_KEY is not set. Export it before live calls "
            f"(see config/env.example). masked={mask_api_key(None)}"
        )
    return key


def _throttle(gap: float | None = None) -> None:
    global _last_call_ts
    g = REQUEST_GAP if gap is None else gap
    now = time.time()
    wait = g - (now - _last_call_ts)
    if wait > 0:
        time.sleep(wait)
    _last_call_ts = time.time()


def _is_upstream_cooldown(status: int | None, body_or_err: str) -> bool:
    text = (body_or_err or "").lower()
    if status == 503:
        markers = (
            "cooldown",
            "no upstream",
            "service_unavailable",
            "service unavailable",
            "excluded_models",
        )
        if any(m in text for m in markers):
            return True
        if "503" in text or text.strip() == "" or "httperror: 503" in text:
            return True
    if "cooldown" in text and "excluded_models" in text:
        return True
    return False


def _extract_security_flag(body_text: str) -> str:
    """Pull scanner / rule identifiers from 403 body for analyze distributions."""
    if not body_text:
        return ""
    try:
        data = json.loads(body_text)
    except Exception:
        # keep a short raw snippet for offline review
        if "SECURITY_BLOCKED" in body_text:
            return body_text[:500]
        return body_text[:200]

    parts: list[str] = []
    if isinstance(data, dict):
        for key in ("scanner", "flag", "rule", "rule_name", "security_flag", "code", "error"):
            val = data.get(key)
            if val is not None:
                parts.append(f"{key}={val}")
        # nested error objects
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


def classify_linemod_http(status: int, body_text: str) -> dict[str, Any]:
    """Pure outcome classifier — unit-testable without network.

    Returns dict with at least: status, outcome, blocked, security_flag, response.
    Caller adds latency_ms / attempts / raw.
    """
    body_text = body_text or ""

    if status == 403 and "SECURITY_BLOCKED" in body_text:
        return {
            "blocked": True,
            "error": None,
            "status": 403,
            "outcome": "blocked",
            "security_flag": _extract_security_flag(body_text),
            "response": "",
        }
    if status == 200:
        content = ""
        try:
            msg = json.loads(body_text)["choices"][0]["message"]
            content = msg.get("content") or ""
        except Exception:
            pass
        return {
            "blocked": False,
            "error": None,
            "status": 200,
            "outcome": "passed",
            "security_flag": "",
            "response": (content or "")[:200],
        }
    if status in (400, 413):
        # oversize / bad request often used for payload limit
        lower = body_text.lower()
        oversize_markers = (
            "too large",
            "too long",
            "payload",
            "context length",
            "maximum context",
            "request entity too large",
            "content too long",
            "token",
        )
        if status == 413 or any(m in lower for m in oversize_markers):
            return {
                "blocked": False,
                "error": None,
                "status": status,
                "outcome": "payload_too_large",
                "security_flag": "",
                "response": "",
            }

    if _is_upstream_cooldown(status, body_text):
        return {
            "blocked": False,
            "error": None,
            "status": status or 503,
            "outcome": "passed_upstream_cooldown",
            "security_flag": "",
            "response": "",
            "note": "guard_passed_model_cooldown",
            "retryable_cooldown": True,
        }
    if status == 429 or "Too Many Requests" in body_text:
        return {
            "blocked": False,
            "error": "HTTPError: 429 Too Many Requests",
            "status": 429,
            "outcome": "rate_limited",
            "security_flag": "",
            "response": "",
            "retryable_cooldown": True,
        }
    return {
        "blocked": False,
        "error": "HTTPError: %s %s" % (status, body_text[:120]),
        "status": status or 0,
        "outcome": "error",
        "security_flag": "",
        "response": "",
        "retryable_cooldown": status in (0, 500, 502, 503, 504) or status is None,
    }


CLEAR_OUTCOMES = frozenset(
    {"blocked", "passed", "passed_upstream_cooldown", "payload_too_large"}
)
# Resume skips these (judged enough for metrics)
RESUME_CLEAR = CLEAR_OUTCOMES


def is_clear_outcome(outcome: str) -> bool:
    return outcome in RESUME_CLEAR


def test_linemod(
    prompt: str,
    *,
    timeout: int | float | None = None,
    do_throttle: bool = True,
    session: requests.Session | None = None,
) -> dict[str, Any]:
    """Call LineMod pure guard; return outcome dict with latency_ms.

    Signature extended with optional kwargs only — call sites using
    test_linemod(prompt) remain valid.
    """
    key = get_api_key()
    to = TIMEOUT if timeout is None else float(timeout)
    post = session.post if session is not None else requests.post

    if do_throttle:
        _throttle()

    t0 = time.perf_counter()
    try:
        r = post(
            LINEMOD_URL,
            json={
                "model": LINEMOD_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0,
                "max_tokens": 8,
            },
            headers={
                "Authorization": "Bearer %s" % key,
                "Content-Type": "application/json",
                "X-LineMod-No-Failover": "true",
            },
            timeout=to,
        )
        latency_ms = int((time.perf_counter() - t0) * 1000)
        classified = classify_linemod_http(r.status_code, r.text)
        classified["latency_ms"] = latency_ms
        classified["attempts"] = 1
        classified["raw"] = r.text[:2000] if r.text else ""
        # never log full key
        classified["key_masked"] = mask_api_key(key)
        return classified
    except requests.exceptions.Timeout:
        latency_ms = int((time.perf_counter() - t0) * 1000)
        return {
            "blocked": False,
            "error": "Timeout",
            "status": 0,
            "outcome": "error",
            "security_flag": "",
            "response": "",
            "latency_ms": latency_ms,
            "attempts": 1,
            "raw": "",
            "key_masked": mask_api_key(key),
            "retryable_cooldown": True,
        }
    except requests.exceptions.RequestException as e:
        latency_ms = int((time.perf_counter() - t0) * 1000)
        return {
            "blocked": False,
            "error": "%s: %s" % (type(e).__name__, str(e)[:150]),
            "status": 0,
            "outcome": "error",
            "security_flag": "",
            "response": "",
            "latency_ms": latency_ms,
            "attempts": 1,
            "raw": "",
            "key_masked": mask_api_key(key),
            "retryable_cooldown": True,
        }
