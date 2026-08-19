"""Qwen3Guard TargetAdapter (plan §39).

Qwen Guard is a *classifier*, not a gateway: it returns a Safety label rather
than an HTTP 403. We keep the adapter interface identical so the analyzer can
place Gateway Decision next to Classifier Decision, but the report must state
that their security responsibilities differ.

Judgment (mirrors V2 qwen3guard_client):
  Safety: Safe               -> passed
  Unsafe / Controversial /   -> blocked
  missing / parse fail
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from typing import Any

from ..core.contracts import GatewayObservation, GatewayRequest
from .base import TargetAdapter, TargetType

DEFAULT_URL = "http://192.168.66.13:8100/v1/chat/completions"
DEFAULT_MODEL = "Qwen/Qwen3Guard-Gen-0.6B"
_SAFE_RE = re.compile(r"Safety:\s*(Safe|Unsafe|Controversial)", re.I)


def _extract_safety(content: str) -> str | None:
    m = _SAFE_RE.search(content or "")
    if not m:
        return None
    raw = m.group(1)
    return {"safe": "Safe", "unsafe": "Unsafe", "controversial": "Controversial"}.get(
        raw.lower(), raw
    )


class QwenGuardTargetAdapter(TargetAdapter):
    target_name = "qwen3guard"
    target_type = TargetType.CLASSIFIER
    adapter_version = "1.0"

    def __init__(
        self,
        *,
        url: str | None = None,
        model: str | None = None,
        timeout: float = 120.0,
        max_tokens: int = 64,
    ) -> None:
        self.url = url or os.environ.get("QWEN3GUARD_URL", DEFAULT_URL)
        self.model = model or os.environ.get("QWEN3GUARD_MODEL", DEFAULT_MODEL)
        self.timeout = float(timeout)
        self.max_tokens = max_tokens

    def build_request(
        self,
        *,
        rendered_text: str,
        model: str | None = None,
        temperature: float = 0.0,
        max_tokens: int | None = None,
    ) -> GatewayRequest:
        body = {
            "model": model or self.model,
            "messages": [{"role": "user", "content": rendered_text}],
            "temperature": temperature,
            "max_tokens": self.max_tokens if max_tokens is None else max_tokens,
        }
        return GatewayRequest(
            target=self.target_name,
            url=self.url,
            method="POST",
            headers={"Content-Type": "application/json"},
            json_body=body,
            model=body["model"],
            timeout=self.timeout,
            rendered_text=rendered_text,
        )

    def execute(self, request: GatewayRequest) -> GatewayObservation:
        data = json.dumps(request.json_body).encode("utf-8")
        req = urllib.request.Request(
            request.url,
            data=data,
            headers=request.headers,
            method="POST",
        )
        t0 = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=request.timeout) as resp:
                status = resp.status
                raw = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            latency_ms = int((time.perf_counter() - t0) * 1000)
            err_body = e.read().decode("utf-8", errors="replace") if e.fp else ""
            obs = GatewayObservation(
                http_status=e.code,
                raw_body=err_body[:2000],
                error_type=f"HTTPError {e.code}: {err_body[:300]}",
                latency_ms=latency_ms,
            )
            return obs
        except Exception as e:
            latency_ms = int((time.perf_counter() - t0) * 1000)
            obs = GatewayObservation(
                http_status=0,
                error_type=f"{type(e).__name__}: {e}",
                latency_ms=latency_ms,
            )
            return obs

        latency_ms = int((time.perf_counter() - t0) * 1000)
        try:
            payload = json.loads(raw)
            content = payload.get("choices", [{}])[0].get("message", {}).get("content", "")
        except Exception as e:
            return GatewayObservation(
                http_status=status,
                raw_body=raw[:2000],
                error_type=f"parse: {e}",
                latency_ms=latency_ms,
            )
        obs = GatewayObservation(http_status=status, raw_body=raw[:2000], latency_ms=latency_ms)
        safety = _extract_safety(content)
        obs.note = f"qwen3guard safety={safety}"
        if safety == "Safe":
            obs.gateway_action = "allowed"
            obs.response_text = content
        else:
            # Unsafe / Controversial / None -> blocked
            obs.security_blocked = True
            obs.gateway_action = "blocked"
            obs.scanner = "qwen3guard"
            obs.security_flag = f"safety={safety}"
        return obs
