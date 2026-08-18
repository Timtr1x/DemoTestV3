"""LineMod TargetAdapter (plan §9, §10, §37).

Extracts the network layer from V2's ``linemod_guard_client.test_linemod``.
The request body is built to be byte-identical to V2 so the regression
contract holds:

    {"model": ..., "messages": [{"role":"user","content": <rendered_text>}],
     "temperature": 0, "max_tokens": 8}

with header ``X-LineMod-No-Failover: true``.

Benchmark-mode invariant (plan §10): if ``benchmark_mode`` is true and the
No-Failover header is absent/false, the adapter refuses to start. Without it a
guard block would silently fall back to a 200, corrupting the experiment.
"""
from __future__ import annotations

import os
import time
from typing import Any

import requests

from ..core.contracts import GatewayObservation, GatewayRequest
from ..core.exceptions import TargetError
from .base import TargetAdapter, TargetType
from .http_parser import parse_linemod_response, parse_transport_error

DEFAULT_URL = "https://api.linemod.ai/v1/chat/completions"
DEFAULT_MODEL = "deepseek-v4-flash"
NO_FAILOVER_HEADER = "X-LineMod-No-Failover"


def mask_api_key(key: str | None) -> str:
    """Log-safe key (mirrors V2). At most first 6 chars + ellipsis."""
    if not key:
        return "<missing>"
    if len(key) <= 6:
        return key[:2] + "***"
    return key[:6] + "..."


class LineModTargetAdapter(TargetAdapter):
    target_name = "linemod"
    target_type = TargetType.GATEWAY
    adapter_version = "1.0"

    def __init__(
        self,
        *,
        url: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        timeout: float = 60.0,
        benchmark_mode: bool = True,
        max_attempts: int = 6,
        extra_headers: dict[str, str] | None = None,
        session: requests.Session | None = None,
    ) -> None:
        self.url = url or os.environ.get("LINEMOD_URL", DEFAULT_URL)
        self.api_key = api_key or os.environ.get("LINEMOD_API_KEY", "").strip()
        self.model = model or os.environ.get("LINEMOD_MODEL", DEFAULT_MODEL)
        self.timeout = float(timeout)
        self.benchmark_mode = benchmark_mode
        self.max_attempts = max_attempts
        self._session = session
        self._headers = self._build_headers(extra_headers)
        self._validate_benchmark_mode()

    # ------------------------------------------------------------------ config
    def _build_headers(self, extra: dict[str, str] | None) -> dict[str, str]:
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            NO_FAILOVER_HEADER: "true",
        }
        if self.api_key:
            headers["Authorization"] = "Bearer %s" % self.api_key
        if extra:
            headers.update(extra)
        return headers

    def _validate_benchmark_mode(self) -> None:
        if not self.benchmark_mode:
            return
        val = self._headers.get(NO_FAILOVER_HEADER, "").lower()
        if val != "true":
            raise TargetError(
                "benchmark_mode=True requires X-LineMod-No-Failover=true; "
                "without it a guard block silently falls back to 200 and "
                "corrupts the experiment."
            )

    # ------------------------------------------------------------------ build
    def build_request(
        self,
        *,
        rendered_text: str,
        model: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 8,
    ) -> GatewayRequest:
        body = {
            "model": model or self.model,
            "messages": [{"role": "user", "content": rendered_text}],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        return GatewayRequest(
            target=self.target_name,
            url=self.url,
            method="POST",
            headers=dict(self._headers),
            json_body=body,
            model=body["model"],
            timeout=self.timeout,
            rendered_text=rendered_text,
        )

    # ------------------------------------------------------------------ exec
    def execute(self, request: GatewayRequest) -> GatewayObservation:
        post = self._session.post if self._session is not None else requests.post
        t0 = time.perf_counter()
        try:
            r = post(
                request.url,
                json=request.json_body,
                headers=request.headers,
                timeout=request.timeout,
            )
            latency_ms = int((time.perf_counter() - t0) * 1000)
            obs = parse_linemod_response(r.status_code, r.text)
            obs.latency_ms = latency_ms
            obs.attempts = 1
            return obs
        except requests.exceptions.Timeout as e:
            obs = parse_transport_error(e, status=0)
            obs.latency_ms = int((time.perf_counter() - t0) * 1000)
            return obs
        except requests.exceptions.RequestException as e:
            obs = parse_transport_error(e, status=0)
            obs.latency_ms = int((time.perf_counter() - t0) * 1000)
            return obs

    # ------------------------------------------------------------------ misc
    def key_masked(self) -> str:
        return mask_api_key(self.api_key)

    def config_summary(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "model": self.model,
            "timeout": self.timeout,
            "benchmark_mode": self.benchmark_mode,
            "no_failover": self._headers.get(NO_FAILOVER_HEADER, ""),
            "key_masked": self.key_masked(),
        }
