"""OpenAI-compatible driver — reads AGENT_API_KEY only on Host."""
from __future__ import annotations

import json
import os
from typing import Any
from urllib import request as urlrequest
from urllib.error import HTTPError, URLError

from .base import AgentDriver, AgentTurn, ToolCall
from .models import AgentConfig, AgentProvenance


class OpenAICompatibleAgentDriver(AgentDriver):
    """Host-side driver for any OpenAI-compatible API (OpenAI/DeepSeek/Qwen/LineMod proxy)."""

    def __init__(self, config: AgentConfig | None = None) -> None:
        self.config = config or AgentConfig()
        base_url = os.environ.get(self.config.base_url_env, "").strip()
        api_key = os.environ.get(self.config.api_key_env, "")
        if not base_url:
            base_url = os.environ.get("OPENAI_BASE_URL", "").strip()
        if not api_key:
            api_key = os.environ.get("OPENAI_API_KEY", "")
        self._base_url = base_url.rstrip("/").removesuffix("/v1")
        self._api_key = api_key
        # Model is a benchmark variable — never silently default.
        self._model = (os.environ.get("AGENT_MODEL", "") or self.config.model or "").strip()

    def run_turn(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> AgentTurn:
        if not self._base_url or not self._api_key:
            raise RuntimeError(
                f"missing {self.config.base_url_env} or {self.config.api_key_env} — "
                "real API key must be set on Host, never in Docker"
            )
        if not self._model:
            raise RuntimeError("AGENT_MODEL is required for benchmark runs — refusing implicit model")
        url = f"{self._base_url}/v1/chat/completions"
        body = {
            "model": self._model,
            "messages": messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
        }
        if tools:
            body["tools"] = tools
            body["tool_choice"] = "auto"
        data = json.dumps(body).encode()
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._api_key}",
        }
        req = urlrequest.Request(url, data=data, headers=headers, method="POST")
        try:
            with urlrequest.urlopen(req, timeout=60) as resp:
                payload = json.loads(resp.read().decode("utf-8", errors="replace"))
        except HTTPError as e:
            raise RuntimeError(f"agent API HTTP {e.code}: {e.read().decode(errors='replace')[:600]}") from e
        except URLError as e:
            raise RuntimeError(f"agent API unreachable: {e}") from e

        choice = (payload.get("choices") or [{}])[0]
        msg = choice.get("message") or {}
        text = str(msg.get("content") or "")
        tool_calls: list[ToolCall] = []
        for tc in msg.get("tool_calls") or []:
            fn = tc.get("function") or {}
            args_raw = fn.get("arguments") or "{}"
            try:
                args = json.loads(args_raw) if isinstance(args_raw, str) else dict(args_raw)
            except Exception:
                args = {"_raw": args_raw}
            tool_calls.append(ToolCall(
                name=str(fn.get("name") or ""),
                arguments=args,
                call_id=str(tc.get("id") or ""),
            ))
        return AgentTurn(
            assistant_text=text,
            tool_calls=tuple(tool_calls),
            usage=dict(payload.get("usage") or {}),
            finish_reason=str(choice.get("finish_reason") or ""),
            provider_metadata={"model": payload.get("model", ""), "id": payload.get("id", "")},
        )

    @property
    def provenance(self) -> dict[str, str]:
        prov = AgentProvenance(
            provider=self.config.provider,
            base_url_hash=AgentProvenance.hash_url(self._base_url),
            model=self._model,
            temperature=self.config.temperature,
        )
        return {k: str(v) for k, v in prov.to_dict().items()}
