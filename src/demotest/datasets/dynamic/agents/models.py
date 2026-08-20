"""Agent config + provenance — API keys never serialized."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class AgentConfig:
    provider: str = "openai_compatible"
    base_url_env: str = "AGENT_BASE_URL"
    api_key_env: str = "AGENT_API_KEY"
    model: str = ""
    temperature: float = 0.0
    max_tokens: int = 2048


@dataclass(frozen=True)
class AgentProvenance:
    agent_driver: str = "openai_compatible"
    agent_driver_version: str = "1.0.0"
    provider: str = ""
    base_url_hash: str = ""
    model: str = ""
    temperature: float = 0.0
    agent_prompt_version: str = "p4-agent-diff-v1"

    def to_dict(self) -> dict[str, str | float]:
        return {
            "agent_driver": self.agent_driver,
            "agent_driver_version": self.agent_driver_version,
            "provider": self.provider,
            "base_url_hash": self.base_url_hash,
            "model": self.model,
            "temperature": self.temperature,
            "agent_prompt_version": self.agent_prompt_version,
        }

    @staticmethod
    def hash_url(url: str) -> str:
        return hashlib.sha256(url.encode()).hexdigest()[:16]
