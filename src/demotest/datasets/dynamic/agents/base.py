"""AgentDriver ABC — model proposes actions, sandbox executes them."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ToolCall:
    name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    call_id: str = ""


@dataclass(frozen=True)
class AgentTurn:
    assistant_text: str = ""
    tool_calls: tuple[ToolCall, ...] = ()
    usage: dict[str, Any] = field(default_factory=dict)
    finish_reason: str = ""
    provider_metadata: dict[str, Any] = field(default_factory=dict)


class AgentDriver(ABC):
    """Host-side driver: inference only, never executes skills directly."""

    @abstractmethod
    def run_turn(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> AgentTurn:
        ...

    @property
    @abstractmethod
    def provenance(self) -> dict[str, str]:
        ...
