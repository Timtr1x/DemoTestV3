"""Agent-driven dynamic — provider-agnostic driver abstraction (guide P4 §5).

Deterministic Core (P4 Core v1) never needs a real API key. Agent-driven
differential runs Host-side and must keep the real API key on the Host —
never inside Docker, never in traces/manifests/logs.
"""
from .base import AgentDriver, AgentTurn, ToolCall
from .models import AgentConfig, AgentProvenance
from .openai_compatible import OpenAICompatibleAgentDriver

__all__ = [
    "AgentDriver",
    "AgentTurn",
    "ToolCall",
    "AgentConfig",
    "AgentProvenance",
    "OpenAICompatibleAgentDriver",
]
