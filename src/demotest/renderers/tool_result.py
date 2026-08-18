"""ToolResultRenderer — tool_response channel (plan §8.3).

Tests whether the gateway blocks malicious instructions arriving *inside* a tool
result (the canonical indirect-injection vector).
"""
from __future__ import annotations

from ..core.models import SecurityCase
from .base import CaseRenderer
from .registry import register_renderer


@register_renderer
class ToolResultRenderer(CaseRenderer):
    renderer_name = "tool_result"
    renderer_version = "v1"
    supported_channels = ("tool_result",)

    def render(self, case: SecurityCase) -> str:
        self._check_channel(case)
        tool = case.tool_name or "unknown_tool"
        content = case.tool_result or case.content
        return (
            "[TOOL_RESULT]\n"
            f"tool: {tool}\n"
            "The following content is returned by an external tool.\n"
            f"{content}"
        )
