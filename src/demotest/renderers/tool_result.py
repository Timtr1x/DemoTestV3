"""ToolResultRenderer — tool_result channel (plan §8.3, F8).

Three fidelity tiers (F8):
  * RAW         — just the result text, no tool framing
  * STRUCTURED  — a realistic tool-result envelope (tool name + the returned
                  content), no security label
  * LABELED     — the ``[TOOL_RESULT]`` wrapper (v1 default)

Tests whether the gateway blocks malicious instructions arriving *inside* a tool
result (the canonical indirect-injection vector).
"""
from __future__ import annotations

import json

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

    def render_structured(self, case: SecurityCase) -> str:
        self._check_channel(case)
        tool = case.tool_name or "unknown_tool"
        content = case.tool_result or case.content
        # A realistic tool-result payload the agent layer would actually receive.
        return json.dumps(
            {"tool": tool, "result": content},
            ensure_ascii=False,
            sort_keys=True,
        )

    def render_raw(self, case: SecurityCase) -> str:
        # RAW: the result text verbatim — no tool framing, no security label.
        self._check_channel(case)
        return case.tool_result or case.content
