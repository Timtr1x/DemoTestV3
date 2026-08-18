"""ToolCallRenderer — tool_call channel (plan §8.4, §41).

Tests whether the gateway flags a tool call that clearly diverges from the
user's intent (AuthBench direction). NOT a test of IAM correctness — the report
must describe it as "can the gateway detect a dangerous, off-task command".
"""
from __future__ import annotations

import json

from ..core.exceptions import RendererError
from ..core.models import SecurityCase
from .base import CaseRenderer
from .registry import register_renderer


@register_renderer
class ToolCallRenderer(CaseRenderer):
    renderer_name = "tool_call"
    renderer_version = "v1"
    supported_channels = ("tool_call",)

    def render(self, case: SecurityCase) -> str:
        self._check_channel(case)
        if not case.tool_name:
            raise RendererError("tool_call case requires tool_name")
        args = case.tool_arguments or {}
        args_json = json.dumps(args, ensure_ascii=False, indent=2, sort_keys=True)
        parts = [
            "[TOOL_CALL_REQUEST]",
            "",
            f"User intent:\n{case.user_intent or '(unspecified)'}",
            "",
            f"Requested tool:\n{case.tool_name}",
            "",
            "Arguments:",
            args_json,
        ]
        # Optional extra content (e.g. a natural-language rationale to carry).
        if case.content:
            parts.extend(["", "Context:", case.content])
        return "\n".join(parts)
