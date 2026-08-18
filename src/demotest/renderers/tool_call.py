"""ToolCallRenderer — tool_call channel (plan §8.4, §41, F8, F12).

Three fidelity tiers (F8):
  * RAW         — a plain-language description of the call (closest to what a
                  user might type), no struct
  * STRUCTURED  — a realistic tool-call envelope (tool + args), no security label
  * LABELED     — the ``[TOOL_CALL_REQUEST]`` wrapper (v1 default)

F12: an optional ``authorization_context`` (subject/role/granted_permissions/
task_scope/resource/requested_action) is rendered into STRUCTURED and LABELED
output so P2 can test whether the gateway flags an obviously over-privileged
call. NOT a test of IAM correctness — the gateway only sees this as text; the
report must describe it as "can the gateway detect a dangerous, off-task /
off-scope command".
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
        _append_auth(parts, case)
        if case.content:
            parts.extend(["", "Context:", case.content])
        return "\n".join(parts)

    def render_structured(self, case: SecurityCase) -> str:
        self._check_channel(case)
        if not case.tool_name:
            raise RendererError("tool_call case requires tool_name")
        args = case.tool_arguments or {}
        # A realistic tool-call envelope the agent framework would dispatch.
        envelope: dict = {
            "tool": case.tool_name,
            "arguments": args,
        }
        if case.user_intent:
            envelope["user_intent"] = case.user_intent
        if case.authorization_context:
            envelope["authorization"] = dict(case.authorization_context)
        return json.dumps(envelope, ensure_ascii=False, sort_keys=True)

    def render_raw(self, case: SecurityCase) -> str:
        # RAW for tool_call: a plain-language statement of what is about to happen.
        self._check_channel(case)
        if not case.tool_name:
            raise RendererError("tool_call case requires tool_name")
        intent = case.user_intent or "(unspecified intent)"
        return f"Calling tool {case.tool_name} for: {intent}."


def _append_auth(parts: list[str], case: SecurityCase) -> None:
    ac = case.authorization_context or {}
    if not ac:
        return
    parts.extend(
        [
            "",
            "Authorization context:",
            json.dumps(ac, ensure_ascii=False, indent=2, sort_keys=True),
        ]
    )
