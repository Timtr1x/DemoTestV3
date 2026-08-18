"""CredentialFlowRenderer — secret propagation across channels (plan §8.7).

Not a content source of its own: it renders a credential-bearing payload on top
of another channel's wrapper. Used for P4 (Credential Flow Guard) to test
whether a secret exfiltrates through tool args, memory writes, outbound
responses, etc.

The credential marker used by the benchmark is always a fake canary
(e.g. ``TEST_SECRET_7B021C``), never a real secret.
"""
from __future__ import annotations

import json

from ..core.exceptions import RendererError
from ..core.models import SecurityCase
from .base import CaseRenderer
from .registry import register_renderer


def _format_credential_block(markers: list[str]) -> str:
    """Render the credential markers into a stable block."""
    if not markers:
        return "(no credentials in scope)"
    return "\n".join(f"- {m}" for m in markers)


@register_renderer
class CredentialFlowRenderer(CaseRenderer):
    """Render credential flow on top of another channel's structure.

    ``base_channel`` selects the underlying wrapper (tool_call / memory_write /
    outbound / user_prompt / tool_result). The credential payload (the body that
    *would* carry the secret) comes from ``case.content`` / ``tool_arguments``.
    """

    renderer_name = "credential_flow"
    renderer_version = "v1"
    # credential_flow composes over other channels, so accept all of them
    supported_channels = (
        "user_prompt",
        "tool_result",
        "tool_call",
        "memory_write",
        "outbound_response",
    )

    def render(self, case: SecurityCase) -> str:
        self._check_channel(case)
        ch = case.channel.value
        cred_block = _format_credential_block(list(case.credential_markers))
        header = (
            "[CREDENTIAL_FLOW_CHECK]\n"
            f"base_channel: {ch}\n"
            f"credentials_in_scope:\n{cred_block}\n"
        )
        body = self._render_base_body(case, ch)
        return header + "\n" + body

    def _render_base_body(self, case: SecurityCase, ch: str) -> str:
        if ch == "tool_call":
            if not case.tool_name:
                raise RendererError("credential_flow+tool_call requires tool_name")
            args = case.tool_arguments or {}
            args_json = json.dumps(args, ensure_ascii=False, indent=2, sort_keys=True)
            return (
                "Tool:\n"
                f"{case.tool_name}\n\n"
                "Arguments:\n"
                f"{args_json}\n\n"
                f"User intent:\n{case.user_intent or '(unspecified)'}"
            )
        if ch == "memory_write":
            target = case.memory_target or "(unspecified)"
            return (
                "memory_target:\n"
                f"{target}\n\n"
                "Content to persist:\n"
                f"{case.content}"
            )
        if ch == "outbound_response":
            return (
                "Outbound response that may carry a secret:\n"
                f"{case.content}"
            )
        if ch == "tool_result":
            tool = case.tool_name or "unknown_tool"
            content = case.tool_result or case.content
            return f"tool: {tool}\nresult:\n{content}"
        # user_prompt fallback
        return case.content
