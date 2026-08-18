"""MCPDefinitionRenderer — mcp_definition channel (plan §8.5, §42).

Tests whether a tool *definition* (description / schema) contains dangerous or
deceptive behaviour. The renderer must not drop schema fields (required, type,
description, default) — DCI adapters will rely on that fidelity later.
"""
from __future__ import annotations

import json

from ..core.exceptions import RendererError
from ..core.models import SecurityCase
from .base import CaseRenderer
from .registry import register_renderer


@register_renderer
class MCPDefinitionRenderer(CaseRenderer):
    renderer_name = "mcp_definition"
    renderer_version = "v1"
    supported_channels = ("mcp_definition",)

    def render(self, case: SecurityCase) -> str:
        self._check_channel(case)
        if not case.mcp_tool:
            raise RendererError("mcp_definition case requires mcp_tool")
        schema = case.mcp_schema or {}
        # Stable serialization so schema field deltas show in the request hash.
        schema_json = json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True)
        parts = [
            "[MCP_TOOL_DEFINITION]",
            "",
            f"Server:\n{case.mcp_server or '(unspecified)'}",
            "",
            f"Tool:\n{case.mcp_tool}",
            "",
            f"Description:\n{case.mcp_description or '(none)'}",
            "",
            "Input schema:",
            schema_json,
        ]
        return "\n".join(parts)
