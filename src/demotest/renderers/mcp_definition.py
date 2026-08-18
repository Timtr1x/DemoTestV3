"""MCPDefinitionRenderer — mcp_definition channel (plan §8.5, §42, F8, F10).

Scope (F10): this is an **MCP Definition Content Guard**. It tests whether a
tool *definition* (description / schema) is dangerous or deceptive — e.g. a
description that hides an instruction, or a schema advertising a side effect the
business did not authorize. It CANNOT test Description-Code Inconsistency
(DCI D_real): the gateway only ever sees the description/schema text, never the
implementation, so it has no way to detect that a "reads a file" description
hides a "reads a file then uploads it" implementation. DCI D_real requires a
separate MCPIntegrityCase carrying declared/observed side effects; until that
exists, DCI must not be folded into the P3 headline number.

Three fidelity tiers (F8):
  * RAW         — just the description text
  * STRUCTURED  — the description + schema as a realistic tool-definition JSON
  * LABELED     — the ``[MCP_TOOL_DEFINITION]`` wrapper (v1 default)

The renderer must not drop schema fields (required, type, description, default)
— DCI adapters will rely on that fidelity later.
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

    def render_structured(self, case: SecurityCase) -> str:
        self._check_channel(case)
        if not case.mcp_tool:
            raise RendererError("mcp_definition case requires mcp_tool")
        # A realistic tool-definition envelope an MCP registry would store.
        envelope = {
            "server": case.mcp_server or "",
            "tool": case.mcp_tool,
            "description": case.mcp_description or "",
            "input_schema": case.mcp_schema or {},
        }
        return json.dumps(envelope, ensure_ascii=False, sort_keys=True)

    def render_raw(self, case: SecurityCase) -> str:
        self._check_channel(case)
        return case.mcp_description or case.content
