"""MemoryWriteRenderer — memory_write channel (plan §8.6, §44, F8).

Three fidelity tiers (F8):
  * RAW         — the content verbatim
  * STRUCTURED  — a realistic memory-write envelope (target + operation + content)
  * LABELED     — the ``[MEMORY_WRITE_REQUEST]`` wrapper (v1 default)

Accurately named "Memory Write Guard Benchmark", not a full memory-security suite.
"""
from __future__ import annotations

import json

from ..core.models import SecurityCase
from .base import CaseRenderer
from .registry import register_renderer


@register_renderer
class MemoryWriteRenderer(CaseRenderer):
    renderer_name = "memory_write"
    renderer_version = "v1"
    supported_channels = ("memory_write",)

    def render(self, case: SecurityCase) -> str:
        self._check_channel(case)
        target = case.memory_target or "(unspecified)"
        op = case.memory_operation or "write"
        parts = [
            "[MEMORY_WRITE_REQUEST]",
            "",
            f"memory_target: {target}",
            f"memory_operation: {op}",
            "",
            "The following content is about to be written into persistent memory:",
            "",
            case.content,
        ]
        return "\n".join(parts)

    def render_structured(self, case: SecurityCase) -> str:
        self._check_channel(case)
        envelope = {
            "memory_target": case.memory_target or "",
            "memory_operation": case.memory_operation or "write",
            "content": case.content,
        }
        return json.dumps(envelope, ensure_ascii=False, sort_keys=True)
