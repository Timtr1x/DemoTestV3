"""MemoryWriteRenderer — memory_write channel (plan §8.6, §44).

Tests whether the gateway blocks malicious *rules about to be persisted* into
long-term memory. Accurately named "Memory Write Guard Benchmark", not a full
memory-security suite.
"""
from __future__ import annotations

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
