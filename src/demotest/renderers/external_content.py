"""ExternalContentRenderer — email / web / rag (plan §8.2).

Wraps untrusted external content in a FIXED marker. The wrapper itself never
carries attack text — the payload is always inside the content block.
"""
from __future__ import annotations

from ..core.models import SecurityCase
from .base import CaseRenderer
from .registry import register_renderer

_SOURCE_TYPE = {
    "email": "email",
    "web_page": "web_page",
    "rag_document": "rag_document",
}


@register_renderer
class ExternalContentRenderer(CaseRenderer):
    renderer_name = "external_content"
    renderer_version = "v1"
    supported_channels = ("email", "web_page", "rag_document")

    def render(self, case: SecurityCase) -> str:
        self._check_channel(case)
        source_type = _SOURCE_TYPE.get(case.channel.value, case.channel.value)
        # The wrapper is intentionally fixed and benign.
        return (
            "[UNTRUSTED_EXTERNAL_CONTENT]\n"
            f"source_type: {source_type}\n"
            "content:\n"
            f"{case.content}"
        )
