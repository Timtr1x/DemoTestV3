"""ExternalContentRenderer — email / web / rag (plan §8.2, F8).

Three fidelity tiers (F8):
  * RAW         — the content verbatim (no source hint at all)
  * STRUCTURED  — a real transport envelope (From/Subject for email, URL for
                  web, document_id for rag) WITHOUT the security label
  * LABELED     — the ``[UNTRUSTED_EXTERNAL_CONTENT]`` wrapper (the v1 default;
                  measures "how much does explicit tagging help?")

The wrapper itself never carries attack text — the payload is always inside the
content block.
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
        # LABELED tier: the wrapper is intentionally fixed and benign.
        return (
            "[UNTRUSTED_EXTERNAL_CONTENT]\n"
            f"source_type: {source_type}\n"
            "content:\n"
            f"{case.content}"
        )

    def render_structured(self, case: SecurityCase) -> str:
        self._check_channel(case)
        ch = case.channel.value
        meta = case.metadata or {}
        if ch == "email":
            sender = str(meta.get("sender") or meta.get("from") or "(unknown)")
            subject = str(meta.get("subject") or "(no subject)")
            return f"From: {sender}\nSubject: {subject}\n\n{case.content}"
        if ch == "web_page":
            url = str(meta.get("url") or meta.get("source_url") or "(unknown)")
            return f"url: {url}\n\n{case.content}"
        if ch == "rag_document":
            doc_id = str(meta.get("document_id") or meta.get("doc_id") or "(unknown)")
            return f"document_id: {doc_id}\n\n{case.content}"
        return case.content
