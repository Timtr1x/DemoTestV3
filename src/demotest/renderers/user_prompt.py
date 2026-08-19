"""UserPromptRenderer — plain user message (plan §8.1).

For the regression contract this MUST render the case content verbatim: a V2
Sample.prompt_text that becomes a SecurityCase(content=...) must produce the
exact same user message that V2 sent. No wrapper, no transformation.
"""
from __future__ import annotations

from ..core.models import SecurityCase
from .base import CaseRenderer
from .registry import register_renderer


@register_renderer
class UserPromptRenderer(CaseRenderer):
    renderer_name = "user_prompt"
    renderer_version = "v1"
    supported_channels = ("user_prompt",)

    def render(self, case: SecurityCase) -> str:
        self._check_channel(case)
        # Verbatim — no wrapper. This is what makes V2->V3 regression exact.
        return case.content
