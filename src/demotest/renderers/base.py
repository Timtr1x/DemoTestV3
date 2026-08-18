"""CaseRenderer abstract base (plan §7)."""
from __future__ import annotations

from abc import ABC, abstractmethod

from ..core.exceptions import RendererError
from ..core.models import SecurityCase


class CaseRenderer(ABC):
    """Render a SecurityCase into the single user-message text sent to gateway.

    Responsibilities (exhaustive):
      * map a SecurityCase to a fixed-wrapper string
      * be deterministic and stable per version

    MUST NOT: generate attack payloads, send requests, judge outcomes.
    The payload is whatever ``content`` / context the case already carries.
    """

    renderer_name: str = "unknown"
    renderer_version: str = "v1"
    # which channels this renderer accepts; others raise RendererError
    supported_channels: tuple[str, ...] = ()

    @abstractmethod
    def render(self, case: SecurityCase) -> str:
        raise NotImplementedError

    @property
    def full_version(self) -> str:
        return f"{self.renderer_name}/{self.renderer_version}"

    def _check_channel(self, case: SecurityCase) -> None:
        if self.supported_channels and case.channel.value not in self.supported_channels:
            raise RendererError(
                f"{self.renderer_name} does not support channel "
                f"{case.channel.value!r} (supports {self.supported_channels})"
            )
