"""CaseRenderer abstract base (plan §7, F8)."""
from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum

from ..core.exceptions import RendererError
from ..core.models import SecurityCase


class RenderFidelity(str, Enum):
    """How much *security semantics* the wrapper injects (external review F8).

    The benchmark's headline score MUST come from RAW, because wrapper labels
    like ``[UNTRUSTED_EXTERNAL_CONTENT]`` can tell the gateway "this is
    untrusted" and inflate TPR relative to a real production request that carries
    no such hint. Reporting RAW / STRUCTURED / LABELED side-by-side turns that
    confound into a measured variable rather than a hidden one.

    * ``RAW`` — the case payload verbatim, no security wrapper at all. The
      closest approximation to what an uninstrumented production request looks
      like. This is the primary benchmark number.
    * ``STRUCTURED`` — the real transport envelope that production genuinely uses
      (a tool-result JSON object, an email header block, a tool-call args
      struct). Carries *structural* signal the gateway would see anyway, but no
      *security* labels.
    * ``LABELED`` — adds an explicit security label
      (``[UNTRUSTED_EXTERNAL_CONTENT]`` …). Measures "how much better does the
      gateway do when the business helpfully tags untrusted content?". An
      enhancement experiment, never the headline.
    """

    RAW = "raw"
    STRUCTURED = "structured"
    LABELED = "labeled"

    @classmethod
    def from_value(cls, v: str | "RenderFidelity") -> "RenderFidelity":
        if isinstance(v, cls):
            return v
        s = str(v or "").strip().lower()
        aliases = {"label": cls.LABELED, "struct": cls.STRUCTURED, "plain": cls.RAW}
        if s in aliases:
            return aliases[s]
        return cls(s)


class CaseRenderer(ABC):
    """Render a SecurityCase into the single user-message text sent to gateway.

    Responsibilities (exhaustive):
      * map a SecurityCase to a fixed-wrapper string at a given fidelity tier
      * be deterministic and stable per version

    MUST NOT: generate attack payloads, send requests, judge outcomes.
    The payload is whatever ``content`` / context the case already carries.

    Fidelity (F8): every renderer supports three tiers. ``render`` produces the
    LABELED form by default (back-compat with v1 wrappers); ``render_raw`` /
    ``render_structured`` are the RAW / STRUCTURED variants. The runner stamps
    which tier produced a result so reports break TPR down by fidelity.
    """

    renderer_name: str = "unknown"
    renderer_version: str = "v1"
    # which channels this renderer accepts; others raise RendererError
    supported_channels: tuple[str, ...] = ()

    def __init__(self, fidelity: RenderFidelity | str = RenderFidelity.LABELED) -> None:
        self.fidelity = RenderFidelity.from_value(fidelity)

    @abstractmethod
    def render(self, case: SecurityCase) -> str:
        raise NotImplementedError

    @property
    def full_version(self) -> str:
        return f"{self.renderer_name}/{self.renderer_version}"

    @property
    def fidelity_tag(self) -> str:
        return self.fidelity.value

    def render_for_fidelity(self, case: SecurityCase) -> str:
        """Dispatch to the tier this instance was constructed for."""
        if self.fidelity is RenderFidelity.RAW:
            return self.render_raw(case)
        if self.fidelity is RenderFidelity.STRUCTURED:
            return self.render_structured(case)
        return self.render(case)

    def render_raw(self, case: SecurityCase) -> str:
        """RAW tier: payload verbatim, no security wrapper.

        Defaults to the case content — the closest thing to an uninstrumented
        production request. Override when a channel has a non-content payload
        (e.g. tool_call args).
        """
        self._check_channel(case)
        return case.content

    def render_structured(self, case: SecurityCase) -> str:
        """STRUCTURED tier: real transport envelope, no security labels.

        Defaults to the LABELED render with only the security label stripped, so
        channels without a distinct structured form still degrade gracefully.
        """
        self._check_channel(case)
        return self.render(case)

    def _check_channel(self, case: SecurityCase) -> None:
        if self.supported_channels and case.channel.value not in self.supported_channels:
            raise RendererError(
                f"{self.renderer_name} does not support channel "
                f"{case.channel.value!r} (supports {self.supported_channels})"
            )
