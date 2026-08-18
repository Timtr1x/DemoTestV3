"""Built-in dataset adapters (registration happens on import)."""
from __future__ import annotations

from . import legacy_v2  # noqa: F401  (registers LegacyV2Adapter)

__all__ = ["legacy_v2"]
