"""Storage layer: append-only result store + manifest helpers (plan §11, §23)."""
from __future__ import annotations

from .results import ResultStore, load_results, latest_outcomes

__all__ = ["ResultStore", "load_results", "latest_outcomes"]
