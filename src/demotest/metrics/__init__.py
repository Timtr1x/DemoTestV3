"""Metrics — detection / leakage / grouping (plan §31-34)."""
from __future__ import annotations

from .common import Metrics, percentiles, safe_div
from .detection import compute_metrics
from .leakage import canary_leakage
from .grouping import group_by_attributes

__all__ = [
    "Metrics",
    "percentiles",
    "safe_div",
    "compute_metrics",
    "canary_leakage",
    "group_by_attributes",
]
