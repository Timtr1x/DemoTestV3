"""Dataset adapters: raw data -> SecurityCase (plan §18).

An adapter ONLY converts source data into ``SecurityCase`` objects. It must
never send network requests, judge gateway results, or compute metrics.
"""
from __future__ import annotations

from .base import DatasetAdapter
from .registry import get_adapter, register_adapter, registered_adapters

__all__ = [
    "DatasetAdapter",
    "get_adapter",
    "register_adapter",
    "registered_adapters",
]
