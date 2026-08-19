"""Target adapters: send GatewayRequest -> GatewayObservation (plan §9, §37).

A TargetAdapter owns transport (URL / auth / headers / timeout / retry) and
response parsing. It knows nothing about datasets, cases, oracles, or metrics.
"""
from __future__ import annotations

from .base import TargetAdapter, TargetType
from .linemod import LineModTargetAdapter
from .qwen_guard import QwenGuardTargetAdapter

__all__ = [
    "TargetAdapter",
    "TargetType",
    "LineModTargetAdapter",
    "QwenGuardTargetAdapter",
]
