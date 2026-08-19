"""Oracles — decide whether an observation is correct for a case (plan §13).

An Oracle decouples *what the gateway returned* (observation) from *whether that
is correct* (verdict). V2 had a single implicit BlockPassOracle; V3 makes it
explicit and adds CanaryOracle + CompositeOracle.
"""
from __future__ import annotations

from .base import Oracle
from .block_pass import BlockPassOracle
from .canary import CanaryOracle
from .composite import CompositeOracle

__all__ = [
    "Oracle",
    "BlockPassOracle",
    "CanaryOracle",
    "CompositeOracle",
]
