"""Oracle abstract base (plan §13)."""
from __future__ import annotations

from abc import ABC, abstractmethod

from ..core.contracts import Evaluation, GatewayObservation
from ..core.models import SecurityCase


class Oracle(ABC):
    """Evaluate whether an observation is correct for a case."""

    oracle_name: str = "oracle"

    @abstractmethod
    def evaluate(
        self,
        case: SecurityCase,
        observation: GatewayObservation,
    ) -> Evaluation:
        raise NotImplementedError
