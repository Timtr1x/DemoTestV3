"""TargetAdapter abstract base (plan §9)."""
from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum

from ..core.contracts import GatewayObservation, GatewayRequest


class TargetType(str, Enum):
    GATEWAY = "gateway"
    CLASSIFIER = "classifier"


class TargetAdapter(ABC):
    """Send a GatewayRequest and return a parsed GatewayObservation.

    Responsibilities (exhaustive):
      * resolve URL / API key / model / headers / timeout from config + env
      * enforce benchmark-mode invariants (e.g. No-Failover)
      * issue the HTTP call (with transport retry)
      * parse the response into GatewayObservation

    MUST NOT: know about SecurityCase, datasets, oracles, metrics, reports.
    """

    target_name: str = "unknown"
    target_type: TargetType = TargetType.GATEWAY
    adapter_version: str = "1.0"

    @abstractmethod
    def execute(self, request: GatewayRequest) -> GatewayObservation:
        raise NotImplementedError

    @abstractmethod
    def build_request(
        self,
        *,
        rendered_text: str,
        model: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 8,
    ) -> GatewayRequest:
        """Build a GatewayRequest from rendered user text + target defaults."""
        raise NotImplementedError

    def provenance(self) -> dict[str, str]:
        return {
            "target": self.target_name,
            "target_type": self.target_type.value,
            "adapter_version": f"{self.target_name}@{self.adapter_version}",
        }
