"""Core domain primitives: enums, ids, exceptions, models, contracts."""
from __future__ import annotations

from .enums import (
    CLEAR_OUTCOMES,
    RETRYABLE_OUTCOMES,
    Channel,
    Direction,
    ExpectedAction,
    Operation,
    Outcome,
)
from .exceptions import (
    ConfigError,
    ManifestError,
    RendererError,
    TargetError,
    ValidationError,
)
from .ids import (
    config_hash,
    compute_case_id,
    compute_run_id,
    manifest_hash,
    request_hash,
)
from .models import SecurityCase
from .contracts import (
    CaseResult,
    Evaluation,
    GatewayObservation,
    GatewayRequest,
    Verdict,
)

__all__ = [
    "Channel",
    "Direction",
    "ExpectedAction",
    "Operation",
    "Outcome",
    "CLEAR_OUTCOMES",
    "RETRYABLE_OUTCOMES",
    "ValidationError",
    "ManifestError",
    "ConfigError",
    "RendererError",
    "TargetError",
    "compute_case_id",
    "compute_run_id",
    "request_hash",
    "config_hash",
    "manifest_hash",
    "SecurityCase",
    "GatewayRequest",
    "GatewayObservation",
    "Evaluation",
    "CaseResult",
    "Verdict",
]
