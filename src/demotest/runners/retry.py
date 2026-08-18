"""Retry logic — transport retry vs benchmark retest (plan §30).

Two distinct concerns the refactor separates:
  * **transport retry** — HTTP 429 / transient transport error: retry in-line
    with backoff, same case, same attempt window.
  * **benchmark retest** — upstream cooldown (503): the call itself succeeded
    at the transport layer but the gateway had no upstream; re-issue later as a
    separate benchmark-level action (GatewayRunner.retest).
"""
from __future__ import annotations

import time
from typing import Any, Callable

from ..core.contracts import GatewayObservation, GatewayRequest
from ..core.enums import Outcome

SleepFn = Callable[[float], None]

DEFAULT_MAX_ATTEMPTS = 6


def call_with_retry(
    execute: Callable[[GatewayRequest], GatewayObservation],
    request: GatewayRequest,
    *,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    gap: float = 0.5,
    sleep_fn: SleepFn = time.sleep,
) -> GatewayObservation:
    """Call execute(request); retry on rate_limited / transient error.

    Clear outcomes (blocked / passed / cooldown / payload_too_large) stop early.
    Backoff is min(2**attempt * gap, 120s), mirroring V2.
    """
    last: GatewayObservation | None = None
    for attempt in range(max_attempts):
        obs = execute(request)
        obs.attempts = attempt + 1
        outcome = obs.outcome
        # Clear outcomes are final for this attempt window.
        if outcome in (Outcome.BLOCKED, Outcome.PASSED, Outcome.UPSTREAM_COOLDOWN, Outcome.PAYLOAD_TOO_LARGE):
            return obs
        # Retryable: rate_limited or transport error.
        if outcome in (Outcome.RATE_LIMITED, Outcome.ERROR):
            if attempt + 1 < max_attempts:
                pause = min((2**attempt) * gap, 120.0)
                sleep_fn(pause)
                continue
        return obs
    # Should not reach here, but be safe.
    if last is None:
        last = GatewayObservation(error_type="retry_exhausted")
    return last
