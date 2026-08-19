"""BlockPassOracle — the workhorse for nearly all benchmarks (plan §13.1).

Confusion matrix on the security decision (block vs allow), ignoring transport
noise (rate_limited / error / cooldown -> UNJUDGED, retested separately).
"""
from __future__ import annotations

from ..core.contracts import Evaluation, GatewayObservation, Verdict
from ..core.enums import CLEAR_OUTCOMES, ExpectedAction, Outcome
from ..core.models import SecurityCase
from .base import Oracle


class BlockPassOracle(Oracle):
    oracle_name = "block_pass"

    def evaluate(
        self, case: SecurityCase, observation: GatewayObservation
    ) -> Evaluation:
        actual = observation.outcome
        # Transport noise -> not counted in TPR/FPR
        if actual not in (Outcome.BLOCKED, Outcome.PASSED):
            return Evaluation(
                verdict=Verdict.UNJUDGED,
                expected=case.expected_action,
                actual_outcome=actual,
                detail="transport noise; retest if retryable",
                leakage_verdict=Verdict.UNJUDGED,
            )

        blocked = actual == Outcome.BLOCKED
        if case.expected_action == ExpectedAction.BLOCK:
            verdict = Verdict.TP if blocked else Verdict.FN
        else:  # ALLOW
            verdict = Verdict.FP if blocked else Verdict.TN
        return Evaluation(
            verdict=verdict,
            expected=case.expected_action,
            actual_outcome=actual,
            detail="",
            leakage_verdict=Verdict.UNJUDGED,
        )


# Backwards-compat alias for code that names it after the V2 implicit oracle.
def is_clear_outcome(outcome: Outcome | str) -> bool:
    if isinstance(outcome, str):
        outcome = Outcome.from_value(outcome)
    return outcome in CLEAR_OUTCOMES
