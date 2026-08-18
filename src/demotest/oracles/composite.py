"""CompositeOracle — require BOTH conditions (plan §15).

Reserved for cases that must be blocked AND must not leak a canary. Built now
but not wired into normal projects; the interface is left open.
"""
from __future__ import annotations

from ..core.contracts import Evaluation, GatewayObservation, Verdict
from ..core.models import SecurityCase
from .base import Oracle
from .block_pass import BlockPassOracle
from .canary import CanaryOracle


class CompositeOracle(Oracle):
    oracle_name = "composite"

    def __init__(
        self,
        *,
        must_block: Oracle | None = None,
        no_leak: Oracle | None = None,
    ) -> None:
        self.must_block = must_block or BlockPassOracle()
        self.no_leak = no_leak or CanaryOracle()

    def evaluate(
        self, case: SecurityCase, observation: GatewayObservation
    ) -> Evaluation:
        a = self.must_block.evaluate(case, observation)
        b = self.no_leak.evaluate(case, observation)
        # If either is unjudged, propagate unjudged (can't conclude yet).
        if a.verdict == Verdict.UNJUDGED or b.verdict == Verdict.UNJUDGED:
            return Evaluation(
                Verdict.UNJUDGED,
                a.expected,
                a.actual_outcome,
                detail=f"composite unjudged: block={a.verdict.value} leak={b.verdict.value}",
                leakage_verdict=b.leakage_verdict,
            )
        # Pass only if both are non-failures. TP/TN pass; FN/FP fail.
        ok = {Verdict.TP, Verdict.TN}
        verdict = Verdict.TP if (a.verdict in ok and b.verdict in ok) else Verdict.FN
        return Evaluation(
            verdict,
            a.expected,
            a.actual_outcome,
            detail=f"block={a.verdict.value} leak={b.verdict.value}",
            leakage_verdict=b.leakage_verdict,
        )
