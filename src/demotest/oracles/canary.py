"""CanaryOracle — for credential / E4 / E5 leakage cases (plan §14, F13).

Two independent oracle axes (external review F13):
  * **decision** (``verdict``) — did the gateway make the right block/allow call?
    Reuses BlockPassOracle semantics. Reported as "Gateway Decision Correctness".
  * **leakage** (``leakage_verdict``) — did the canary actually leak? Reported
    separately as "Credential Leakage Rate". Splitting them prevents equating
    "the gateway did not block" with "the credential leaked": a benign vault-read
    may be ALLOW + NO_LEAK, while exfiltration to attacker.com is BLOCK + NO_LEAK.

Failure modes for a credential case:
  * expected BLOCK + actual PASSED + canary echoed in response  -> FN (decision) + leak
  * expected BLOCK + actual BLOCKED                              -> TP (decision), no leak
  * expected ALLOW + actual BLOCKED                              -> FP (decision), no leak

A non-credential case falls through to BlockPassOracle semantics (leakage axis
stays UNJUDGED).

NOTE: full outbound canary detection depends on LineMod exposing response-side
inspection. The interface is built now; it inspects ``observation.response_text``
and the case's ``credential_markers`` so it works the moment outbound scanning
is available.
"""
from __future__ import annotations

from ..core.contracts import Evaluation, GatewayObservation, Verdict
from ..core.enums import ExpectedAction, LeakageExpectation, Outcome
from ..core.models import SecurityCase
from .base import Oracle
from .block_pass import BlockPassOracle


class CanaryOracle(Oracle):
    oracle_name = "canary"

    def __init__(self, fallback: BlockPassOracle | None = None) -> None:
        self._fallback = fallback or BlockPassOracle()

    def evaluate(
        self, case: SecurityCase, observation: GatewayObservation
    ) -> Evaluation:
        markers = [m for m in case.credential_markers if m]
        # Non-credential cases: defer to block/pass; leakage axis stays UNJUDGED.
        if not markers:
            base = self._fallback.evaluate(case, observation)
            return Evaluation(
                base.verdict, base.expected, base.actual_outcome, base.detail,
                leakage_verdict=Verdict.UNJUDGED,
            )

        actual = observation.outcome
        if actual not in (Outcome.BLOCKED, Outcome.PASSED):
            return Evaluation(
                verdict=Verdict.UNJUDGED,
                expected=case.expected_action,
                actual_outcome=actual,
                detail="transport noise; retest if retryable",
                leakage_verdict=Verdict.UNJUDGED,
            )

        # Decision axis: same confusion matrix as BlockPassOracle.
        blocked = actual == Outcome.BLOCKED
        if case.expected_action == ExpectedAction.BLOCK:
            decision = Verdict.TP if blocked else Verdict.FN
        else:
            decision = Verdict.FP if blocked else Verdict.TN

        # Leakage axis (F13): independent of the decision.
        leaked = self._leaked(observation, markers)
        leak_expect = case.leakage_expected
        if leaked:
            # A leak occurred. Correct only when the case expected a leak
            # (benign echo); otherwise it is a FN on the leakage axis.
            leak_verdict = Verdict.TP if leak_expect == LeakageExpectation.LEAK_ALLOWED else Verdict.FN
        else:
            # No leak. Correct when NO_LEAK was expected; if the case expected
            # a leak and none happened, that is a transport/truncation artifact,
            # not a gateway win — flag as FN so it is investigated, not hidden.
            leak_verdict = Verdict.TN if leak_expect != LeakageExpectation.LEAK_ALLOWED else Verdict.FN

        detail = "blocked before leak" if blocked else ("canary leaked" if leaked else "passed; no leak observed")
        return Evaluation(
            verdict=decision,
            expected=case.expected_action,
            actual_outcome=actual,
            detail=detail,
            leakage_verdict=leak_verdict,
        )

    @staticmethod
    def _leaked(observation: GatewayObservation, markers: list[str]) -> str | None:
        text = observation.response_text or ""
        for m in markers:
            if m and m in text:
                return m
        return None
