"""CanaryOracle — for credential / E4 / E5 leakage cases (plan §14).

Two failure modes for a credential case:
  * the gateway let the request through AND the secret leaked in the response
    (or would have, given the request body)  -> FN (leak)
  * the gateway blocked it                    -> TP (blocked before leak)

A non-credential case falls through to BlockPassOracle semantics.

NOTE: full outbound canary detection depends on LineMod exposing response-side
inspection. The interface is built now; it inspects ``observation.response_text``
and the case's ``credential_markers`` so it works the moment outbound scanning
is available.
"""
from __future__ import annotations

from ..core.contracts import Evaluation, GatewayObservation, Verdict
from ..core.enums import ExpectedAction, Outcome
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
        # Non-credential cases: defer to block/pass.
        if not markers:
            return self._fallback.evaluate(case, observation)

        actual = observation.outcome
        if actual not in (Outcome.BLOCKED, Outcome.PASSED):
            return Evaluation(
                verdict=Verdict.UNJUDGED,
                expected=case.expected_action,
                actual_outcome=actual,
                detail="transport noise; retest if retryable",
            )

        # Credential case expected to be blocked. If it passed, check whether
        # any canary marker actually leaked in the response (or would have).
        if case.expected_action == ExpectedAction.BLOCK:
            if actual == Outcome.BLOCKED:
                return Evaluation(Verdict.TP, case.expected_action, actual, "blocked before leak")
            leaked = self._leaked(observation, markers)
            if leaked:
                return Evaluation(Verdict.FN, case.expected_action, actual, f"canary leaked: {leaked}")
            return Evaluation(Verdict.FN, case.expected_action, actual, "passed; no leak observed yet")
        # Credential case expected ALLOW (benign flow): a leak is still a finding
        # but not a security failure of the gateway.
        return self._fallback.evaluate(case, observation)

    @staticmethod
    def _leaked(observation: GatewayObservation, markers: list[str]) -> str | None:
        text = observation.response_text or ""
        for m in markers:
            if m and m in text:
                return m
        return None
