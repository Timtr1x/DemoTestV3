"""GatewayRunner — the V3 execution engine (plan §10, §25, §28, §29, §30).

Pipeline per case::

    SecurityCase
       -> CaseRenderer.render(case)            # deterministic text
       -> TargetAdapter.build_request(text)   # transport request
       -> [dry-run stops here]
       -> call_with_retry(target.execute)     # transport retry on 429/error
       -> Oracle.evaluate(case, observation)  # verdict
       -> CaseResult -> ResultStore.append    # append-only jsonl

The runner is agnostic to datasets and project names; it only sees SecurityCase,
a renderer, a target, and an oracle. Resume skips cases already judged clear.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from ..core.contracts import CaseResult, GatewayObservation
from ..core.enums import Outcome
from ..core.models import SecurityCase
from ..oracles.base import Oracle
from ..renderers.base import CaseRenderer
from ..storage.results import ResultStore
from ..targets.base import TargetAdapter
from .base import RunResult, Runner
from .retry import SleepFn, call_with_retry


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class GatewayRunner(Runner):
    def __init__(
        self,
        *,
        renderer: CaseRenderer,
        target: TargetAdapter,
        oracle: Oracle,
        store: ResultStore,
        run_id: str,
        project: str = "",
        request_gap: float = 0.5,
        max_attempts: int = 6,
        sleep_fn: SleepFn = time.sleep,
        temperature: float = 0.0,
        max_tokens: int = 8,
    ) -> None:
        self.renderer = renderer
        self.target = target
        self.oracle = oracle
        self.store = store
        self.run_id = run_id
        self.project = project
        self.request_gap = request_gap
        self.max_attempts = max_attempts
        self.sleep_fn = sleep_fn
        self.temperature = temperature
        self.max_tokens = max_tokens

    # ------------------------------------------------------------------ run
    def run(self, cases: list[SecurityCase], *, dry_run: bool = False) -> RunResult:
        """Run cases serially; append-only; skip clear (resume)."""
        rr = RunResult(total=len(cases))
        clear_ids = self.store.clear_case_ids()

        for case in cases:
            rr.total += 0  # already counted
            if case.case_id in clear_ids:
                rr.skipped += 1
                continue

            result = self._run_one(case, dry_run=dry_run)
            if result is not None:
                if dry_run:
                    # dry-run does not persist; just collect for inspection
                    rr.results.append(result)
                    rr.ran += 1
                else:
                    self.store.append(result)
                    rr.written += 1
                    rr.ran += 1
                    if result.outcome == Outcome.ERROR.value:
                        rr.errors += 1
            # serial gap before the next live call (not in dry-run)
            if not dry_run and self.request_gap > 0:
                self.sleep_fn(self.request_gap)
        return rr

    def retest(self, cases: list[SecurityCase]) -> RunResult:
        """Re-issue cases whose latest outcome is upstream_cooldown (plan §30)."""
        rr = RunResult(total=len(cases))
        cooldown_ids = self.store.cooldown_case_ids()
        if not cooldown_ids:
            return rr
        for case in cases:
            if case.case_id not in cooldown_ids:
                rr.skipped += 1
                continue
            if self.request_gap > 0:
                self.sleep_fn(self.request_gap)
            result = self._run_one(case, dry_run=False)
            if result is not None:
                self.store.append(result)
                rr.written += 1
                rr.retested += 1
                rr.ran += 1
        return rr

    # ------------------------------------------------------------------ one
    def _run_one(self, case: SecurityCase, *, dry_run: bool) -> CaseResult | None:
        rendered_text = self.renderer.render(case)
        request = self.target.build_request(
            rendered_text=rendered_text,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
        )
        req_hash = request.request_hash()

        if dry_run:
            # Build a placeholder result for inspection; not persisted.
            obs = GatewayObservation(http_status=-1, note="dry_run")
            ev = self.oracle.evaluate(case, obs)
            return CaseResult(
                case_id=case.case_id,
                run_id=self.run_id,
                project=case.project_id or self.project,
                channel=case.channel.value,
                expected=case.expected_action.value,
                target=self.target.target_name,
                request_hash=req_hash,
                http_status=-1,
                outcome="dry_run",
                renderer_name=self.renderer.renderer_name,
                renderer_version=self.renderer.renderer_version,
                verdict=ev.verdict.value,
                response_text="",
                metadata={"rendered_text": rendered_text},
            )

        obs = call_with_retry(
            self.target.execute,
            request,
            max_attempts=self.max_attempts,
            gap=self.request_gap,
            sleep_fn=self.sleep_fn,
        )
        ev = self.oracle.evaluate(case, obs)
        # Compute leakage summary here (before redaction) so the analyzer can
        # report canary-echo rates without needing the raw response_text from
        # disk (which the ResultStore redacts per §24/§43).
        leakage_summary = self._leakage_summary(case, obs)
        # response_text is stored only when the oracle needs it (canary). The
        # ResultStore redacts it before writing to disk (plan §24, §43).
        response_text = ""
        if case.credential_markers:
            response_text = obs.response_text[:2000]
        result = CaseResult(
            case_id=case.case_id,
            run_id=self.run_id,
            project=case.project_id or self.project,
            channel=case.channel.value,
            expected=case.expected_action.value,
            target=self.target.target_name,
            request_hash=req_hash,
            http_status=obs.http_status,
            outcome=obs.outcome.value,
            scanner=obs.scanner,
            policy=obs.policy,
            score=obs.score,
            security_flag=obs.security_flag,
            attempt=obs.attempts,
            latency_ms=obs.latency_ms,
            renderer_name=self.renderer.renderer_name,
            renderer_version=self.renderer.renderer_version,
            verdict=ev.verdict.value,
            response_text=response_text,
            timestamp=_now_iso(),
            metadata={
                "run_id": self.run_id,
                # passed to ResultStore so it knows which markers to redact
                "credential_markers": list(case.credential_markers or []),
                # pre-redaction leakage summary for the analyzer
                "leakage": leakage_summary,
            },
        )
        return result

    @staticmethod
    def _leakage_summary(case: SecurityCase, obs: GatewayObservation) -> dict:
        """Detect canary leakage before redaction; store only the boolean +
        count, never the raw marker value (plan §24)."""
        markers = [m for m in case.credential_markers if m]
        if not markers:
            return {"has_markers": False, "leaked": False, "leaked_count": 0}
        if obs.outcome.value not in ("blocked", "passed"):
            return {"has_markers": True, "leaked": False, "leaked_count": 0}
        if obs.outcome.value == "blocked":
            return {"has_markers": True, "leaked": False, "leaked_count": 0}
        text = obs.response_text or ""
        count = sum(1 for m in markers if m and m in text)
        return {"has_markers": True, "leaked": count > 0, "leaked_count": count}
