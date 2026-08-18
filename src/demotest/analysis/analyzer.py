"""Analyzer — cases + result store -> AnalysisReport (plan §31-35)."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

from ..core.models import SecurityCase
from ..metrics import Metrics, canary_leakage, compute_metrics
from ..storage.results import ResultStore


@dataclass
class AnalysisReport:
    project: str = ""
    run_id: str = ""
    target: str = ""
    n_total: int = 0
    metrics: Metrics = field(default_factory=Metrics)
    leakage: dict[str, Any] = field(default_factory=dict)
    caveats: list[str] = field(default_factory=list)
    thresholds: dict[str, Any] = field(default_factory=dict)
    pass_fail: str = "N/A"
    manifest_name: str = ""

    def to_dict(self) -> dict[str, Any]:
        m = self.metrics
        return {
            "project": self.project,
            "run_id": self.run_id,
            "target": self.target,
            "n_total": self.n_total,
            "n_judged": m.n_judged,
            "n_unjudged": m.n_unjudged,
            "tp": m.tp, "fp": m.fp, "tn": m.tn, "fn": m.fn,
            "tpr": m.tpr, "fpr": m.fpr,
            "block_rate": m.block_rate,
            "by_channel": m.by_channel,
            "by_scanner": m.by_scanner,
            "by_style": m.by_style,
            "by_operation": m.by_operation,
            "score_distribution": m.score_distribution,
            "scanner_counts": m.scanner_counts,
            "leakage": self.leakage,
            "pass_fail": self.pass_fail,
            "manifest_name": self.manifest_name,
        }


def evaluate_thresholds(metrics: Metrics, thresholds: dict[str, Any]) -> str:
    if not thresholds:
        return "N/A"
    checks: list[bool] = []
    if "tpr_min" in thresholds and metrics.tpr is not None:
        checks.append(metrics.tpr >= float(thresholds["tpr_min"]))
    if "fpr_max" in thresholds and metrics.fpr is not None:
        checks.append(metrics.fpr <= float(thresholds["fpr_max"]))
    if "canary_echo_max" in thresholds:
        max_echo = int(thresholds["canary_echo_max"])
        if metrics.n_judged and (metrics.canary_echo_den or 0) > 0:
            checks.append((metrics.canary_echo_num or 0) <= max_echo)
    if not checks:
        return "N/A"
    return "PASS" if all(checks) else "FAIL"


def analyze(
    cases: Sequence[SecurityCase],
    store: ResultStore | Path,
    *,
    project: str = "",
    run_id: str = "",
    target: str = "",
    thresholds: dict[str, Any] | None = None,
    caveats: list[str] | None = None,
    manifest_name: str = "",
) -> AnalysisReport:
    if isinstance(store, Path):
        store = ResultStore(store)
    resolved = store.resolved()
    metrics = compute_metrics(cases, resolved)
    leak = canary_leakage(cases, resolved)
    metrics.canary_echo_num = leak["canary_echo_num"]
    metrics.canary_echo_den = leak["canary_echo_den"]
    metrics.canary_echo_rate = leak["canary_echo_rate"]
    th = dict(thresholds or {})
    rep = AnalysisReport(
        project=project,
        run_id=run_id,
        target=target,
        n_total=len(cases),
        metrics=metrics,
        leakage=leak,
        caveats=list(caveats or []),
        thresholds=th,
        pass_fail=evaluate_thresholds(metrics, th),
        manifest_name=manifest_name,
    )
    return rep
