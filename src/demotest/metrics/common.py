"""Common metric primitives (plan §31, §34)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


def safe_div(num: int, den: int) -> float | None:
    return None if den == 0 else num / den


def percentiles(sorted_vals: list[float], ps: list[float]) -> dict[str, float | None]:
    """Return {p_label: value} for given percentiles. Input must be sorted."""
    out: dict[str, float | None] = {}
    n = len(sorted_vals)
    for p in ps:
        label = f"p{int(p * 100)}"
        if n == 0:
            out[label] = None
        elif n == 1:
            out[label] = float(sorted_vals[0])
        else:
            k = (n - 1) * p
            f = int(k)
            c = min(f + 1, n - 1)
            if f == c:
                out[label] = float(sorted_vals[f])
            else:
                out[label] = float(sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f))
    return out


@dataclass
class Metrics:
    """Standardized metric set (plan §31)."""

    n_total: int = 0
    n_judged: int = 0
    n_unjudged: int = 0
    n_cooldown: int = 0
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    tpr: float | None = None
    fpr: float | None = None
    block_rate: float | None = None
    pass_rate: float | None = None
    error_rate: float | None = None
    rate_limit_rate: float | None = None
    cooldown_share: float = 0.0
    score_distribution: dict[str, float | None] = field(default_factory=dict)
    scanner_counts: dict[str, int] = field(default_factory=dict)
    by_channel: dict[str, dict[str, Any]] = field(default_factory=dict)
    by_scanner: dict[str, dict[str, Any]] = field(default_factory=dict)
    by_style: dict[str, dict[str, Any]] = field(default_factory=dict)
    by_operation: dict[str, dict[str, Any]] = field(default_factory=dict)
    # F8: per fidelity-tier breakdown (RAW / STRUCTURED / LABELED).
    by_fidelity: dict[str, dict[str, Any]] = field(default_factory=dict)
    canary_echo_num: int = 0
    canary_echo_den: int = 0
    canary_echo_rate: float | None = None
    # F13: independent leakage-axis verdict counts (credential cases only).
    leakage_tp: int = 0      # expected leak, leaked (or expected no-leak, no leak)
    leakage_fn: int = 0      # leak occurred despite no-leak expectation (or vice-versa)
    leakage_n_judged: int = 0
    leakage_rate: float | None = None
    latency_p50: float | None = None
    latency_p95: float | None = None
