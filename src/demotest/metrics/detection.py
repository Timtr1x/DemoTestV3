"""Detection metrics — confusion matrix + breakdowns (plan §31-34)."""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Mapping, Sequence

from ..core.contracts import Verdict
from ..core.enums import CLEAR_OUTCOMES, ExpectedAction, Outcome
from ..core.models import SecurityCase
from .common import Metrics, percentiles, safe_div

_CLEAR = {o.value for o in CLEAR_OUTCOMES}


def _is_judged(outcome: str) -> bool:
    return outcome in _CLEAR


def compute_metrics(
    cases: Sequence[SecurityCase],
    resolved: Mapping[str, Mapping[str, Any]],
    *,
    group_by: list[str] | None = None,
) -> Metrics:
    """Compute the standardized metric set + breakdowns.

    ``resolved`` maps case_id -> latest result row (from ResultStore.resolved()).
    Breakdowns: by_channel, by_scanner, by_style (presentation_style), by_operation
    (plan §32-35).
    """
    m = Metrics()
    m.n_total = len(cases)
    latencies: list[float] = []
    scores: list[float] = []
    scanner_counter: Counter[str] = Counter()

    buckets: dict[str, list[tuple[SecurityCase, Mapping[str, Any]]]] = defaultdict(list)

    for c in cases:
        rec = resolved.get(c.case_id)
        if rec is None:
            m.n_unjudged += 1
            continue
        outcome = str(rec.get("outcome") or "error")
        if not _is_judged(outcome):
            m.n_unjudged += 1
            continue
        m.n_judged += 1
        if outcome == Outcome.UPSTREAM_COOLDOWN.value:
            m.n_cooldown += 1

        verdict = str(rec.get("verdict") or "")
        if verdict == Verdict.TP.value:
            m.tp += 1
        elif verdict == Verdict.FP.value:
            m.fp += 1
        elif verdict == Verdict.TN.value:
            m.tn += 1
        elif verdict == Verdict.FN.value:
            m.fn += 1

        lat = rec.get("latency_ms")
        if lat is not None:
            latencies.append(float(lat))
        sc = rec.get("score")
        if sc is not None:
            try:
                scores.append(float(sc))
            except (TypeError, ValueError):
                pass
        scanner = str(rec.get("scanner") or "")
        if scanner:
            scanner_counter[scanner] += 1

        # bucket for breakdowns
        for key, attr in (
            (f"channel={c.channel.value}", "channel"),
            (f"scanner={scanner or 'none'}", "scanner"),
            (f"style={c.presentation_style or 'unknown'}", "presentation_style"),
            (f"operation={c.operation.value}", "operation"),
        ):
            buckets[key].append((c, rec))

    m.tpr = safe_div(m.tp, m.tp + m.fn)
    m.fpr = safe_div(m.fp, m.fp + m.tn)
    blocked = m.tp + m.fp
    m.block_rate = safe_div(blocked, m.n_judged)
    m.pass_rate = safe_div(m.tn + m.fn, m.n_judged)
    m.error_rate = safe_div(
        sum(1 for c in cases if (resolved.get(c.case_id) or {}).get("outcome") == Outcome.ERROR.value),
        m.n_total,
    )
    m.rate_limit_rate = safe_div(
        sum(1 for c in cases if (resolved.get(c.case_id) or {}).get("outcome") == Outcome.RATE_LIMITED.value),
        m.n_total,
    )
    m.cooldown_share = (m.n_cooldown / m.n_judged) if m.n_judged else 0.0
    m.scanner_counts = dict(scanner_counter.most_common(50))

    latencies.sort()
    latp = percentiles(latencies, [0.50, 0.95])
    m.latency_p50 = latp.get("p50")
    m.latency_p95 = latp.get("p95")

    scores.sort()
    # min/max are the endpoints; percentiles cover the interior (plan §34)
    m.score_distribution = percentiles(scores, [0.10, 0.25, 0.50, 0.75, 0.90])
    m.score_distribution["min"] = scores[0] if scores else None
    m.score_distribution["max"] = scores[-1] if scores else None

    # breakdowns
    m.by_channel = _breakdown(buckets, "channel=", cases, resolved)
    m.by_scanner = _breakdown(buckets, "scanner=", cases, resolved)
    m.by_style = _breakdown(buckets, "style=", cases, resolved)
    m.by_operation = _breakdown(buckets, "operation=", cases, resolved)

    if group_by:
        # custom grouping (e.g. ["channel","presentation_style"])
        custom: dict[str, list[tuple[SecurityCase, Mapping[str, Any]]]] = defaultdict(list)
        for c in cases:
            rec = resolved.get(c.case_id)
            if rec is None or not _is_judged(str(rec.get("outcome") or "")):
                continue
            parts = []
            for g in group_by:
                parts.append(f"{g}={getattr(c, g, rec.get(g, ''))}")
            custom["|".join(parts)].append((c, rec))
        # stash under a synthetic key via metadata? keep separate return value
    return m


def _breakdown(
    buckets: Mapping[str, list],
    prefix: str,
    cases: Sequence[SecurityCase],
    resolved: Mapping[str, Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Compute per-bucket TP/FP/TN/FN/TPR/FPR WITHOUT recursing into compute_metrics."""
    out: dict[str, dict[str, Any]] = {}
    for key, pairs in sorted(buckets.items()):
        if not key.startswith(prefix):
            continue
        tp = fp = tn = fn = 0
        n_judged = 0
        for c, rec in pairs:
            outcome = str(rec.get("outcome") or "error")
            if outcome not in _CLEAR:
                continue
            n_judged += 1
            verdict = str(rec.get("verdict") or "")
            if verdict == Verdict.TP.value:
                tp += 1
            elif verdict == Verdict.FP.value:
                fp += 1
            elif verdict == Verdict.TN.value:
                tn += 1
            elif verdict == Verdict.FN.value:
                fn += 1
        out[key[len(prefix):]] = {
            "n_judged": n_judged,
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "tpr": safe_div(tp, tp + fn),
            "fpr": safe_div(fp, fp + tn),
        }
    return out
