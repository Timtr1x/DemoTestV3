"""Detection metrics — confusion matrix + breakdowns (plan §31-34)."""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Mapping, Sequence

from ..core.contracts import Verdict
from ..core.enums import CLEAR_OUTCOMES, ExpectedAction, Outcome
from ..core.models import SecurityCase
from .common import Metrics, percentiles, safe_div

# Outcomes that are "clear enough" to skip on resume (transport-final).
_CLEAR = {o.value for o in CLEAR_OUTCOMES}

# Verdicts that count toward the security confusion matrix.
# UPSTREAM_COOLDOWN / PAYLOAD_TOO_LARGE are clear for *resume* but the oracle
# returns UNJUDGED for them, so they must NOT inflate n_judged (external review).
_SECURITY_VERDICTS = {Verdict.TP.value, Verdict.FP.value, Verdict.TN.value, Verdict.FN.value}


def _is_judged_for_security(verdict: str) -> bool:
    """True only when the oracle produced a security verdict (not UNJUDGED).

    This is distinct from "clear for resume": a cooldown outcome is transport-
    final (skip on retest) but not a security judgment (don't count in TPR/FPR).
    """
    return verdict in _SECURITY_VERDICTS


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
        verdict = str(rec.get("verdict") or "")

        # Cooldown / payload_too_large are clear for *resume* but NOT security
        # judgments — track separately, don't inflate n_judged (review P1).
        if outcome == Outcome.UPSTREAM_COOLDOWN.value:
            m.n_cooldown += 1
        if not _is_judged_for_security(verdict):
            m.n_unjudged += 1
            continue
        m.n_judged += 1
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
            (f"fidelity={rec.get('render_fidelity') or 'unknown'}", "render_fidelity"),
        ):
            buckets[key].append((c, rec))

        # F13: leakage-axis verdict (independent of the decision verdict).
        lv = str(rec.get("leakage_verdict") or "")
        if lv in (Verdict.TP.value, Verdict.TN.value, Verdict.FP.value, Verdict.FN.value):
            m.leakage_n_judged += 1
            if lv in (Verdict.TP.value, Verdict.TN.value):
                m.leakage_tp += 1
            else:
                m.leakage_fn += 1

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
    # R4-6: cooldown_share is now cooldown_rate = n_cooldown / n_total.
    # Previously divided by n_judged (which no longer counts cooldown), which
    # could exceed 100%. n_total is the stable denominator.
    m.cooldown_share = safe_div(m.n_cooldown, m.n_total) or 0.0
    m.scanner_counts = dict(scanner_counter.most_common(50))
    m.leakage_rate = safe_div(m.leakage_fn, m.leakage_n_judged)

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
    m.by_fidelity = _breakdown(buckets, "fidelity=", cases, resolved)

    if group_by:
        # custom grouping (e.g. ["channel","presentation_style"])
        custom: dict[str, list[tuple[SecurityCase, Mapping[str, Any]]]] = defaultdict(list)
        for c in cases:
            rec = resolved.get(c.case_id)
            if rec is None or not _is_judged_for_security(str(rec.get("verdict") or "")):
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
            verdict = str(rec.get("verdict") or "")
            if not _is_judged_for_security(verdict):
                continue
            n_judged += 1
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
