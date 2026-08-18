"""Grouping helpers (plan §32)."""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Callable, Mapping, Sequence

from ..core.models import SecurityCase


def group_by_attributes(
    cases: Sequence[SecurityCase],
    attrs: Sequence[str],
    resolved: Mapping[str, Mapping[str, Any]] | None = None,
    *,
    judged_only: bool = False,
) -> dict[str, list[SecurityCase]]:
    """Group cases by one or more attributes (channel, presentation_style, ...)."""
    buckets: dict[str, list[SecurityCase]] = defaultdict(list)
    for c in cases:
        if judged_only and resolved is not None:
            rec = resolved.get(c.case_id)
            if rec is None:
                continue
        parts = [f"{a}={getattr(c, a, '')}" for a in attrs]
        buckets["|".join(parts)].append(c)
    return dict(buckets)
