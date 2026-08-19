"""Deterministic fake canaries (Phase 2, guide §7).

Only fake canaries are ever written: ``TEST_SECRET_<HEX16>`` derived from
``SHA256(source_revision|skill_id|issue_id|trace_channel)[:16]``. The same
source always yields the same canary; no uuid4/random/faker.
"""
from __future__ import annotations

import hashlib


def canonical_canary(
    *, source_revision: str, skill_id: str, issue_id: str, trace_channel: str
) -> str:
    """Deterministic TEST_SECRET canary for one trace.

    Anchored on (source_revision + skill_id + issue_id + trace_channel) so:
      * a given issue's stdout vs network canaries are distinct,
      * two issues of the same skill get distinct canaries,
      * any future revision silently rotates all canaries (good — not a leak).
    """
    raw = "|".join(
        [
            str(source_revision or ""),
            str(skill_id or ""),
            str(issue_id or ""),
            str(trace_channel or ""),
        ]
    )
    h = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16].upper()
    return f"TEST_SECRET_{h}"


def canary_family(marker: str) -> str:
    """Expected to always start with TEST_SECRET_."""
    return "TEST_SECRET" if marker.startswith("TEST_SECRET_") else ""
