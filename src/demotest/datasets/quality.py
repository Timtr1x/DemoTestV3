"""Quality metadata for normalized cases (guide §23-§27, §54).

Every normalized SecurityCase carries a uniform provenance block so reports
can answer "where did this attack come from and how was it derived?" without
re-reading the raw dataset. The block is stored on ``case.metadata`` under a
single ``source`` key to keep SecurityCase's own schema stable (frozen core,
guide §2).

quality_tier (guide §24-§27):
  A — real source / human attack / human-verified vuln
  B — deterministic derivation from a real ground truth (e.g. AgentDojo
      tool_result + tool_call from one original security case)
  C — template / model-generated / mass rewrite (Phase 1 forbids; Extended only)

derivation:
  original                — the case IS the original source row
  deterministic_projection — projected from a real benchmark case, no LLM
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

from ..core.models import SecurityCase

QUALITY_TIERS = ("A", "B", "C")
DERIVATIONS = ("original", "deterministic_projection")


class QualityTier(str, Enum):
    A = "A"
    B = "B"
    C = "C"

    @classmethod
    def from_value(cls, v: str) -> "QualityTier":
        s = str(v or "A").strip().upper()
        if s not in ("A", "B", "C"):
            raise ValueError(f"unknown quality_tier {v!r}")
        return cls(s)


@dataclass(frozen=True)
class SourceProvenance:
    """Uniform provenance attached to every normalized case (guide §23)."""

    source_dataset: str
    source_revision: str
    source_id: str
    group_id: str
    raw_sha256: str
    normalized_sha256: str
    adapter_name: str
    adapter_version: str
    quality_tier: str = "A"
    derivation: str = "original"
    # optional lineage (AgentDojo parent case)
    parent_source_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_dataset": self.source_dataset,
            "source_revision": self.source_revision,
            "source_id": self.source_id,
            "group_id": self.group_id,
            "raw_sha256": self.raw_sha256,
            "normalized_sha256": self.normalized_sha256,
            "adapter_name": self.adapter_name,
            "adapter_version": self.adapter_version,
            "quality_tier": self.quality_tier,
            "derivation": self.derivation,
            "parent_source_id": self.parent_source_id,
        }


def attach_provenance(case: SecurityCase, prov: SourceProvenance) -> SecurityCase:
    """Return a new SecurityCase with the provenance block in ``metadata['source']``.

    SecurityCase is frozen, so we rebuild via ``from_dict`` with the merged
    metadata. The caller should not set ``metadata['source']`` beforehand.
    """
    d = case.to_dict()
    meta = dict(d.get("metadata") or {})
    meta["source"] = prov.to_dict()
    d["metadata"] = meta
    return SecurityCase.from_dict(d)


def get_provenance(case: SecurityCase) -> dict[str, Any] | None:
    meta = case.metadata or {}
    src = meta.get("source")
    if isinstance(src, Mapping):
        return dict(src)
    return None


def require_provenance(case: SecurityCase) -> dict[str, Any]:
    prov = get_provenance(case)
    if prov is None:
        raise ValueError(
            f"case {case.case_id} has no source provenance (metadata.source) — "
            "did the adapter attach it?"
        )
    return prov


def validate_provenance_block(cases: list[SecurityCase]) -> list[str]:
    """Return a list of human-readable problems (empty == OK)."""
    problems: list[str] = []
    for c in cases:
        prov = get_provenance(c)
        if prov is None:
            problems.append(f"{c.case_id}: missing metadata.source")
            continue
        for k in (
            "source_dataset",
            "source_revision",
            "source_id",
            "group_id",
            "raw_sha256",
            "normalized_sha256",
            "adapter_name",
            "adapter_version",
            "quality_tier",
            "derivation",
        ):
            v = prov.get(k)
            if v in (None, "", []):
                problems.append(f"{c.case_id}: source.{k} is empty")
        if prov.get("quality_tier") not in QUALITY_TIERS:
            problems.append(f"{c.case_id}: bad quality_tier={prov.get('quality_tier')!r}")
        if prov.get("derivation") not in DERIVATIONS:
            problems.append(f"{c.case_id}: bad derivation={prov.get('derivation')!r}")
    return problems
