"""Frozen manifest builder + verifier (guide §36-§38, §47-§48).

A manifest is a frozen selection of cases for one project within one suite.
It records, for every case, only the *identity* needed to resolve the body from
the raw dataset later (case_id / source_id / split / fingerprint) — never the
payload itself. The manifest is the benchmark's identity: once frozen it is
committed to git and never overwritten; a new selection is a new version
(``standard-v1`` -> ``standard-v2``, guide §37, §64).

Determinism contract (guide §48): building the same manifest twice must yield
a byte-identical file — same case ordering, same ids, same splits, same
manifest SHA-256. We achieve that by sorting cases by selection_key before
serialization and writing canonical (sorted-key, fixed-indent) JSON.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from ..config import SuiteConfig  # noqa: F401  (re-exported for CLI typing)
from ..core.exceptions import ManifestError
from ..core.models import SecurityCase
from .quality import get_provenance
from .sampler import Split, assign_splits, group_id_of, selection_key

MANIFEST_VERSION = "v3.1"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def manifest_sha256(manifest: dict[str, Any]) -> str:
    """Byte-stable hash of a manifest (canonical JSON, sorted keys).

    Excludes both ``created_at`` (run-dependent timestamp) and
    ``manifest_sha256`` itself (self-referential) so the hash is stable and the
    stored value can be re-verified by recomputation.
    """
    stable = {k: v for k, v in manifest.items() if k not in ("created_at", "manifest_sha256")}
    blob = json.dumps(stable, sort_keys=True, ensure_ascii=False, default=str)
    return "sha256:" + hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass
class ManifestEntry:
    case_id: str
    case_fingerprint: str
    dataset_id: str
    source_id: str
    split: str
    group_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "case_fingerprint": self.case_fingerprint,
            "dataset_id": self.dataset_id,
            "source_id": self.source_id,
            "split": self.split,
            "group_id": self.group_id,
        }


def _entry_for(case: SecurityCase, split: str) -> ManifestEntry:
    prov = get_provenance(case) or {}
    return ManifestEntry(
        case_id=case.case_id,
        case_fingerprint=case.fingerprint(),
        dataset_id=case.dataset_id,
        source_id=case.source_id,
        split=split,
        group_id=group_id_of(case),
    )


def build_manifest(
    *,
    suite_id: str,
    project_id: str,
    cases: Sequence[SecurityCase],
    seed: int = 42,
    split: Split | str | Sequence[Split | str] = Split.EVAL,
    target: int = 0,
    source_locks: dict[str, dict[str, str]] | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Build a frozen manifest dict for one project within a suite.

    ``cases`` should already be normalized + deduped + provenance-attached.
    Selection is deterministic (selection_key sort); the entries list is
    sorted by selection_key so two builds produce the same byte content.
    """
    cases = list(cases)
    # group-aware split assignment for ALL candidates (so split labels are stable)
    splits = assign_splits(cases, seed=seed)

    allowed: set[str] = set()
    if isinstance(split, (Split, str)):
        split = [split]
    for s in split:
        allowed.add(Split.from_value(s if isinstance(s, str) else s.value).value)
    eligible = [c for c in cases if splits.get(c.case_id, Split.EVAL).value in allowed]
    # deterministic order by selection_key
    dataset_ids = sorted({c.dataset_id for c in cases})
    # selection_key needs a dataset_id; use the case's own dataset_id (multi-dataset
    # projects like P1 span llmail + agentdojo — sort within each dataset).
    eligible.sort(
        key=lambda c: selection_key(c, suite_version=suite_id, seed=seed, dataset_id=c.dataset_id)
    )
    selected = eligible[: max(0, target)] if target else eligible

    entries = [_entry_for(c, splits.get(c.case_id, Split.EVAL).value) for c in selected]
    # final sort by case_id for a canonical, input-order-independent listing
    entries.sort(key=lambda e: e.case_id)

    manifest = {
        "manifest_version": MANIFEST_VERSION,
        "suite": suite_id,
        "project": project_id,
        "seed": seed,
        "split": sorted(allowed),
        "target": target,
        "created_from": source_locks or {},
        "selection_policy": {
            "algorithm": "hash_rank_v1",
            "split_algorithm": "group_aware_cumulative_count_v1",
            "split_ratios": {"dev": 0.20, "eval": 0.60, "holdout": 0.20},
        },
        "n": len(entries),
        "cases": [e.to_dict() for e in entries],
        "created_at": created_at or _utc_now(),
    }
    manifest["manifest_sha256"] = manifest_sha256(manifest)
    return manifest


def write_manifest(manifest: dict[str, Any], path: Path | str) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    blob = json.dumps(manifest, sort_keys=True, ensure_ascii=False, indent=2)
    p.write_text(blob + "\n", encoding="utf-8")
    return p


def load_manifest(path: Path | str) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        raise ManifestError(f"manifest not found: {p}")
    return json.loads(p.read_text(encoding="utf-8"))


def verify_manifest(
    manifest: dict[str, Any],
    *,
    resolved_cases: dict[str, SecurityCase] | None = None,
) -> list[str]:
    """Return a list of problems (empty == OK).

    Checks (guide §47): manifest_sha256 matches, case_ids unique, every case
    resolvable with a matching fingerprint, no group spans multiple splits.
    """
    problems: list[str] = []
    # 1. self-hash
    recomputed = manifest_sha256(manifest)
    if manifest.get("manifest_sha256") and manifest.get("manifest_sha256") != recomputed:
        problems.append(
            f"manifest_sha256 mismatch: stored={manifest.get('manifest_sha256')} computed={recomputed}"
        )
    entries = manifest.get("cases") or []
    # 2. unique case_ids
    seen: dict[str, int] = {}
    for e in entries:
        seen[e["case_id"]] = seen.get(e["case_id"], 0) + 1
    dupes = [cid for cid, n in seen.items() if n > 1]
    if dupes:
        problems.append(f"duplicate case_ids in manifest: {dupes[:10]}")
    # 3. group does not span splits
    group_splits: dict[str, set[str]] = {}
    for e in entries:
        group_splits.setdefault(e["group_id"], set()).add(e["split"])
    bad_groups = {g: sorted(s) for g, s in group_splits.items() if len(s) > 1}
    if bad_groups:
        problems.append(f"group spans multiple splits (train/test leakage): {bad_groups}")
    # 4. resolved cases match fingerprint (when a resolver is provided)
    if resolved_cases is not None:
        for e in entries:
            c = resolved_cases.get(e["case_id"])
            if c is None:
                problems.append(f"case not resolvable: {e['case_id']} (source_id={e['source_id']})")
                continue
            if c.fingerprint() != e["case_fingerprint"]:
                problems.append(
                    f"fingerprint drift for {e['case_id']}: "
                    f"manifest={e['case_fingerprint']} actual={c.fingerprint()}"
                )
    return problems


def resolve_manifest_cases(
    manifest: dict[str, Any], all_cases: Sequence[SecurityCase]
) -> dict[str, SecurityCase]:
    """Map case_id -> SecurityCase for every entry, from a normalized pool."""
    by_id = {c.case_id: c for c in all_cases}
    return {e["case_id"]: by_id[e["case_id"]] for e in (manifest.get("cases") or []) if e["case_id"] in by_id}
