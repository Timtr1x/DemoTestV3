"""Deterministic, order-independent sampler (guide §28-§32).

Two concerns are kept strictly separate:

  * **selection** — given a candidate pool + target size, pick which cases run
    in a suite. Uses ``sha256(suite_version + seed + dataset_id + source_id +
    group_id)`` as the sort key and takes the first N (guide §29). Independent
    of Python version, OS, dict ordering, or input order.

  * **split** — assign every case to DEV / EVAL / HOLDOUT (20/60/20) by
    ``sha256("split-v1" + seed + group_id)`` so near-duplicate attacks (or
    AgentDojo tool_result+tool_call from one parent) share a split and cannot
    leak across train/test (guide §22, §31, §32).

A frozen manifest records both ``split`` and the selection, so re-running the
build produces a byte-identical manifest (guide §48).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Sequence

from ..core.models import SecurityCase
from .quality import get_provenance


class Split(str, Enum):
    DEV = "dev"
    EVAL = "eval"
    HOLDOUT = "holdout"

    @classmethod
    def from_value(cls, v: str | "Split") -> "Split":
        if isinstance(v, cls):
            return v
        # other enums/objects with .value (str-enum str() gives "Split.X", so
        # read .value explicitly)
        if hasattr(v, "value"):
            v = v.value
        s = str(v or "eval").strip().lower()
        return cls(s)


def _sha(text: str, n: int = 16) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:n]


def group_id_of(case: SecurityCase) -> str:
    """The grouping key for splitting.

    Falls back to source_id when a dataset has no explicit group_id (e.g. LLMail
    uses near_dup_cluster_id, AgentDojo uses parent_source_id). Both are stored
    in ``metadata`` by dedup/adapter.
    """
    meta = case.metadata or {}
    for k in ("group_id", "near_dup_cluster_id", "parent_source_id"):
        v = meta.get(k)
        if v:
            return str(v)
    prov = get_provenance(case) or {}
    for k in ("group_id",):
        v = prov.get(k)
        if v:
            return str(v)
    return case.source_id


def selection_key(
    case: SecurityCase, *, suite_version: str, seed: int, dataset_id: str
) -> str:
    """Deterministic per-case selection key (guide §29)."""
    gid = group_id_of(case)
    raw = "|".join(
        [str(suite_version or ""), str(seed), str(dataset_id or ""), case.source_id, gid]
    )
    return _sha(raw)


def split_key(group_id: str, *, seed: int, version: str = "split-v1") -> str:
    """Deterministic per-group split key (guide §31)."""
    return _sha("|".join([version, str(seed), group_id]))


def assign_split(group_id: str, *, seed: int = 42, version: str = "split-v1") -> Split:
    """20/60/20 split by group, by cumulative-count cut after sorting (guide §31).

    Pure-hash bucketing (00-19/20-79/80-99) gives *proportionally* correct
    splits only in expectation; cumulative-count-after-sort guarantees exact
    20/60/20 boundaries across the whole group set and is still fully
    deterministic. We sort groups by ``split_key`` then cut by count.
    """
    # For a single group we still want a stable answer: use the leading byte.
    # This path is only hit for stand-alone assignment; the manifest builder
    # uses assign_splits() which does the cumulative-count cut.
    h = split_key(group_id, seed=seed, version=version)
    bucket = int(h[:2], 16) % 100
    if bucket < 20:
        return Split.DEV
    if bucket < 80:
        return Split.EVAL
    return Split.HOLDOUT


def assign_splits(
    cases: Sequence[SecurityCase], *, seed: int = 42, version: str = "split-v1"
) -> dict[str, Split]:
    """Assign a split to every *group* by cumulative-count cut (guide §31, §32).

    Returns ``{case_id: Split}``. Groups are sorted by ``split_key``; the first
    20% of groups -> DEV, next 60% -> EVAL, last 20% -> HOLDOUT. All cases in a
    group inherit the group's split (guide §22).
    """
    groups: dict[str, list[str]] = {}
    order: list[str] = []
    for c in cases:
        gid = group_id_of(c)
        if gid not in groups:
            groups[gid] = []
            order.append(gid)
        groups[gid].append(c.case_id)
    sorted_groups = sorted(groups.keys(), key=lambda g: split_key(g, seed=seed, version=version))
    n_groups = len(sorted_groups)
    dev_cut = max(1, round(n_groups * 0.20))
    eval_cut = max(dev_cut + 1, round(n_groups * 0.80))
    out: dict[str, Split] = {}
    for idx, gid in enumerate(sorted_groups):
        if idx < dev_cut:
            sp = Split.DEV
        elif idx < eval_cut:
            sp = Split.EVAL
        else:
            sp = Split.HOLDOUT
        for cid in groups[gid]:
            out[cid] = sp
    return out


@dataclass
class SelectionResult:
    selected: list[SecurityCase]
    n_candidate: int
    n_selected: int
    split_counts: dict[str, int]


def select_for_suite(
    cases: Iterable[SecurityCase],
    *,
    suite_version: str,
    seed: int,
    dataset_id: str,
    target: int,
    split: Split | str | Sequence[Split | str] = Split.EVAL,
    version: str = "split-v1",
) -> SelectionResult:
    """Select up to ``target`` cases from ``split``(s), deterministically.

    1. Assign every candidate a split (group-aware).
    2. Keep only cases whose split is in the requested ``split`` set.
    3. Sort by ``selection_key`` and take the first ``target``.
    """
    cases = list(cases)
    allowed: set[str] = set()
    if isinstance(split, (Split, str)):
        split = [split]
    for s in split:
        allowed.add(Split.from_value(s if isinstance(s, str) else s.value).value)
    splits = assign_splits(cases, seed=seed, version=version)
    eligible = [c for c in cases if splits.get(c.case_id, Split.EVAL).value in allowed]
    eligible.sort(key=lambda c: selection_key(c, suite_version=suite_version, seed=seed, dataset_id=dataset_id))
    selected = eligible[: max(0, target)]
    sc: dict[str, int] = {"dev": 0, "eval": 0, "holdout": 0}
    for c in selected:
        sc[splits.get(c.case_id, Split.EVAL).value] += 1
    return SelectionResult(
        selected=selected,
        n_candidate=len(cases),
        n_selected=len(selected),
        split_counts=sc,
    )
