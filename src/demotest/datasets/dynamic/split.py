"""P4 skill-level deterministic split (guide D4 / §15).

Maps a set of accepted CredentialTraces to dev/eval/holdout by Skill,
never by trace — all traces from the same source_skill_id stay together
(§14). LineMod never participates in the split.

Default split ratio is 20% dev / 60% eval / 20% holdout, and the hash key is:

    sha256(split_version | seed | source_skill_id)

so the same reviewed pool + seed always yields the same assignment.
"""
from __future__ import annotations

import hashlib
from collections import defaultdict
from typing import Any, Literal

from ..traces.models import CredentialTrace

SplitName = Literal["dev", "eval", "holdout"]
SPLIT_NAMES: tuple[str, ...] = ("dev", "eval", "holdout")
DEFAULT_SPLIT_VERSION = "split-v2"
DEFAULT_SEED = 42
DEFAULT_RATIOS = {"dev": 0.20, "eval": 0.60, "holdout": 0.20}


def split_key(source_skill_id: str, *, seed: int, version: str = DEFAULT_SPLIT_VERSION) -> str:
    return hashlib.sha256(f"{version}|{seed}|{source_skill_id}".encode()).hexdigest()


def _bucket_for_skill(skill_id: str, *, seed: int, version: str, ratios: dict[str, float]) -> SplitName:
    h = hashlib.sha256(f"{version}|{seed}|{skill_id}".encode()).hexdigest()
    # Interpret first 8 hex chars as a uniform float in [0,1)
    frac = int(h[:8], 16) / 0xFFFFFFFF
    dev_cut = ratios.get("dev", 0.20)
    eval_cut = dev_cut + ratios.get("eval", 0.60)
    if frac < dev_cut:
        return "dev"
    if frac < eval_cut:
        return "eval"
    return "holdout"


def assign_skill_splits(
    traces: list[CredentialTrace],
    *,
    seed: int = DEFAULT_SEED,
    version: str = DEFAULT_SPLIT_VERSION,
    ratios: dict[str, float] | None = None,
) -> dict[str, SplitName]:
    """skill_id → split (hash-ranked, deterministic)."""
    ratios = ratios or dict(DEFAULT_RATIOS)
    skill_ids = sorted({t.skill_id for t in traces})
    return {sid: _bucket_for_skill(sid, seed=seed, version=version, ratios=ratios) for sid in skill_ids}


def split_traces(
    traces: list[CredentialTrace],
    *,
    seed: int = DEFAULT_SEED,
    version: str = DEFAULT_SPLIT_VERSION,
    ratios: dict[str, float] | None = None,
) -> dict[SplitName, list[CredentialTrace]]:
    """Partition traces by skill (same-skill traces never cross splits)."""
    skill_split = assign_skill_splits(traces, seed=seed, version=version, ratios=ratios)
    out: dict[SplitName, list[CredentialTrace]] = {"dev": [], "eval": [], "holdout": []}
    for t in traces:
        out[skill_split[t.skill_id]].append(t)
    for k in out:
        out[k] = sorted(out[k], key=lambda x: x.trace_id)
    return out


def verify_no_skill_leakage(traces: list[CredentialTrace], skill_split: dict[str, str]) -> list[str]:
    """Return problems if any skill's traces span multiple splits (should be impossible)."""
    by_skill: dict[str, set[str]] = defaultdict(set)
    for t in traces:
        sp = skill_split.get(t.skill_id, "")
        by_skill[t.skill_id].add(sp)
    problems: list[str] = []
    for sid, splits in by_skill.items():
        if len(splits) > 1:
            problems.append(f"skill {sid} spans splits {sorted(splits)}")
    return problems
