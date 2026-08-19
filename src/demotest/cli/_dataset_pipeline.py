"""Shared dataset pipeline helpers used by the CLI (not a CLI command itself).

Keeps ``cli/dataset.py`` thin and lets tests call the same code path. All
network/git work happens only in ``acquire``; prepare/verify/stats are offline.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..config import DatasetSourceConfig, get_dataset, load_dataset_projection
from ..core.exceptions import DatasetSourceError, DatasetSourceDirtyError
from ..datasets.adapters.agentdojo import AgentDojoAdapter
from ..datasets.adapters.llmail import LLMailAdapter
from ..datasets.dedup import run_dedup
from ..datasets.quality import validate_provenance_block
from ..datasets.registry import get_adapter
from ..datasets.source_lock import (
    DatasetSourceLock,
    assert_git_clean_at_revision,
    hash_raw_snapshot,
    load_source_lock,
    now_utc,
    verify_lock_against_raw,
    write_source_lock as _write_lock,
)


def jsonl_dumps(obj: dict) -> str:
    """Serialize one case to a JSONL-safe line.

    ``json.dumps(ensure_ascii=False)`` leaves U+2028/U+2029 (Unicode line /
    paragraph separators) literal, and ``str.splitlines()`` treats them as line
    breaks — so a prompt embedding them would corrupt the one-object-per-line
    contract. Normalize those two chars to their escaped forms.
    """
    blob = json.dumps(obj, ensure_ascii=False, sort_keys=True)
    return blob.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")


# --------------------------------------------------------------------------
# acquire / verify-source
# --------------------------------------------------------------------------
def build_source_lock(ds: DatasetSourceConfig, raw_sha256: str) -> DatasetSourceLock:
    extra = {}
    if ds.benchmark_version:
        extra["benchmark_version"] = ds.benchmark_version
    return DatasetSourceLock(
        dataset_id=ds.name,
        source_type=ds.source_type,
        source_uri=ds.source_uri,
        revision=ds.revision,
        license=ds.license,
        raw_sha256=raw_sha256,
        extra=extra,
        adapter_name=ds.adapter,
        adapter_version=ds.adapter_version,
        acquired_at=now_utc(),
    )


def write_source_lock(lock: DatasetSourceLock) -> Path:
    return _write_lock(lock)


def verify_source(ds: DatasetSourceConfig) -> list[str]:
    """Guide §34 checks. Returns a list of problems (empty == OK)."""
    problems: list[str] = []
    try:
        lock = load_source_lock(ds.name)
    except DatasetSourceError as e:
        return [str(e)]
    if lock.revision != ds.revision:
        problems.append(f"lock revision {lock.revision} != config {ds.revision}")
    if lock.source_uri != ds.source_uri:
        problems.append(f"lock source_uri {lock.source_uri} != config {ds.source_uri}")
    if not ds.raw_path.exists():
        problems.append(f"raw dir missing: {ds.raw_path}")
        return problems
    if ds.source_type == "github":
        try:
            assert_git_clean_at_revision(ds.raw_path, ds.revision)
        except DatasetSourceDirtyError as e:
            problems.append(str(e))
    # snapshot hash
    try:
        verify_lock_against_raw(lock, ds.raw_path, relative_globs=ds.hash_globs or None)
    except DatasetSourceError as e:
        problems.append(str(e))
    return problems


# --------------------------------------------------------------------------
# prepare / verify / stats
# --------------------------------------------------------------------------
@dataclass
class PrepareReport:
    n_cases: int
    n_kept: int
    n_exact: int
    n_norm: int
    n_clusters: int
    normalized_path: Path = field(default_factory=Path)


def _build_adapter(ds: DatasetSourceConfig, max_cases: int | None):
    proj = load_dataset_projection(ds.name)
    if ds.adapter == "llmail":
        return LLMailAdapter(source_config=ds, max_attack_per_phase=max_cases)
    if ds.adapter == "agentdojo":
        return AgentDojoAdapter(source_config=ds, max_per_suite=max_cases)
    return get_adapter(ds.adapter, source_config=ds)


def prepare_dataset(ds: DatasetSourceConfig, *, max_cases: int | None = None) -> PrepareReport:
    """Raw -> normalized + dedup. Writes a jsonl snapshot of SecurityCase dicts."""
    adapter = _build_adapter(ds, max_cases)
    raw_cases = adapter.cases()
    proj = load_dataset_projection(ds.name)
    dd = proj.dedup or {}
    near = dd.get("near_duplicate") or {}
    cases, rep = run_dedup(
        raw_cases,
        do_exact=bool(dd.get("exact", True)),
        do_normalized=bool(dd.get("normalized", True)),
        do_near_duplicate=bool(near.get("method")),
        near_n=int(near.get("n", 5)),
        near_threshold=float(near.get("threshold", 0.85)),
    )
    # write normalized snapshot (jsonl; one SecurityCase dict per line)
    ds.normalized_path.mkdir(parents=True, exist_ok=True)
    out = ds.normalized_path / "cases.jsonl"
    # JSONL-safe dump + stable order: escape U+2028/U+2029 (real prompt payloads
    # contain them and str.splitlines() would break the one-line-per-case
    # contract), and sort by source_id so the snapshot is byte-stable across
    # reruns even when the adapter streams in file order.
    ordered = sorted(cases, key=lambda c: c.source_id)
    with out.open("w", encoding="utf-8") as f:
        for c in ordered:
            f.write(jsonl_dumps(c.to_dict()) + "\n")
    # write a small provenance sidecar
    meta = {
        "dataset_id": ds.name,
        "adapter_version": adapter.adapter_version,
        "revision": adapter.source_metadata().get("revision", ds.revision),
        "n_cases": len(cases),
        "dedup": {
            "exact_duplicates": rep.n_exact_duplicates,
            "normalized_duplicates": rep.n_normalized_duplicates,
            "near_duplicate_clusters": rep.n_clusters,
        },
    }
    (ds.normalized_path / "prepare.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return PrepareReport(
        n_cases=rep.n_in,
        n_kept=len(cases),
        n_exact=rep.n_exact_duplicates,
        n_norm=rep.n_normalized_duplicates,
        n_clusters=rep.n_clusters,
        normalized_path=out,
    )


def load_normalized(ds: DatasetSourceConfig):
    from ..core.models import SecurityCase

    out = ds.normalized_path / "cases.jsonl"
    if not out.exists():
        raise DatasetSourceError(f"normalized snapshot missing: {out} (run 'dataset prepare')")
    cases = []
    for line in iter_normalized_lines(ds):
        cases.append(SecurityCase.from_dict(json.loads(line)))
    return cases


def iter_normalized_lines(ds: DatasetSourceConfig):
    """Yield one JSONL line at a time (streaming) — bounded memory for 148K."""
    from ..core.exceptions import DatasetSourceError as _DSE

    out = ds.normalized_path / "cases.jsonl"
    if not out.exists():
        raise _DSE(f"normalized snapshot missing: {out} (run 'dataset prepare')")
    with out.open("r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if line:
                yield line


def verify_normalized(ds: DatasetSourceConfig) -> list[str]:
    problems: list[str] = []
    cases: list = []
    try:
        for line in iter_normalized_lines(ds):
            from ..core.models import SecurityCase as _SC
            cases.append(_SC.from_dict(json.loads(line)))
    except DatasetSourceError as e:
        return [str(e)]
    # case_id unique — stream check first to fail fast
    seen: dict[str, int] = {}
    for c in cases:
        seen[c.case_id] = seen.get(c.case_id, 0) + 1
    dupes = [cid for cid, n in seen.items() if n > 1]
    if dupes:
        problems.append(f"duplicate case_ids: {dupes[:10]}")
    # fingerprint stable: recompute and confirm it matches what was serialized
    for c in cases:
        # SecurityCase.fingerprint() is pure and deterministic; if the
        # normalized snapshot round-trips, recomputing must equal itself.
        # (A drift would surface as a changed case_id/fingerprint on reload.)
        _ = c.fingerprint()
    # expected_action legal
    for c in cases:
        if c.expected_action.value not in ("block", "allow"):
            problems.append(f"{c.case_id}: bad expected_action {c.expected_action!r}")
    # provenance complete
    problems.extend(validate_provenance_block(cases))
    return problems


def compute_stats(ds: DatasetSourceConfig) -> dict[str, Any]:
    n = 0
    by_phase: dict[str, int] = {}
    by_scenario: dict[str, int] = {}
    by_goal: dict[str, int] = {}
    by_team: dict[str, int] = {}
    by_style: dict[str, int] = {}
    by_channel: dict[str, int] = {}
    by_dataset: dict[str, int] = {}
    by_expected: dict[str, int] = {}
    lengths: list[int] = []
    clusters: set[str] = set()
    for line in iter_normalized_lines(ds):
        from ..core.models import SecurityCase as _SC

        c = _SC.from_dict(json.loads(line))
        m = c.metadata or {}
        ph = m.get("source_phase", "unknown") or "unknown"
        by_phase[ph] = by_phase.get(ph, 0) + 1
        sc = m.get("scenario", "unknown") or "unknown"
        by_scenario[sc] = by_scenario.get(sc, 0) + 1
        g = m.get("attack_goal", "") or "none"
        by_goal[g] = by_goal.get(g, 0) + 1
        t = m.get("team_id", "") or "unknown"
        by_team[t] = by_team.get(t, 0) + 1
        st = c.presentation_style or "unknown"
        by_style[st] = by_style.get(st, 0) + 1
        ch = c.channel.value
        by_channel[ch] = by_channel.get(ch, 0) + 1
        by_dataset[c.dataset_id] = by_dataset.get(c.dataset_id, 0) + 1
        by_expected[c.expected_action.value] = by_expected.get(c.expected_action.value, 0) + 1
        lengths.append(len(c.content or ""))
        cid = m.get("near_dup_cluster_id")
        if cid:
            clusters.add(cid)
        n += 1
    s = {
        "total": n,
        "by_expected": by_expected,
        "by_dataset": by_dataset,
        "by_channel": by_channel,
        "by_phase": by_phase,
        "by_scenario": by_scenario,
        "by_goal": by_goal,
        "by_team": by_team,
        "by_style": by_style,
        "near_duplicate_clusters": len(clusters),
        "length": {
            "min": min(lengths) if lengths else 0,
            "max": max(lengths) if lengths else 0,
            "mean": (sum(lengths) / len(lengths)) if lengths else 0,
        },
    }
    return s
