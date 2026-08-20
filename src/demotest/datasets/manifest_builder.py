"""Frozen manifest builder + verifier (guide §36-§38, §47-§48, fix round v3.2).

A manifest is a frozen selection of cases for one project within one suite.
It records, for every case, only the *identity* needed to resolve the body from
the raw dataset later (case_id / source_id / split / fingerprint) — never the
payload itself. The manifest is the benchmark's identity: once frozen it is
committed to git and never overwritten; a new selection is a new suite version
(``standard-v1`` -> ``standard-v2``).

Determinism contract (guide §48): building the same manifest twice must yield
a byte-identical file — same case ordering, same ids, same splits, same
manifest SHA-256. We achieve that by sorting cases by selection_key before
serialization and writing canonical (sorted-key, fixed-indent) JSON. No
``created_at`` wall-clock field is included in v3.2 (fix round P1-4).

Strata (fix round P0-3/P1-3): each suite declares per-project strata
(attack/benign quotas + cluster cap). The builder enforces them: split first,
then for each stratum filter -> hash-rank -> cluster-cap -> take N.

For large pools (LLMail 148K) callers should use ``build_manifest_streaming``
which operates on lightweight CaseHeader without holding full SecurityCase.
"""
from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

from ..config import SuiteConfig  # noqa: F401
from ..core.exceptions import ConfigError, ManifestError
from ..core.models import SecurityCase
from .quality import get_provenance
from .sampler import CaseHeader, Split, assign_splits, assign_splits_case_weighted, group_id_of, header_of, selection_key, split_key

MANIFEST_VERSION = "v3.2"


def validate_benchmark_track(track: str, headline_eligible: bool) -> None:
    """Shared invariant (review P0-2/P0-3): extended => headline_eligible == False."""
    tr = str(track or "").strip().lower()
    if tr not in ("core", "extended"):
        raise ConfigError(f"invalid benchmark_track {track!r}; expected 'core' or 'extended'")
    if tr == "extended" and bool(headline_eligible):
        raise ConfigError("extended track cannot be headline_eligible=true")



def manifest_sha256(manifest: dict[str, Any]) -> str:
    """Byte-stable hash of a manifest (canonical JSON, sorted keys).

    Excludes ``manifest_sha256`` itself (self-referential) so the hash is
    stable and the stored value can be re-verified.
    """
    stable = {k: v for k, v in manifest.items() if k not in ("manifest_sha256",)}
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


def _entry_for_header(h: CaseHeader, split: str) -> ManifestEntry:
    return ManifestEntry(
        case_id=h.case_id,
        case_fingerprint=h.case_fingerprint,
        dataset_id=h.dataset_id,
        source_id=h.source_id,
        split=split,
        group_id=h.group_id,
    )


def _strata_select(
    *,
    headers: list[CaseHeader],
    strata: list[dict[str, Any]],
    suite_id: str,
    seed: int,
    max_cluster_share: float | None,
) -> tuple[list[CaseHeader], dict[str, dict[str, Any]]]:
    """Select per stratum: filter -> hash-rank -> cluster cap -> take N."""
    selected: list[CaseHeader] = []
    strata_report: dict[str, dict[str, Any]] = {}
    for st in strata:
        sid = str(st.get("id") or st.get("name") or "stratum")
        count_raw = st.get("count", 0)
        is_all = isinstance(count_raw, str) and count_raw.lower() == "all"
        target = 0 if is_all else int(count_raw or 0)
        # filter
        filt = list(headers)
        ds = st.get("dataset")
        if ds:
            filt = [h for h in filt if h.dataset_id == ds]
        ea = st.get("expected_action")
        if ea:
            filt = [h for h in filt if h.expected_action == ea]
        ch = st.get("channel")
        if ch:
            filt = [h for h in filt if h.channel == ch]
        # hash-rank within stratum
        filt.sort(key=lambda h: hashlib.sha256(
            "|".join([suite_id, str(seed), h.dataset_id, h.source_id, h.group_id]).encode()
        ).hexdigest())
        # cluster cap
        if max_cluster_share and max_cluster_share > 0 and not is_all:
            cap = max(1, math.ceil(target * float(max_cluster_share)))
            by_group: dict[str, int] = {}
            capped: list[CaseHeader] = []
            for h in filt:
                if by_group.get(h.group_id, 0) >= cap:
                    continue
                capped.append(h)
                by_group[h.group_id] = by_group.get(h.group_id, 0) + 1
                if len(capped) >= target:
                    break
            chosen = capped[:target] if not is_all else capped
        else:
            chosen = filt if is_all else filt[:target]
        selected.extend(chosen)
        strata_report[sid] = {
            "target": count_raw,
            "actual": len(chosen),
            "filtered": len(filt),
        }
    return selected, strata_report


def build_manifest(
    *,
    suite_id: str,
    project_id: str,
    cases: Sequence[SecurityCase],
    seed: int = 42,
    split: Split | str | Sequence[Split | str] = Split.EVAL,
    target: int = 0,
    source_locks: dict[str, dict[str, str]] | None = None,
    strata: list[dict[str, Any]] | None = None,
    max_cluster_share: float | None = None,
    split_version: str = "split-v1",
    benchmark_track: str | None = None,
    headline_eligible: bool | None = None,
) -> dict[str, Any]:
    """Build a frozen manifest dict for one project within a suite.

    If ``strata`` is provided, selection is per-stratum (attack/benign quotas).
    Otherwise falls back to legacy single-target selection for backward compat.
    """
    cases = list(cases)
    # group-aware split: use case-weighted v2 when requested, else legacy v1
    if split_version == "split-v2":
        # need group sizes
        group_sizes: dict[str, int] = {}
        group_members: dict[str, list[str]] = {}
        for c in cases:
            gid = group_id_of(c)
            group_sizes[gid] = group_sizes.get(gid, 0) + 1
            group_members.setdefault(gid, []).append(c.case_id)
        group_split = assign_splits_case_weighted(group_sizes, seed=seed, version=split_version)
        splits: dict[str, Split] = {}
        for gid, sp in group_split.items():
            for cid in group_members.get(gid, []):
                splits[cid] = sp
    else:
        splits = assign_splits(cases, seed=seed, version=split_version)

    allowed: set[str] = set()
    if isinstance(split, (Split, str)):
        split = [split]
    for s in split:
        allowed.add(Split.from_value(s if isinstance(s, str) else s.value).value)

    # Build headers for strata logic (reuse header_of)
    all_headers = [header_of(c) for c in cases]
    # filter to requested split
    eligible_headers = [h for h in all_headers if splits.get(h.case_id, Split.EVAL).value in allowed]
    eligible_cases = [c for c in cases if splits.get(c.case_id, Split.EVAL).value in allowed]

    if strata:
        selected_headers, strata_report = _strata_select(
            headers=eligible_headers,
            strata=strata,
            suite_id=suite_id,
            seed=seed,
            max_cluster_share=max_cluster_share,
        )
        # map back to entries via header
        by_id = {c.case_id: c for c in cases}
        # need split value per header
        entries = []
        for h in selected_headers:
            sp = splits.get(h.case_id, Split.EVAL).value
            entries.append(_entry_for_header(h, sp))
    else:
        # legacy: hash-rank across eligible
        eligible_cases.sort(
            key=lambda c: selection_key(c, suite_version=suite_id, seed=seed, dataset_id=c.dataset_id)
        )
        selected = eligible_cases[: max(0, target)] if target else eligible_cases
        entries = [_entry_for(c, splits.get(c.case_id, Split.EVAL).value) for c in selected]
        strata_report = {}

    entries.sort(key=lambda e: e.case_id)

    # created_from: include adapter version + benchmark_version when available
    cf = source_locks or {}
    # Phase 2.1 hard isolation: benchmark_track / headline_eligible derived from suite config if not explicit
    if benchmark_track is None or headline_eligible is None:
        try:
            from ..config import get_suite as _gs
            _suite = _gs(suite_id)
            _pt = _suite.projects.get(project_id)
            if _pt is not None:
                if benchmark_track is None:
                    benchmark_track = getattr(_pt, "track", "core") or "core"
                if headline_eligible is None:
                    headline_eligible = bool(getattr(_pt, "headline_eligible", benchmark_track == "core"))
        except Exception:
            pass
    if benchmark_track is None:
        benchmark_track = "core"
    if headline_eligible is None:
        headline_eligible = (benchmark_track == "core")
    benchmark_track = str(benchmark_track).lower()
    validate_benchmark_track(benchmark_track, bool(headline_eligible))
    manifest: dict[str, Any] = {
        "manifest_version": MANIFEST_VERSION,
        "suite": suite_id,
        "project": project_id,
        "seed": seed,
        "split": sorted(allowed),
        "target": target,
        "benchmark_track": benchmark_track,
        "headline_eligible": bool(headline_eligible),
        "created_from": cf,
        "selection_policy": {
            "algorithm": "hash_rank_v1",
            "split_algorithm": "group_aware_case_count_v2" if split_version == "split-v2" else "group_aware_cumulative_count_v1",
            "split_ratios": {"dev": 0.20, "eval": 0.60, "holdout": 0.20},
            "split_version": split_version,
        },
        "n": len(entries),
        "cases": [e.to_dict() for e in entries],
    }
    if strata_report:
        manifest["strata"] = strata_report
    manifest["manifest_sha256"] = manifest_sha256(manifest)
    return manifest


def build_manifest_streaming(
    *,
    suite_id: str,
    project_id: str,
    cases_iter: Any,
    seed: int = 42,
    split: Split | str | Sequence[Split | str] = Split.EVAL,
    target: int = 0,
    source_locks: dict[str, dict[str, str]] | None = None,
    strata: list[dict[str, Any]] | None = None,
    max_cluster_share: float | None = None,
    split_version: str = "split-v1",
    benchmark_track: str | None = None,
    headline_eligible: bool | None = None,
) -> dict[str, Any]:
    """Streaming manifest builder — collects headers only, not full cases.

    Pass 1: collect group sizes (for split). Pass 2: collect lightweight headers.
    Then reuse build_manifest logic on headers.
    """
    # Collect headers without holding payloads; we need case_id etc. from headers
    # cases_iter yields SecurityCase; we convert to headers immediately
    headers: list[CaseHeader] = []
    for c in cases_iter:
        headers.append(header_of(c))
    if not headers:
        return build_manifest(
            suite_id=suite_id, project_id=project_id, cases=[],
            seed=seed, split=split, target=target, source_locks=source_locks,
            strata=strata, max_cluster_share=max_cluster_share, split_version=split_version,
        )
    # Reconstruct minimal split assignment from headers
    if split_version == "split-v2":
        group_sizes: dict[str, int] = {}
        group_members: dict[str, list[str]] = {}
        for h in headers:
            group_sizes[h.group_id] = group_sizes.get(h.group_id, 0) + 1
            group_members.setdefault(h.group_id, []).append(h.case_id)
        group_split = assign_splits_case_weighted(group_sizes, seed=seed, version=split_version)
        splits: dict[str, Split] = {}
        for gid, sp in group_split.items():
            for cid in group_members.get(gid, []):
                splits[cid] = sp
    else:
        # legacy v1: group count based
        groups = sorted({h.group_id for h in headers}, key=lambda g: split_key(g, seed=seed, version=split_version))
        n_groups = len(groups)
        dev_cut = max(1, round(n_groups * 0.20))
        eval_cut = max(dev_cut + 1, round(n_groups * 0.80))
        g2split: dict[str, Split] = {}
        for idx, gid in enumerate(groups):
            if idx < dev_cut:
                g2split[gid] = Split.DEV
            elif idx < eval_cut:
                g2split[gid] = Split.EVAL
            else:
                g2split[gid] = Split.HOLDOUT
        splits = {h.case_id: g2split[h.group_id] for h in headers}

    allowed: set[str] = set()
    if isinstance(split, (Split, str)):
        split = [split]
    for s in split:
        allowed.add(Split.from_value(s if isinstance(s, str) else s.value).value)
    eligible = [h for h in headers if splits.get(h.case_id, Split.EVAL).value in allowed]

    if strata:
        selected_headers, strata_report = _strata_select(
            headers=eligible, strata=strata, suite_id=suite_id, seed=seed,
            max_cluster_share=max_cluster_share,
        )
        entries = [_entry_for_header(h, splits.get(h.case_id, Split.EVAL).value) for h in selected_headers]
    else:
        eligible.sort(key=lambda h: hashlib.sha256(
            "|".join([suite_id, str(seed), h.dataset_id, h.source_id, h.group_id]).encode()
        ).hexdigest())
        selected_headers = eligible[: max(0, target)] if target else eligible
        entries = [_entry_for_header(h, splits.get(h.case_id, Split.EVAL).value) for h in selected_headers]
        strata_report = {}

    entries.sort(key=lambda e: e.case_id)
    if benchmark_track is None or headline_eligible is None:
        try:
            from ..config import get_suite as _gs2
            _suite2 = _gs2(suite_id)
            _pt2 = _suite2.projects.get(project_id)
            if _pt2 is not None:
                if benchmark_track is None:
                    benchmark_track = getattr(_pt2, "track", "core") or "core"
                if headline_eligible is None:
                    headline_eligible = bool(getattr(_pt2, "headline_eligible", benchmark_track == "core"))
        except Exception:
            pass
    if benchmark_track is None:
        benchmark_track = "core"
    if headline_eligible is None:
        headline_eligible = (benchmark_track == "core")
    benchmark_track = str(benchmark_track).lower()
    validate_benchmark_track(benchmark_track, bool(headline_eligible))
    manifest: dict[str, Any] = {
        "manifest_version": MANIFEST_VERSION,
        "suite": suite_id,
        "project": project_id,
        "seed": seed,
        "split": sorted(allowed),
        "target": target,
        "benchmark_track": benchmark_track,
        "headline_eligible": bool(headline_eligible),
        "created_from": source_locks or {},
        "selection_policy": {
            "algorithm": "hash_rank_v1",
            "split_algorithm": "group_aware_case_count_v2" if split_version == "split-v2" else "group_aware_cumulative_count_v1",
            "split_ratios": {"dev": 0.20, "eval": 0.60, "holdout": 0.20},
            "split_version": split_version,
        },
        "n": len(entries),
        "cases": [e.to_dict() for e in entries],
    }
    if strata_report:
        manifest["strata"] = strata_report
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
    """Return a list of problems (empty == OK)."""
    problems: list[str] = []
    recomputed = manifest_sha256(manifest)
    if manifest.get("manifest_sha256") and manifest.get("manifest_sha256") != recomputed:
        problems.append(
            f"manifest_sha256 mismatch: stored={manifest.get('manifest_sha256')} computed={recomputed}"
        )
    # Phase 2.1: benchmark track invariants (review P0-2/P0-3) — missing => legacy core, present => strict
    bt = manifest.get("benchmark_track")
    he = manifest.get("headline_eligible")
    if bt is not None or he is not None:
        try:
            validate_benchmark_track(str(bt or "core"), bool(he) if he is not None else (str(bt or "core").lower() == "core"))
        except ConfigError as e:
            problems.append(str(e))
        if str(bt or "").lower() == "extended" and bool(he):
            problems.append("manifest extended track cannot be headline_eligible=true")
    entries = manifest.get("cases") or []
    seen: dict[str, int] = {}
    for e in entries:
        seen[e["case_id"]] = seen.get(e["case_id"], 0) + 1
    dupes = [cid for cid, n in seen.items() if n > 1]
    if dupes:
        problems.append(f"duplicate case_ids in manifest: {dupes[:10]}")
    group_splits: dict[str, set[str]] = {}
    for e in entries:
        group_splits.setdefault(e["group_id"], set()).add(e["split"])
    bad_groups = {g: sorted(s) for g, s in group_splits.items() if len(s) > 1}
    if bad_groups:
        problems.append(f"group spans multiple splits (train/test leakage): {bad_groups}")
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
