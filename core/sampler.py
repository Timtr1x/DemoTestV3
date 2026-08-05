"""Stratified sampling engine + manifest read/write (refuse overwrite)."""
from __future__ import annotations

import json
import os
import random
from collections import defaultdict
from pathlib import Path
from typing import Sequence

from core.schema import Manifest, Sample
from paths import MANIFEST_DIR

SAMPLE_SEED = int(os.environ.get("SAMPLE_SEED", "42"))


class ManifestExistsError(FileExistsError):
    """Raised when save_manifest would overwrite an existing file."""


def manifest_path(name: str, directory: Path | None = None) -> Path:
    base = directory if directory is not None else MANIFEST_DIR
    return base / f"{name}.json"


def stratified_sample(
    samples: Sequence[Sample],
    quotas: dict[str, int],
    seed: int = SAMPLE_SEED,
    *,
    strata_key: str = "subset",
) -> list[Sample]:
    """Stratified sample by subset (or other attribute).

    quotas: {stratum_name: target_count}
    1. Group by strata_key
    2. rng = random.Random(seed); sample within each group
    3. Short groups take all; shortfall redistributed via largest remainder
       among groups that still have remainder capacity
    4. No sequential head-N without seed
    """
    if not quotas:
        return []

    groups: dict[str, list[Sample]] = defaultdict(list)
    for s in samples:
        key = getattr(s, strata_key, None)
        if key is None:
            key = s.subset
        groups[str(key)].append(s)

    rng = random.Random(seed)
    selected: list[Sample] = []
    shortfall = 0
    capacity_left: dict[str, list[Sample]] = {}

    # First pass: honor per-stratum quotas
    for stratum, target in quotas.items():
        pool = list(groups.get(stratum, []))
        if target <= 0:
            continue
        if len(pool) <= target:
            selected.extend(pool)
            shortfall += target - len(pool)
        else:
            picked = rng.sample(pool, target)
            selected.extend(picked)
            picked_ids = {p.sample_id for p in picked}
            remaining = [x for x in pool if x.sample_id not in picked_ids]
            if remaining:
                capacity_left[stratum] = remaining

    # Also allow redistributing into strata present in data but not short if they have capacity
    for stratum, pool in groups.items():
        if stratum in capacity_left:
            continue
        taken_ids = {s.sample_id for s in selected if s.subset == stratum or getattr(s, strata_key) == stratum}
        remaining = [x for x in pool if x.sample_id not in {s.sample_id for s in selected}]
        if remaining and stratum in quotas:
            # already handled
            pass
        elif remaining and shortfall > 0 and stratum not in quotas:
            capacity_left[stratum] = remaining

    # Rebuild capacity_left from all groups minus selected
    selected_ids = {s.sample_id for s in selected}
    capacity_left = {}
    for stratum, pool in groups.items():
        rem = [x for x in pool if x.sample_id not in selected_ids]
        if rem:
            capacity_left[stratum] = rem

    if shortfall > 0 and capacity_left:
        # largest remainder: distribute shortfall proportional to remaining sizes
        keys = sorted(capacity_left.keys())  # stable order
        sizes = [len(capacity_left[k]) for k in keys]
        total_cap = sum(sizes)
        if total_cap > 0:
            to_take = min(shortfall, total_cap)
            # Hamilton / largest remainder
            exact = [to_take * (sz / total_cap) for sz in sizes]
            floors = [int(x) for x in exact]
            assigned = sum(floors)
            remainders = sorted(
                [(exact[i] - floors[i], i) for i in range(len(keys))],
                reverse=True,
            )
            extra = to_take - assigned
            for j in range(extra):
                floors[remainders[j][1]] += 1
            for i, k in enumerate(keys):
                n = floors[i]
                if n <= 0:
                    continue
                pool = capacity_left[k]
                n = min(n, len(pool))
                picked = rng.sample(pool, n)
                selected.extend(picked)
                selected_ids.update(p.sample_id for p in picked)

    # Deterministic final order: sort by sample_id for stable manifests
    selected.sort(key=lambda s: s.sample_id)
    return selected


def save_manifest(
    m: Manifest,
    *,
    directory: Path | None = None,
    force: bool = False,
) -> Path:
    """Write manifest JSON. Refuses overwrite unless force=True (tests only)."""
    p = manifest_path(m.name, directory)
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.exists() and not force:
        raise ManifestExistsError(
            f"Manifest already exists: {p}. Delete it explicitly to re-sample "
            f"(retest discipline requires a deliberate delete)."
        )
    text = json.dumps(m.to_dict(), ensure_ascii=False, indent=2)
    p.write_text(text, encoding="utf-8")
    return p


def load_manifest(name: str, *, directory: Path | None = None) -> Manifest:
    """Run-phase entry: load named manifest only (no re-sample)."""
    p = manifest_path(name, directory)
    if not p.exists():
        raise FileNotFoundError(f"Manifest not found: {p}")
    data = json.loads(p.read_text(encoding="utf-8"))
    return Manifest.from_dict(data)


def load_manifest_path(path: Path) -> Manifest:
    data = json.loads(path.read_text(encoding="utf-8"))
    return Manifest.from_dict(data)


def build_manifest(
    name: str,
    samples: Sequence[Sample],
    *,
    seed: int,
    source_dataset: str,
    dataset_version: str,
    adapter_version: str,
    template_version: str = "none",
    strata_key: str = "subset",
    extra: dict | None = None,
) -> Manifest:
    counts: dict[str, int] = defaultdict(int)
    for s in samples:
        key = str(getattr(s, strata_key, s.subset))
        counts[key] += 1
    return Manifest(
        name=name,
        created_at=Manifest.now_iso(),
        seed=seed,
        source_dataset=source_dataset,
        dataset_version=dataset_version,
        adapter_version=adapter_version,
        template_version=template_version,
        strata_counts=dict(counts),
        samples=list(samples),
        extra=dict(extra or {}),
    )
