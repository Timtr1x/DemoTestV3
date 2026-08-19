"""Stratified sampler + manifest refuse-overwrite tests."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.sampler import (  # noqa: E402
    ManifestExistsError,
    allocate_proportional,
    build_manifest,
    deterministic_subsample,
    load_manifest,
    save_manifest,
    stratified_sample,
)
from core.schema import Sample  # noqa: E402


def _mk(subset: str, i: int) -> Sample:
    return Sample(
        sample_id=f"e1:t:{subset}:{i}",
        project="e1",
        source_dataset="test",
        subset=subset,
        category=subset,
        label="attack",
        prompt_text=f"p-{subset}-{i}",
        expected="blocked",
    )


def test_stratified_deterministic_seed42():
    pool = [_mk("a", i) for i in range(50)] + [_mk("b", i) for i in range(50)]
    q = {"a": 10, "b": 10}
    s1 = stratified_sample(pool, q, seed=42)
    s2 = stratified_sample(pool, q, seed=42)
    assert [x.sample_id for x in s1] == [x.sample_id for x in s2]
    assert len(s1) == 20
    assert sum(1 for x in s1 if x.subset == "a") == 10


def test_shortfall_redistribution():
    pool = [_mk("a", i) for i in range(3)] + [_mk("b", i) for i in range(50)]
    q = {"a": 10, "b": 5}  # a short by 7, redistribute from b capacity
    s = stratified_sample(pool, q, seed=42)
    assert len(s) == 10 + 5  # wait: a takes 3, shortfall 7, b takes 5 + up to 7 more = 15?
    # a contributes 3, b contributes 5 + redistributed min(7, 45) = 7 → total 3+5+7=15
    assert len(s) == 15
    assert sum(1 for x in s if x.subset == "a") == 3


def test_allocate_proportional_retestable():
    a1 = allocate_proportional([400, 400, 50, 30, 100, 100], 500)
    a2 = allocate_proportional([400, 400, 50, 30, 100, 100], 500)
    assert a1 == a2
    assert sum(a1) == 500
    # capacity clamp redistributes
    capped = allocate_proportional([250, 150], 500, capacities=[300, 300])
    assert sum(capped) == 500
    assert capped[0] <= 300 and capped[1] <= 300
    assert capped == [300, 200] or sum(capped) == 500


def test_deterministic_subsample_seed42():
    pool = [_mk("a", i) for i in range(100)]
    s1 = deterministic_subsample(pool, 20, seed=42)
    s2 = deterministic_subsample(pool, 20, seed=42)
    assert [x.sample_id for x in s1] == [x.sample_id for x in s2]
    assert len(s1) == 20
    assert s1 == sorted(s1, key=lambda x: x.sample_id)


def test_save_manifest_refuse_overwrite(tmp_path: Path):

    samples = [_mk("a", 0)]
    m = build_manifest(
        "unit_m1",
        samples,
        seed=42,
        source_dataset="test",
        dataset_version="v1",
        adapter_version="t@1",
        template_version="none",
    )
    p1 = save_manifest(m, directory=tmp_path)
    assert p1.exists()
    with pytest.raises(ManifestExistsError):
        save_manifest(m, directory=tmp_path)
    loaded = load_manifest("unit_m1", directory=tmp_path)
    assert loaded.dataset_version == "v1"
    assert loaded.adapter_version == "t@1"
    assert loaded.template_version == "none"
    assert len(loaded.samples) == 1
