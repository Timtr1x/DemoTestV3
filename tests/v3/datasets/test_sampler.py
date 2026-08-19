"""Sampler: hash selection + group-aware split tests (guide §28-§32)."""
from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[3] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from demotest.core.models import SecurityCase  # noqa: E402
from demotest.datasets.sampler import (  # noqa: E402
    Split,
    assign_splits,
    group_id_of,
    select_for_suite,
    selection_key,
)


def _case(sid: str, group: str, content: str = "x") -> SecurityCase:
    c = SecurityCase.build(
        dataset_id="t", source_id=sid, channel="email", operation="read", content=content
    )
    d = c.to_dict()
    d["metadata"] = {"group_id": group}
    return SecurityCase.from_dict(d)


def test_selection_key_order_independent_and_stable():
    a = _case("s1", "g1", "a")
    b = _case("s2", "g2", "b")
    k1 = selection_key(a, suite_version="std-v1", seed=42, dataset_id="t")
    k2 = selection_key(b, suite_version="std-v1", seed=42, dataset_id="t")
    assert k1 != k2
    # same inputs -> same key forever
    assert selection_key(a, suite_version="std-v1", seed=42, dataset_id="t") == k1


def test_assign_splits_20_60_20_by_group():
    # 10 distinct groups -> 2 dev, 6 eval, 2 holdout
    cases = [_case(f"s{i}", f"g{i}") for i in range(10)]
    splits = assign_splits(cases, seed=42)
    counts = {"dev": 0, "eval": 0, "holdout": 0}
    for s in splits.values():
        counts[s.value] += 1
    assert counts == {"dev": 2, "eval": 6, "holdout": 2}


def test_assign_splits_group_shares_split():
    # two cases in the same group must land in the same split (guide §22)
    a = _case("s1", "gX", "content a")
    b = _case("s2", "gX", "content b")
    splits = assign_splits([a, b], seed=42)
    assert splits[a.case_id] == splits[b.case_id]


def test_select_for_suite_respects_split_filter():
    # 50 groups -> ~10 dev groups (20%), so target=3 from DEV is feasible
    cases = [_case(f"s{i}", f"g{i}") for i in range(50)]
    res = select_for_suite(
        cases, suite_version="std-v1", seed=42, dataset_id="t", target=3, split=Split.DEV
    )
    assert res.n_selected == 3
    # every selected case must be in the DEV split
    splits = assign_splits(cases, seed=42)
    for c in res.selected:
        assert splits[c.case_id] == Split.DEV


def test_select_for_suite_deterministic():
    cases = [_case(f"s{i}", f"g{i}") for i in range(10)]
    r1 = select_for_suite(cases, suite_version="std-v1", seed=42, dataset_id="t", target=5, split=Split.EVAL)
    r2 = select_for_suite(cases, suite_version="std-v1", seed=42, dataset_id="t", target=5, split=Split.EVAL)
    assert [c.case_id for c in r1.selected] == [c.case_id for c in r2.selected]


def test_group_id_falls_back_to_source_id():
    c = SecurityCase.build(dataset_id="t", source_id="lonely", channel="email", operation="read", content="x")
    assert group_id_of(c) == "lonely"
