"""Manifest builder + verifier tests (fix round v3.2)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parents[3] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from demotest.core.models import SecurityCase  # noqa: E402
from demotest.datasets.manifest_builder import (  # noqa: E402
    build_manifest,
    load_manifest,
    manifest_sha256,
    verify_manifest,
    write_manifest,
)


def _case(sid: str, group: str, content: str = "x") -> SecurityCase:
    c = SecurityCase.build(
        dataset_id="llmail", source_id=sid, channel="email", operation="read", content=content
    )
    d = c.to_dict()
    d["metadata"] = {"group_id": group}
    return SecurityCase.from_dict(d)


def _cases(n=20):
    return [_case(f"s{i}", f"g{i}", content=f"payload {i}") for i in range(n)]


def test_build_manifest_basic_shape():
    m = build_manifest(
        suite_id="std-v1", project_id="P1_external_instruction",
        cases=_cases(20), seed=42, split="eval", target=5,
    )
    assert m["manifest_version"] == "v3.2"
    assert m["suite"] == "std-v1"
    assert m["project"] == "P1_external_instruction"
    assert m["n"] == 5
    assert m["selection_policy"]["algorithm"] == "hash_rank_v1"
    assert "created_at" not in m
    assert len(m["cases"]) == 5
    for e in m["cases"]:
        assert "case_id" in e and "case_fingerprint" in e and "split" in e and "group_id" in e


def test_manifest_reproducible_byte_identical(tmp_path: Path):
    cases = _cases(30)
    m1 = build_manifest(suite_id="std-v1", project_id="P1", cases=cases, seed=42, split="eval", target=10)
    m2 = build_manifest(suite_id="std-v1", project_id="P1", cases=cases, seed=42, split="eval", target=10)
    assert [e["case_id"] for e in m1["cases"]] == [e["case_id"] for e in m2["cases"]]
    assert manifest_sha256(m1) == manifest_sha256(m2)
    p1 = write_manifest(m1, tmp_path / "a.json")
    p2 = write_manifest(m2, tmp_path / "b.json")
    assert p1.read_bytes() == p2.read_bytes()


def test_manifest_self_hash_verifies(tmp_path: Path):
    m = build_manifest(suite_id="std-v1", project_id="P1", cases=_cases(20), seed=42, split="eval", target=5)
    p = write_manifest(m, tmp_path / "m.json")
    loaded = load_manifest(p)
    assert loaded["manifest_sha256"] == manifest_sha256(loaded)
    assert verify_manifest(loaded) == []


def test_verify_detects_duplicate_case_ids():
    m = build_manifest(suite_id="x", project_id="P1", cases=_cases(20), seed=42, split="eval", target=5)
    m["cases"].append(dict(m["cases"][0]))
    problems = verify_manifest(m)
    assert any("duplicate case_ids" in p for p in problems)


def test_verify_detects_group_spanning_splits():
    m = build_manifest(suite_id="x", project_id="P1", cases=_cases(20), seed=42, split=["eval", "holdout"], target=10)
    if len(m["cases"]) >= 2:
        m["cases"][0]["group_id"] = "shared"
        m["cases"][1]["group_id"] = "shared"
        m["cases"][0]["split"] = "eval"
        m["cases"][1]["split"] = "holdout"
    problems = verify_manifest(m)
    assert any("spans multiple splits" in p for p in problems)


def test_verify_detects_fingerprint_drift():
    cases = _cases(20)
    m = build_manifest(suite_id="x", project_id="P1", cases=cases, seed=42, split="eval", target=5)
    m["cases"][0]["case_fingerprint"] = "fp-tampered"
    resolved = {c.case_id: c for c in cases}
    problems = verify_manifest(m, resolved_cases=resolved)
    assert any("fingerprint drift" in p for p in problems)


def test_verify_detects_unresolvable_case():
    m = build_manifest(suite_id="x", project_id="P1", cases=_cases(20), seed=42, split="eval", target=5)
    m["cases"][0]["case_id"] = "case-doesnotexist"
    problems = verify_manifest(m, resolved_cases={})
    assert any("not resolvable" in p for p in problems)


def test_strata_selection():
    from demotest.core.enums import ExpectedAction
    cases = []
    for i in range(20):
        ea = ExpectedAction.BLOCK if i < 15 else ExpectedAction.ALLOW
        c = SecurityCase.build(dataset_id="llmail", source_id=f"s{i}", channel="email", operation="read", content=f"payload {i}", expected_action=ea)
        d = c.to_dict()
        d["metadata"] = {"group_id": f"g{i}"}
        cases.append(SecurityCase.from_dict(d))
    strata = [
        {"id": "attack", "dataset": "llmail", "expected_action": "block", "count": 10},
        {"id": "benign", "dataset": "llmail", "expected_action": "allow", "count": "all"},
    ]
    # eligible eval pool is ~60% of groups, so attack filtered <15
    m = build_manifest(suite_id="std-v1", project_id="P1", cases=cases, seed=42, split=["eval","holdout","dev"], target=15, strata=strata)
    assert m["strata"]["attack"]["actual"] == 10
    assert m["strata"]["benign"]["actual"] == 5


def test_cluster_cap():
    cases = []
    # one big cluster with 20 cases same group
    for i in range(30):
        gid = "big" if i < 20 else f"g{i}"
        c = SecurityCase.build(dataset_id="llmail", source_id=f"s{i}", channel="email", operation="read", content=f"payload {i}")
        d = c.to_dict()
        d["metadata"] = {"group_id": gid, "near_dup_cluster_id": gid}
        cases.append(SecurityCase.from_dict(d))
    strata = [{"id": "attack", "dataset": "llmail", "expected_action": "block", "count": 20}]
    m = build_manifest(suite_id="std-v1", project_id="P1", cases=cases, seed=42, split="eval", target=20, strata=strata, max_cluster_share=0.10)
    # cap = ceil(20*0.10)=2 per cluster
    from collections import Counter
    cnt = Counter(e["group_id"] for e in m["cases"])
    assert max(cnt.values()) <= 2


def test_byte_identical_after_delete_rebuild(tmp_path: Path):
    cases = _cases(30)
    m1 = build_manifest(suite_id="std-v1", project_id="P1", cases=cases, seed=42, split="eval", target=10)
    p = write_manifest(m1, tmp_path / "m.json")
    b1 = p.read_bytes()
    p.unlink()
    m2 = build_manifest(suite_id="std-v1", project_id="P1", cases=cases, seed=42, split="eval", target=10)
    write_manifest(m2, tmp_path / "m.json")
    b2 = (tmp_path / "m.json").read_bytes()
    assert b1 == b2
