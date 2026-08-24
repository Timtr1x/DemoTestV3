"""Phase 1.5 v3 suite regression gates.

Locks in the guarantees that motivated Phase 1.5:

  * v3 P2 manifests carry BOTH real ground-truth kinds, never crossed
    (block <=> injection_attack, allow <=> user_authorized).
  * only phase1-standard-v3 is headline_eligible (audits passed at the
    pinned revisions); smoke/full/holdout-v3 are core but non-headline.
  * the LEGACY (v1/v2) suite snapshots still bind byte-for-byte to their
    committed manifests — history must stay reproducible.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parents[3] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from demotest.datasets.manifest_builder import (  # noqa: E402
    load_manifest,
    manifest_sha256,
)

_ROOT = Path(__file__).resolve().parents[3]
_MANIFESTS = _ROOT / "benchmarks" / "manifests"
_SUITES = _ROOT / "benchmarks" / "suites"

_V3 = ("smoke-v3", "phase1-standard-v3", "phase1-full-v3", "holdout-v3")
_LEGACY_FROZEN = (
    "smoke-v1", "smoke-v2",
    "phase1-standard-v1", "phase1-standard-v2",
    "phase1-full-v1", "phase1-full-v2",
    "holdout-v1", "holdout-v2",
)


def test_v3_p2_manifests_carry_both_kinds_never_crossed():
    for sid in _V3:
        m = load_manifest(_MANIFESTS / sid / "p2.json")
        entries = {e["case_id"]: e for e in m["cases"]}
        assert entries, f"{sid}/p2.json empty"
        # resolve full case payloads from the normalized snapshot
        snap: dict[str, dict] = {}
        norm = _ROOT / "cache" / "datasets_v3" / "normalized" / "agentdojo" / "cases.jsonl"
        for line in norm.read_text(encoding="utf-8").splitlines():
            c = json.loads(line)
            snap[c["case_id"]] = c
        actions, kinds = set(), set()
        for cid, e in entries.items():
            c = snap[cid]
            act = c["expected_action"]
            kind = c["metadata"]["ground_truth_kind"]
            actions.add(act)
            kinds.add(kind)
            assert (act == "block") == (kind == "injection_attack"), \
                f"{sid}: ground-truth kinds crossed at {cid}"
            if act == "allow":
                assert c["metadata"]["parent_source_id"].count(":user:") == 1
        assert actions == {"block", "allow"}, f"{sid}: P2 must have BLOCK+ALLOW"
        assert kinds == {"injection_attack", "user_authorized"}


def test_only_phase1_standard_v3_is_headline():
    for sid in _V3:
        for p in ("p1.json", "p2.json"):
            m = load_manifest(_MANIFESTS / sid / p)
            assert m["benchmark_track"] == "core", f"{sid}/{p} track"
            want = sid == "phase1-standard-v3"
            assert m["headline_eligible"] is want, \
                f"{sid}/{p} headline_eligible={m['headline_eligible']} expected {want}"


def test_v1_manifests_excluded_retired_projection():
    """The deprecated v1 P1 manifests are exactly the ones mixing agentdojo.

    smoke-v1/p1 is llmail-only, but phase1-standard/full/holdout-v1 carry the
    retired AgentDojo P1 tool_result projection — the reason all four are
    marked HISTORICAL.
    """
    for sid in ("phase1-standard-v1", "phase1-full-v1", "holdout-v1"):
        m = load_manifest(_MANIFESTS / sid / "p1.json")
        ds = {e["dataset_id"] for e in m["cases"]}
        assert "agentdojo" in ds, f"{sid}/p1 should document the retired projection"
    assert {e["dataset_id"] for e in
            load_manifest(_MANIFESTS / "smoke-v1" / "p1.json")["cases"]} == {"llmail"}
    for sid in ("smoke-v2", "phase1-standard-v2", "holdout-v2"):
        m = load_manifest(_MANIFESTS / sid / "p1.json")
        assert {e["dataset_id"] for e in m["cases"]} == {"llmail"}


def test_legacy_suite_snapshots_still_bind_committed_manifests():
    """Any swap/edit of a v1/v2 manifest breaks its frozen suite binding.

    Binding check = suite-recorded sha256 == the manifest file's EMBEDDED
    self-hash (works across hash-algorithm generations). Additionally, the
    v2 manifests must satisfy the CURRENT canonical recomputation; the v1
    manifests predate it (known legacy condition, see HISTORICAL.md) and are
    intentionally left byte-frozen rather than regenerated.
    """
    for sid in _LEGACY_FROZEN:
        snap = json.loads((_SUITES / f"{sid}.json").read_text(encoding="utf-8"))
        for pid, info in snap["projects"].items():
            mp = _ROOT / info["manifest"]
            assert mp.exists(), f"{sid}/{pid}: manifest vanished"
            m = load_manifest(mp)
            assert m["manifest_sha256"] == info["manifest_sha256"], \
                f"{sid}/{pid}: frozen manifest was swapped/modified"
            if sid.endswith("-v2"):
                assert manifest_sha256(m) == info["manifest_sha256"], \
                    f"{sid}/{pid}: v2 manifest must recompute under canonical sha"


@pytest.mark.parametrize("dataset,expected_n,blocks,allows", [
    ("llmail", 3860, 3700, 160),
    ("agentdojo", 1005, 670, 335),
])
def test_normalized_snapshot_action_counts(dataset, expected_n, blocks, allows):
    norm = _ROOT / "cache" / "datasets_v3" / "normalized" / dataset / "cases.jsonl"
    n = b = a = 0
    for line in norm.read_text(encoding="utf-8").splitlines():
        c = json.loads(line)
        n += 1
        b += c["expected_action"] == "block"
        a += c["expected_action"] == "allow"
    assert (n, b, a) == (expected_n, blocks, allows)
