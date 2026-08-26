"""Tests for p4_recover_official_skill_sources — official-first recovery.

Covers the 7 required cases without Docker/SkillsMP:

  - no candidate but complete official evidence -> BOUND_EXACT
  - candidate and official consistent -> BOUND_EXACT
  - candidate and official inconsistent -> official independent, not polluted
  - same skill multi evidence consistent -> merged
  - multi evidence repo/path conflict -> BOUND_AMBIGUOUS
  - branch-only -> not bound
  - repo@commit path missing / hash drift -> fail closed
  - stable official_skill_key (multi skill_id preserved)
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))

import p4_recover_official_skill_sources as rec  # noqa: E402


def test_no_candidate_but_official_yields_bound_exact():
    r = rec.resolve_skill_source(
        "my-skill", ["56_my-skill"], [],
        [{"official_skill_name": "my-skill", "repo_url": "https://github.com/org/repo",
          "commit_sha": "a" * 40, "skill_path": "skills/my-skill", "source_sha256": "f" * 64}],
    )
    assert r["status"] == "BOUND_EXACT"
    assert r["official_skill_key"].startswith("osk:")
    assert r["repo_url"] and r["commit_sha"]


def test_candidate_and_official_consistent_exact():
    cand = [{"candidate_id": "c1", "skill_name": "s",
             "repo_url": "https://github.com/org/repo", "source_sha256": "f" * 64,
             "local_path": "skills/s", "skill_subdir": "skills/s"}]
    ev = [{"official_skill_name": "s", "repo_url": "https://github.com/org/repo",
           "commit_sha": "b" * 40, "skill_path": "skills/s", "source_sha256": "f" * 64}]
    r = rec.resolve_skill_source("s", ["56_s"], cand, ev)
    assert r["status"] == "BOUND_EXACT"


def test_official_not_polluted_by_candidate_mismatch():
    # Candidate points elsewhere but official is valid -> official-first still BOUND_EXACT
    cand = [{"candidate_id": "c1", "skill_name": "s",
             "repo_url": "https://github.com/org/other", "source_sha256": "f" * 64,
             "local_path": "skills/s"}]
    ev = [{"official_skill_name": "s", "repo_url": "https://github.com/org/repo",
           "commit_sha": "c" * 40, "skill_path": "skills/s", "source_sha256": "e" * 64}]
    r = rec.resolve_skill_source("s", ["56_s"], cand, ev)
    assert r["status"] == "BOUND_EXACT"
    assert "candidate cache differs" in r["binding_method"]


def test_multi_evidence_consistent_merged():
    ev = [
        {"official_skill_name": "s", "repo_url": "https://github.com/org/repo",
         "commit_sha": "d" * 40, "skill_path": "skills/s", "source_sha256": "f" * 64},
        {"official_skill_name": "s", "repo_url": "https://github.com/org/repo",
         "commit_sha": "d" * 40, "skill_path": "skills/s", "source_sha256": "f" * 64},
    ]
    r = rec.resolve_skill_source("s", ["56_s"], [], ev)
    assert r["status"] == "BOUND_EXACT"
    assert r["evidence_count"] == 2
    assert r["distinct_evidence_keys"] == 1


def test_multi_evidence_conflict_ambiguous():
    ev = [
        {"official_skill_name": "s", "repo_url": "https://github.com/org/repo1",
         "commit_sha": "a" * 40, "skill_path": "skills/s", "source_sha256": "f" * 64},
        {"official_skill_name": "s", "repo_url": "https://github.com/org/repo2",
         "commit_sha": "b" * 40, "skill_path": "skills/s", "source_sha256": "e" * 64},
    ]
    r = rec.resolve_skill_source("s", ["56_s"], [], ev)
    assert r["status"] == "BOUND_AMBIGUOUS"


def test_branch_only_not_bound():
    ev = [{"official_skill_name": "s", "repo_url": "https://github.com/org/repo",
           "commit_sha": "main", "skill_path": "skills/s", "source_sha256": "f" * 64}]
    r = rec.resolve_skill_source("s", ["56_s"], [], ev)
    assert r["status"] == "SOURCE_NOT_FOUND"
    assert "branch-only" in r["binding_method"]


def test_hash_drift_and_missing_path_fail_closed(tmp_path):
    root = tmp_path / "tree"
    sp = root / "skills/s"
    sp.mkdir(parents=True)
    (sp / "a.txt").write_text("hello", encoding="utf-8")
    sha, _ = rec.compute_tree_sha_for_skill_path(root, "skills/s")
    assert sha and len(sha) == 64

    # drift: official claims wrong sha
    ev = [{"official_skill_name": "s", "repo_url": "https://github.com/org/repo",
           "commit_sha": "e" * 40, "skill_path": "skills/s", "source_sha256": "0" * 64}]
    r = rec.resolve_skill_source("s", ["56_s"], [], ev, tree_root_resolver=lambda *a: root)
    assert r["status"] == "SOURCE_NOT_FOUND"
    assert "drift" in r["binding_method"]

    # missing path
    ev2 = [{"official_skill_name": "s", "repo_url": "https://github.com/org/repo",
            "commit_sha": "e" * 40, "skill_path": "skills/missing", "source_sha256": sha}]
    r2 = rec.resolve_skill_source("s", ["56_s"], [], ev2, tree_root_resolver=lambda *a: root)
    assert r2["status"] == "SOURCE_NOT_FOUND"
    assert "missing path" in r2["binding_method"]


def test_official_skill_key_stable_and_multi_id():
    k1 = rec.official_skill_key("creative-writer", ["56_creative-writer", "277_creative-writer"])
    k2 = rec.official_skill_key("creative-writer", ["277_creative-writer", "56_creative-writer"])
    assert k1 == k2
    assert k1.startswith("osk:")
    k3 = rec.official_skill_key("creative-writer", ["56_creative-writer"])
    assert k1 != k3
    # skill_name is part of key, not just ids
    k4 = rec.official_skill_key("other", ["56_creative-writer", "277_creative-writer"])
    assert k1 != k4


def test_recompute_sha_not_only_sidecar(tmp_path):
    root = tmp_path / "tree"
    sp = root / "skills/s"
    sp.mkdir(parents=True)
    (sp / "x.txt").write_text("content v1", encoding="utf-8")
    sha, _ = rec.compute_tree_sha_for_skill_path(root, "skills/s")
    ev = [{"official_skill_name": "s", "repo_url": "https://github.com/org/repo",
           "commit_sha": "f" * 40, "skill_path": "skills/s", "source_sha256": sha}]
    r = rec.resolve_skill_source("s", ["56_s"], [], ev, tree_root_resolver=lambda *a: root)
    assert r["status"] == "BOUND_EXACT"
    assert r["source_sha256"].lower() == sha.lower()
    # mutate file -> drift detected
    (sp / "x.txt").write_text("content v2", encoding="utf-8")
    r2 = rec.resolve_skill_source("s", ["56_s"], [], ev, tree_root_resolver=lambda *a: root)
    assert r2["status"] == "SOURCE_NOT_FOUND"
