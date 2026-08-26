"""Tests for p4_recover_official_skill_sources — official-first, recompute-gated.

Two-tier trust (2026-08-26 review):
  SOURCE_OBJECT_VERIFIED = repo@immutable_commit acquired + subtree SHA recomputed (object verified)
  OFFICIAL_SKILL_BOUND   = SOURCE_VERIFIED + VERIFIED_OFFICIAL_MAPPING (private master / official metadata / Zenodo)
Sidecar repo/commit/path/source_sha alone is OFFICIAL_SOURCE_DECLARED, never verified.
Same (repo,commit,path) with multiple distinct non-empty source_sha -> BOUND_AMBIGUOUS.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))

import p4_recover_official_skill_sources as rec  # noqa: E402


def test_declared_not_exact_without_acquire():
    r = rec.resolve_skill_source(
        "my-skill", ["56_my-skill"], [],
        [{"official_skill_name": "my-skill", "repo_url": "https://github.com/org/repo",
          "commit_sha": "a" * 40, "skill_path": "skills/my-skill", "source_sha256": "f" * 64}],
    )
    assert r["status"] == "OFFICIAL_SOURCE_DECLARED"
    assert r["official_skill_key"].startswith("osk:")


def test_acquire_and_hash_match_gives_exact(tmp_path):
    root = tmp_path / "tree"
    sp = root / "skills/s"
    sp.mkdir(parents=True)
    (sp / "x.txt").write_text("content v1", encoding="utf-8")
    sha, _ = rec.compute_tree_sha_for_skill_path(root, "skills/s")
    assert sha and len(sha) == 64
    ev = [{"official_skill_name": "s", "repo_url": "https://github.com/org/repo",
           "commit_sha": "b" * 40, "skill_path": "skills/s", "source_sha256": sha}]
    r = rec.resolve_skill_source("s", ["56_s"], [], ev, tree_root_resolver=lambda *a: root)
    assert r["status"] == "SOURCE_OBJECT_VERIFIED"
    assert r["source_sha256"].lower() == sha.lower()


def test_acquire_and_hash_match_with_candidate_consistent(tmp_path):
    root = tmp_path / "tree"
    sp = root / "skills/s"
    sp.mkdir(parents=True)
    (sp / "a.txt").write_text("hello world", encoding="utf-8")
    sha, _ = rec.compute_tree_sha_for_skill_path(root, "skills/s")
    cand = [{"candidate_id": "c1", "skill_name": "s",
             "repo_url": "https://github.com/org/repo", "source_sha256": sha,
             "local_path": "skills/s", "skill_subdir": "skills/s"}]
    ev = [{"official_skill_name": "s", "repo_url": "https://github.com/org/repo",
           "commit_sha": "c" * 40, "skill_path": "skills/s", "source_sha256": sha}]
    r = rec.resolve_skill_source("s", ["56_s"], cand, ev, tree_root_resolver=lambda *a: root)
    assert r["status"] == "SOURCE_OBJECT_VERIFIED"


def test_official_not_polluted_by_candidate_mismatch_but_declared_without_acquire():
    # Without acquire, even valid official is only DECLARED, not verified
    cand = [{"candidate_id": "c1", "skill_name": "s",
             "repo_url": "https://github.com/org/other", "source_sha256": "f" * 64,
             "local_path": "skills/s"}]
    ev = [{"official_skill_name": "s", "repo_url": "https://github.com/org/repo",
           "commit_sha": "c" * 40, "skill_path": "skills/s", "source_sha256": "e" * 64}]
    r = rec.resolve_skill_source("s", ["56_s"], cand, ev)
    assert r["status"] == "OFFICIAL_SOURCE_DECLARED"


def test_official_with_acquire_not_polluted_by_candidate_mismatch(tmp_path):
    root = tmp_path / "tree"
    sp = root / "skills/s"
    sp.mkdir(parents=True)
    (sp / "a.txt").write_text("hello", encoding="utf-8")
    sha, _ = rec.compute_tree_sha_for_skill_path(root, "skills/s")
    cand = [{"candidate_id": "c1", "skill_name": "s",
             "repo_url": "https://github.com/org/other", "source_sha256": "f" * 64,
             "local_path": "skills/s"}]
    ev = [{"official_skill_name": "s", "repo_url": "https://github.com/org/repo",
           "commit_sha": "d" * 40, "skill_path": "skills/s", "source_sha256": sha}]
    r = rec.resolve_skill_source("s", ["56_s"], cand, ev, tree_root_resolver=lambda *a: root)
    assert r["status"] == "SOURCE_OBJECT_VERIFIED"
    assert "candidate cache differs" in r["binding_method"]


def test_same_logical_source_multi_sha_conflict_ambiguous():
    ev = [
        {"official_skill_name": "s", "repo_url": "https://github.com/org/repo",
         "commit_sha": "a" * 40, "skill_path": "skills/s", "source_sha256": "f" * 64},
        {"official_skill_name": "s", "repo_url": "https://github.com/org/repo",
         "commit_sha": "a" * 40, "skill_path": "skills/s", "source_sha256": "e" * 64},
    ]
    r = rec.resolve_skill_source("s", ["56_s"], [], ev)
    assert r["status"] == "BOUND_AMBIGUOUS"
    assert "distinct non-empty source_sha" in r["binding_method"]


def test_multi_evidence_consistent_merge_still_declared_without_acquire():
    ev = [
        {"official_skill_name": "s", "repo_url": "https://github.com/org/repo",
         "commit_sha": "d" * 40, "skill_path": "skills/s", "source_sha256": "f" * 64},
        {"official_skill_name": "s", "repo_url": "https://github.com/org/repo",
         "commit_sha": "d" * 40, "skill_path": "skills/s", "source_sha256": "f" * 64},
    ]
    r = rec.resolve_skill_source("s", ["56_s"], [], ev)
    assert r["status"] == "OFFICIAL_SOURCE_DECLARED"
    assert r["evidence_count"] == 2
    assert r["distinct_evidence_keys"] == 1


def test_multi_evidence_consistent_merge_exact_with_acquire(tmp_path):
    root = tmp_path / "tree"
    sp = root / "skills/s"
    sp.mkdir(parents=True)
    (sp / "x.txt").write_text("hello", encoding="utf-8")
    sha, _ = rec.compute_tree_sha_for_skill_path(root, "skills/s")
    ev = [
        {"official_skill_name": "s", "repo_url": "https://github.com/org/repo",
         "commit_sha": "d" * 40, "skill_path": "skills/s", "source_sha256": sha},
        {"official_skill_name": "s", "repo_url": "https://github.com/org/repo",
         "commit_sha": "d" * 40, "skill_path": "skills/s", "source_sha256": sha},
    ]
    r = rec.resolve_skill_source("s", ["56_s"], [], ev, tree_root_resolver=lambda *a: root)
    assert r["status"] == "SOURCE_OBJECT_VERIFIED"


def test_multi_evidence_repo_path_conflict_ambiguous():
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
    ev = [{"official_skill_name": "s", "repo_url": "https://github.com/org/repo",
           "commit_sha": "e" * 40, "skill_path": "skills/s", "source_sha256": "0" * 64}]
    r = rec.resolve_skill_source("s", ["56_s"], [], ev, tree_root_resolver=lambda *a: root)
    assert r["status"] == "SOURCE_NOT_FOUND"
    assert "drift" in r["binding_method"]
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
    k4 = rec.official_skill_key("other", ["56_creative-writer", "277_creative-writer"])
    assert k1 != k4


def test_recompute_sha_after_mutation_fails(tmp_path):
    root = tmp_path / "tree"
    sp = root / "skills/s"
    sp.mkdir(parents=True)
    (sp / "x.txt").write_text("content v1", encoding="utf-8")
    sha, _ = rec.compute_tree_sha_for_skill_path(root, "skills/s")
    ev = [{"official_skill_name": "s", "repo_url": "https://github.com/org/repo",
           "commit_sha": "f" * 40, "skill_path": "skills/s", "source_sha256": sha}]
    r = rec.resolve_skill_source("s", ["56_s"], [], ev, tree_root_resolver=lambda *a: root)
    assert r["status"] == "SOURCE_OBJECT_VERIFIED"
    (sp / "x.txt").write_text("content v2", encoding="utf-8")
    r2 = rec.resolve_skill_source("s", ["56_s"], [], ev, tree_root_resolver=lambda *a: root)
    assert r2["status"] == "SOURCE_NOT_FOUND"


def test_verified_mapping_promotes_to_official_skill_bound(tmp_path):
    root = tmp_path / "tree"
    sp = root / "skills/s"
    sp.mkdir(parents=True)
    (sp / "a.txt").write_text("hello", encoding="utf-8")
    sha, _ = rec.compute_tree_sha_for_skill_path(root, "skills/s")
    ev = [{"official_skill_name": "s", "repo_url": "https://github.com/org/repo",
           "commit_sha": "a" * 40, "skill_path": "skills/s", "source_sha256": sha,
           "mapping_provenance": {"audit_verdict": "VERIFIED_OFFICIAL_MAPPING",
                                  "mapping_source_type": "private_master",
                                  "mapping_source_uri": "private/creds_in_skills.xlsx",
                                  "mapping_method": "official manifest"}}]
    r = rec.resolve_skill_source("s", ["56_s"], [], ev, tree_root_resolver=lambda *a: root)
    assert r["status"] == "OFFICIAL_SKILL_BOUND"
    assert r["audit_verdict"] == "VERIFIED_OFFICIAL_MAPPING"


def test_inferred_mapping_stays_source_object_verified(tmp_path):
    root = tmp_path / "tree"
    sp = root / "skills/s"
    sp.mkdir(parents=True)
    (sp / "a.txt").write_text("hello", encoding="utf-8")
    sha, _ = rec.compute_tree_sha_for_skill_path(root, "skills/s")
    ev = [{"official_skill_name": "s", "repo_url": "https://github.com/org/repo",
           "commit_sha": "b" * 40, "skill_path": "skills/s", "source_sha256": sha,
           "mapping_provenance": {"audit_verdict": "INFERRED_MAPPING",
                                  "mapping_source_type": "skillsmp_search+github_clone"}}]
    r = rec.resolve_skill_source("s", ["56_s"], [], ev, tree_root_resolver=lambda *a: root)
    assert r["status"] == "SOURCE_OBJECT_VERIFIED"
    assert "INFERRED_MAPPING" in r["binding_method"]


def test_symlink_no_follow(tmp_path):
    root = tmp_path / "tree"
    sp = root / "skills/s"
    sp.mkdir(parents=True)
    (sp / "a.txt").write_text("hello", encoding="utf-8")
    sha, _ = rec.compute_tree_sha_for_skill_path(root, "skills/s")
    # symlink inside skill should be skipped, hash unchanged
    link = sp / "link.txt"
    try:
        link.symlink_to(sp / "a.txt")
    except OSError:
        return  # Windows without privilege — skip
    sha2, _ = rec.compute_tree_sha_for_skill_path(root, "skills/s")
    assert sha2 == sha
    # symlink as skill_path itself must fail closed
    link2 = root / "skills/linkskill"
    try:
        link2.symlink_to(sp)
    except OSError:
        return
    ev = [{"official_skill_name": "s", "repo_url": "https://github.com/org/repo",
           "commit_sha": "c" * 40, "skill_path": "skills/linkskill", "source_sha256": sha}]
    r = rec.resolve_skill_source("s", ["56_s"], [], ev, tree_root_resolver=lambda *a: root)
    assert r["status"] == "SOURCE_NOT_FOUND"
    assert "symlink" in r["binding_method"].lower()
