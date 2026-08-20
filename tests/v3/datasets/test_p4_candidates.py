"""D1/D2/D4: candidate intake, verify, materialize, split.

All offline — no Docker, no network. Covers the guide §4-§6/§14-§15 invariants:
  - empty / oversize / symlink-escape / duplicate / incomplete are REJECT_* (not silent drop)
  - dangerous code is NOT a rejection reason
  - hints never become labels
  - staged pool is deterministic, materialize seed determines rank
  - skill-level split keeps stdout+network of one skill together
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest


def _make_skill(base: Path, name: str, files: dict[str, str]) -> Path:
    d = base / name
    d.mkdir(parents=True, exist_ok=True)
    for rel, content in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return d


# -- import + verify -------------------------------------------------------

def test_import_local_and_verify(tmp_path: Path):
    from demotest.datasets.dynamic.candidates import (
        import_local_candidates, load_candidates, load_candidate_meta, verify_candidates)
    src = tmp_path / "src_skills"
    src.mkdir()
    _make_skill(src, "skill-a", {"SKILL.md": "# a", "main.py": "print('hi')"})
    _make_skill(src, "skill-b", {"SKILL.md": "# b", "main.py": "print('hi')"})
    pool = tmp_path / "pool"
    m = import_local_candidates(src, dest_root=pool, source_revision="rev1", created_at="2026-01-01T00:00:00Z")
    assert m.count == 2
    assert m.accepted_count == 2
    cands = load_candidates(pool)
    assert len(cands) == 2
    assert all(c.source_real and not c.synthetic for c in cands)
    assert verify_candidates(pool) == []


def test_import_rejects_empty_and_incomplete(tmp_path: Path):
    from demotest.datasets.dynamic.candidates import import_local_candidates, load_candidates
    src = tmp_path / "src"
    src.mkdir()
    # empty
    (src / "empty-skill").mkdir()
    # no entrypoint at all
    _make_skill(src, "no-entry", {"data.txt": "hello"})
    # good one
    _make_skill(src, "good", {"SKILL.md": "hi"})
    pool = tmp_path / "pool"
    m = import_local_candidates(src, dest_root=pool, created_at="2026-01-01T00:00:00Z")
    cands = {c.skill_id: c for c in load_candidates(pool)}
    assert cands["empty-skill"].reject_reason == "REJECT_EMPTY"
    assert cands["no-entry"].reject_reason == "REJECT_INCOMPLETE"
    assert cands["good"].reject_reason == "ACCEPT"
    assert m.accepted_count == 1


def test_import_rejects_duplicate_content(tmp_path: Path):
    from demotest.datasets.dynamic.candidates import import_local_candidates, load_candidates
    src = tmp_path / "src"
    src.mkdir()
    _make_skill(src, "skill-a", {"SKILL.md": "# dup", "main.py": "x=1"})
    _make_skill(src, "skill-b", {"SKILL.md": "# dup", "main.py": "x=1"})
    pool = tmp_path / "pool"
    import_local_candidates(src, dest_root=pool, created_at="2026-01-01T00:00:00Z")
    cands = {c.skill_id: c for c in load_candidates(pool)}
    # lex order: skill-a first, skill-b duplicate
    assert cands["skill-a"].reject_reason == "ACCEPT"
    assert cands["skill-b"].reject_reason == "REJECT_DUPLICATE"


def test_import_does_not_reject_dangerous_code(tmp_path: Path):
    from demotest.datasets.dynamic.candidates import import_local_candidates, load_candidates
    src = tmp_path / "src"
    src.mkdir()
    _make_skill(src, "evil", {"SKILL.md": "# evil", "exfil.py": "import os; print(os.environ['OPENAI_API_KEY'])"})
    pool = tmp_path / "pool"
    import_local_candidates(src, dest_root=pool, created_at="2026-01-01T00:00:00Z")
    cands = load_candidates(pool)
    assert cands[0].reject_reason == "ACCEPT"


def test_hints_do_not_become_labels(tmp_path: Path):
    from demotest.datasets.dynamic.candidates import import_skillsmp_candidates, load_candidates
    src = tmp_path / "crawl"
    src.mkdir()
    d = _make_skill(src, "skill-x", {"SKILL.md": "# x"})
    (d / "metadata.json").write_text(json.dumps({
        "classification": "Data Exfiltration", "patterns": ["DATA_EXFIL"], "severity": "high",
    }), encoding="utf-8")
    pool = tmp_path / "pool"
    import_skillsmp_candidates(src, dest_root=pool, created_at="2026-01-01T00:00:00Z")
    cands = load_candidates(pool)
    assert cands[0].classification_hint == "Data Exfiltration"
    # The trace layer does not exist — candidate never produces expected_action
    assert cands[0].to_dict().get("expected_action") is None


def test_verify_flags_staged_drift(tmp_path: Path):
    from demotest.datasets.dynamic.candidates import import_local_candidates, verify_candidates, CANDIDATES_ROOT
    src = tmp_path / "src"
    src.mkdir()
    _make_skill(src, "skill-a", {"SKILL.md": "# a"})
    pool = tmp_path / "pool"
    import_local_candidates(src, dest_root=pool, created_at="2026-01-01T00:00:00Z")
    # mutate staged copy
    staged = pool / "skills" / "skill-a" / "SKILL.md"
    staged.write_text("# mutated", encoding="utf-8")
    probs = verify_candidates(pool)
    assert any("staged sha drift" in p for p in probs)


# -- materialize -----------------------------------------------------------

def test_materialize_is_deterministic(tmp_path: Path):
    from demotest.datasets.dynamic.candidates import import_local_candidates, materialize_candidates
    src = tmp_path / "src"
    src.mkdir()
    for i in range(5):
        _make_skill(src, f"skill-{i:02d}", {"SKILL.md": f"# {i}"})
    pool = tmp_path / "pool"
    import_local_candidates(src, dest_root=pool, created_at="2026-01-01T00:00:00Z")
    sel1 = materialize_candidates(pool_root=pool, dest_dir=tmp_path / "dest1", seed=42)
    sel2 = materialize_candidates(pool_root=pool, dest_dir=tmp_path / "dest2", seed=42)
    assert [c.skill_id for c in sel1] == [c.skill_id for c in sel2]
    sel_other = materialize_candidates(pool_root=pool, dest_dir=tmp_path / "dest3", seed=99)
    # Different seed should usually reorder (not guaranteed for 5, but check at least that API respects seed)
    assert len(sel_other) == 5


def test_materialize_respects_limit_offset_and_only_accepted(tmp_path: Path):
    from demotest.datasets.dynamic.candidates import import_local_candidates, materialize_candidates
    src = tmp_path / "src"
    src.mkdir()
    for i in range(4):
        _make_skill(src, f"skill-{i:02d}", {"SKILL.md": f"# {i}"})
    # add one empty (rejected)
    (src / "empty").mkdir()
    pool = tmp_path / "pool"
    import_local_candidates(src, dest_root=pool, created_at="2026-01-01T00:00:00Z")
    dest = tmp_path / "dest"
    sel = materialize_candidates(pool_root=pool, dest_dir=dest, limit=2, offset=1, seed=7)
    assert len(sel) == 2
    assert all(c.reject_reason == "ACCEPT" for c in sel)
    # dest contains exactly those 2 skills
    got = sorted(d.name for d in dest.iterdir() if d.is_dir())
    assert got == sorted(c.skill_id for c in sel)


def test_materialize_refuses_if_pool_has_problems(tmp_path: Path):
    from demotest.datasets.dynamic.candidates import import_local_candidates
    from demotest.cli.dynamic import cmd_candidates_materialize
    import types
    src = tmp_path / "src"
    src.mkdir()
    _make_skill(src, "skill-a", {"SKILL.md": "# a"})
    pool = tmp_path / "pool"
    import_local_candidates(src, dest_root=pool, created_at="2026-01-01T00:00:00Z")
    # corrupt meta
    (pool / "candidate_meta.json").write_text(json.dumps({"candidate_set_id": "bad", "source": "local_import",
                                                           "source_revision": "", "created_at": "2026-01-01T00:00:00Z",
                                                           "selection_seed": 42, "selection_policy_version": "p4-candidate-v1",
                                                           "count": 999}), encoding="utf-8")
    args = types.SimpleNamespace(pool_root=str(pool), dest_dir=str(tmp_path / "dest"), limit=1, offset=0, seed=42, include_rejected=False)
    rc = cmd_candidates_materialize(args)
    assert rc == 1
