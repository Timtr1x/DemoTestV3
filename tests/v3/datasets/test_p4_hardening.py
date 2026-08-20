"""P0 hardening regression — candidates preflight, runtime eligibility, review fail-closed.

Offline only — no Docker.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest


def _skill(base: Path, name: str, files: dict[str, str]) -> Path:
    d = base / name
    d.mkdir(parents=True, exist_ok=True)
    for rel, c in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(c, encoding="utf-8")
    return d


def test_symlink_is_rejected_before_read_and_not_staged(tmp_path: Path):
    from demotest.datasets.dynamic.candidates import import_local_candidates, load_candidates
    src = tmp_path / "src"
    src.mkdir()
    # Good skill with explicit entry
    _skill(src, "good", {"SKILL.md": "# good", "main.py": "print('hi')",
                         "demotest.skill.json": json.dumps({"entry_command": ["python", "/skills/main.py"]})})
    # Bad skill with symlink
    bad = src / "bad-link"
    bad.mkdir()
    (bad / "SKILL.md").write_text("# bad", encoding="utf-8")
    # Create a symlink inside bad (point nowhere valid)
    try:
        (bad / "link").symlink_to(tmp_path / "secret.txt")
        (tmp_path / "secret.txt").write_text("host secret", encoding="utf-8")
        has_link = True
    except Exception:
        pytest.skip("symlink not supported on this FS")
        has_link = False
    pool = tmp_path / "pool"
    import_local_candidates(src, dest_root=pool, created_at="2026-01-01T00:00:00Z")
    cands = {c.skill_id: c for c in load_candidates(pool)}
    assert cands["bad-link"].reject_reason in ("REJECT_SYMLINK_ESCAPE", "REJECT_SYMLINK")
    # Must not be staged
    staged_bad = pool / (cands["bad-link"].local_path) if cands["bad-link"].local_path else None
    assert staged_bad is None or not staged_bad.exists()
    # Good still accepted
    assert cands["good"].reject_reason == "ACCEPT"


def test_runtime_eligibility_explicit_entry(tmp_path: Path):
    from demotest.datasets.dynamic.candidates import import_local_candidates, load_candidates
    src = tmp_path / "src"
    src.mkdir()
    # With entry_command -> RUNTIME_READY
    _skill(src, "ready", {"SKILL.md": "# ready",
                          "run.py": "print(1)",
                          "demotest.skill.json": json.dumps({"entry_command": ["python", "/skills/run.py"]})})
    # Without entry -> AGENT_REQUIRED, still ACCEPT source
    _skill(src, "agent-only", {"SKILL.md": "# agent", "helper.py": "x=1"})
    pool = tmp_path / "pool"
    import_local_candidates(src, dest_root=pool, created_at="2026-01-01T00:00:00Z")
    cands = {c.skill_id: c for c in load_candidates(pool)}
    assert cands["ready"].runtime_status == "RUNTIME_READY" and cands["ready"].runtime_eligible is True
    assert cands["agent-only"].runtime_status == "AGENT_REQUIRED" and cands["agent-only"].runtime_eligible is False
    assert cands["agent-only"].reject_reason == "ACCEPT"


def test_materialize_require_runtime_ready_filters(tmp_path: Path):
    from demotest.datasets.dynamic.candidates import import_local_candidates, materialize_candidates
    src = tmp_path / "src"
    src.mkdir()
    _skill(src, "ready", {"SKILL.md": "# ready", "demotest.skill.json": json.dumps({"entry_command": ["python", "/skills/run.py"]}), "run.py": "print(1)"})
    _skill(src, "agent", {"SKILL.md": "# agent", "main.py": "print(1)"})
    pool = tmp_path / "pool"
    import_local_candidates(src, dest_root=pool, created_at="2026-01-01T00:00:00Z")
    sel = materialize_candidates(pool_root=pool, dest_dir=tmp_path / "dest", require_runtime_ready=True)
    assert [c.skill_id for c in sel] == ["ready"]


def test_materialize_dest_hygiene(tmp_path: Path):
    from demotest.datasets.dynamic.candidates import import_local_candidates, materialize_candidates
    src = tmp_path / "src"
    src.mkdir()
    _skill(src, "a", {"SKILL.md": "# a", "demotest.skill.json": json.dumps({"entry_command": ["python", "/skills/run.py"]}), "run.py": "print(1)"})
    pool = tmp_path / "pool"
    import_local_candidates(src, dest_root=pool, created_at="2026-01-01T00:00:00Z")
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "stale-skill").mkdir()
    (dest / "stale-skill" / "old.txt").write_text("old", encoding="utf-8")
    # Without clean-dest -> refuse
    with pytest.raises(RuntimeError, match="not empty"):
        materialize_candidates(pool_root=pool, dest_dir=dest, clean_dest=False)
    # With clean-dest -> clears stale
    sel = materialize_candidates(pool_root=pool, dest_dir=dest, clean_dest=True)
    assert not (dest / "stale-skill").exists()
    assert len(sel) == 1


def test_materialization_manifest_written(tmp_path: Path):
    from demotest.datasets.dynamic.candidates import import_local_candidates, materialize_candidates
    import json as _j
    src = tmp_path / "src"
    src.mkdir()
    _skill(src, "a", {"SKILL.md": "# a", "demotest.skill.json": _j.dumps({"entry_command": ["python", "/skills/run.py"]}), "run.py": "print(1)"})
    pool = tmp_path / "pool"
    import_local_candidates(src, dest_root=pool, created_at="2026-01-01T00:00:00Z")
    dest = tmp_path / "dest"
    materialize_candidates(pool_root=pool, dest_dir=dest, seed=42)
    assert (dest / "_p4_materialization.json").exists()
    doc = _j.loads((dest / "_p4_materialization.json").read_text(encoding="utf-8"))
    assert doc["candidate_set_id"].startswith("p4-candidates-")
    assert doc["selected_count"] == 1


def test_snapshot_binds_materialization_provenance(tmp_path: Path):
    from demotest.datasets.dynamic.candidates import import_local_candidates, materialize_candidates
    from demotest.datasets.dynamic.snapshot import freeze_skill_snapshot, load_snapshot
    import json as _j
    src = tmp_path / "src"
    src.mkdir()
    _skill(src, "a", {"SKILL.md": "# a", "demotest.skill.json": _j.dumps({"entry_command": ["python", "/skills/run.py"]}), "run.py": "print(1)"})
    pool = tmp_path / "pool"
    import_local_candidates(src, dest_root=pool, created_at="2026-01-01T00:00:00Z", source_revision="rev-123")
    dest = tmp_path / "mat"
    materialize_candidates(pool_root=pool, dest_dir=dest, seed=42)
    snap_pool = tmp_path / "snaps"
    m = freeze_skill_snapshot(dest, pipeline_revision="pipe-rev", out_root=snap_pool)
    loaded = load_snapshot(m.snapshot_id, root=snap_pool)
    assert loaded.candidate_provenance.get("candidate_set_id", "").startswith("p4-candidates-")
    assert loaded.skills[0].source_sha256  # carried
    assert loaded.skills[0].entry_command == ("python", "/skills/run.py")


def test_review_fail_closed_defaults():
    from demotest.datasets.dynamic.review import TraceReview, validate_review
    from demotest.datasets.traces.models import CredentialTrace
    tr = CredentialTrace(trace_id="t1", skill_id="sk", skill_name="sk", issue_id="OPENAI_API_KEY",
                         academic_code="DYNAMIC", pattern="CREDENTIAL_FLOW", classification="Information Exposure", severity="high",
                         sink="stdout", gateway_channel="TOOL_RESULT", gateway_visibility="DIRECT",
                         flow_class="STDOUT_EXPOSURE", credential_marker="TEST_SECRET_AAAAAAAAAAAAAAAA",
                         payload="hi TEST_SECRET_AAAAAAAAAAAAAAAA", trace_hash="sha256:abc",
                         dynamic_confirmed=True, evidence_type="DYNAMIC_TRACE")
    # Default export is NEEDS_REVIEW + all gates False -> ACCEPTED must fail
    bad = TraceReview(trace_id="t1", review_status="ACCEPTED")
    probs = validate_review(bad, tr)
    assert any("source_real" in p for p in probs)
    # Explicitly set all gates True -> passes
    good = TraceReview(trace_id="t1", review_status="ACCEPTED",
                       source_real=True, dynamic_execution_real=True, fake_credential_confirmed=True,
                       marker_observed=True, sink_confirmed=True, gateway_projection_valid=True,
                       expected_action_valid=True)
    assert validate_review(good, tr) == []


def test_review_flow_semantics_allow_requires_evidence():
    from demotest.datasets.dynamic.review import TraceReview, validate_review
    from demotest.datasets.traces.models import CredentialTrace
    # AUTHORIZED flow without authorized_sink -> fail
    tr = CredentialTrace(trace_id="t1", skill_id="sk", skill_name="sk", issue_id="OPENAI_API_KEY",
                         academic_code="DYNAMIC", pattern="CREDENTIAL_FLOW", classification="Information Exposure", severity="high",
                         sink="network", gateway_channel="TOOL_CALL", gateway_visibility="PROJECTED",
                         flow_class="AUTHORIZED_SECRET_USE", credential_marker="TEST_SECRET_AAAAAAAAAAAAAAAA",
                         payload="hi TEST_SECRET_AAAAAAAAAAAAAAAA", trace_hash="sha256:abc",
                         dynamic_confirmed=True, evidence_type="DYNAMIC_TRACE", metadata={})
    good_gates = dict(source_real=True, dynamic_execution_real=True, fake_credential_confirmed=True,
                      marker_observed=True, sink_confirmed=True, gateway_projection_valid=True,
                      expected_action_valid=True)
    bad = TraceReview(trace_id="t1", review_status="ACCEPTED", **good_gates)
    probs = validate_review(bad, tr)
    assert any("authorized_sink" in p for p in probs)
    # With evidence -> ok
    tr2 = CredentialTrace(trace_id="t1", skill_id="sk", skill_name="sk", issue_id="OPENAI_API_KEY",
                          academic_code="DYNAMIC", pattern="CREDENTIAL_FLOW", classification="Information Exposure", severity="high",
                          sink="network", gateway_channel="TOOL_CALL", gateway_visibility="PROJECTED",
                          flow_class="AUTHORIZED_SECRET_USE", credential_marker="TEST_SECRET_AAAAAAAAAAAAAAAA",
                          payload="hi TEST_SECRET_AAAAAAAAAAAAAAAA", trace_hash="sha256:abc",
                          dynamic_confirmed=True, evidence_type="DYNAMIC_TRACE",
                          metadata={"authorized_sink": True})
    assert validate_review(bad, tr2) == []


def test_review_stdout_marker_mismatch_fails():
    from demotest.datasets.dynamic.review import TraceReview, validate_review
    from demotest.datasets.traces.models import CredentialTrace
    tr = CredentialTrace(trace_id="t1", skill_id="sk", skill_name="sk", issue_id="OPENAI_API_KEY",
                         academic_code="DYNAMIC", pattern="CREDENTIAL_FLOW", classification="Information Exposure", severity="high",
                         sink="stdout", gateway_channel="TOOL_RESULT", gateway_visibility="DIRECT",
                         flow_class="STDOUT_EXPOSURE", credential_marker="TEST_SECRET_AAAAAAAAAAAAAAAA",
                         payload="no marker here", trace_hash="sha256:abc",
                         dynamic_confirmed=True, evidence_type="DYNAMIC_TRACE")
    bad = TraceReview(trace_id="t1", review_status="ACCEPTED",
                      source_real=True, dynamic_execution_real=True, fake_credential_confirmed=True,
                      marker_observed=True, sink_confirmed=True, gateway_projection_valid=True,
                      expected_action_valid=True)
    probs = validate_review(bad, tr)
    assert any("marker not in payload" in p for p in probs)
