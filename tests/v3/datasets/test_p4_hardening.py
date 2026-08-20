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


# -- second-round hardening (execution identity / fail-closed collect) --------

def _mat_root(root: Path, skill_ids: list[str]) -> Path:
    """Materialized-style skills root (entry via runtime_spec, provenance attached)."""
    import hashlib as _hl
    skills_root = root / "skills"
    skills_doc = []
    for sid in skill_ids:
        d = skills_root / sid
        d.mkdir(parents=True)
        (d / "run.sh").write_text("#!/bin/sh\necho hi\n")
        skills_doc.append({
            "skill_id": sid,
            "candidate_id": f"cand-{sid}",
            "source_uri": f"https://skillsmp.test/skills/{sid}",
            "source_revision": "rev-test",
            "source_sha256": _hl.sha256(sid.encode()).hexdigest(),
            "runtime_spec": {
                "spec_version": "p4-runtime-v1",
                "entry_command": ["python", "/skills/run.sh"],
                "declared_providers": [],
            },
        })
    (skills_root / "_p4_materialization.json").write_text(json.dumps({
        "candidate_set_id": "p4-candidates-testset",
        "candidate_policy_version": "p4-candidate-v2",
        "seed": 42,
        "selection_sha256": _hl.sha256(b"test-selection").hexdigest(),
        "skills": skills_doc,
    }, indent=2, sort_keys=True), encoding="utf-8")
    return skills_root


def _stub_runner(rev: str):
    from demotest.datasets.dynamic.schemas import DynamicExecutionRecord

    class StubRunner:
        pipeline_revision = rev
        pipeline_root = Path("cache/datasets_v3/raw/skillleakbench_pipeline")

        def image_digest(self):
            return "sha256:stub-image"

        def resource_profile(self):
            return {"isolation_level": "docker_only_hardened", "concurrency": 1}

        def run_skill(self, *, skill_id, skill_dir, skill_snapshot_sha256, credentials,
                      condition="deterministic", declared_providers=(), command=None,
                      work_root=None, timeout_s=None):
            marker = next(iter(credentials.values()), "")
            return DynamicExecutionRecord(
                execution_id=f"exec-{skill_id}", skill_id=skill_id,
                skill_snapshot_sha256=skill_snapshot_sha256,
                condition=condition, execution_mode="deterministic",
                sandbox_provider="SkillLeakBench", pipeline_revision=self.pipeline_revision,
                sandbox_image_digest=self.image_digest(),
                outcome="SUCCESS_REACHED_SECRET_PATH", exit_code=0, timeout=False,
                stdout_text=f"leaked {marker}", stdout_artifact="", network_artifact="",
                network_events=(), credential_names=tuple(credentials), declared_providers=(),
            )

    return StubRunner()


def test_collect_refuses_missing_entry_command(tmp_path: Path):
    """Deterministic Core must fail closed — no silent bash fallback."""
    from demotest.datasets.dynamic.snapshot import freeze_skill_snapshot
    from demotest.datasets.dynamic.skillleak_collector import DynamicTraceCollector

    skills_root = tmp_path / "skills"
    (skills_root / "skill-a").mkdir(parents=True)
    (skills_root / "skill-a" / "run.sh").write_text("echo hi")
    manifest = freeze_skill_snapshot(skills_root, pipeline_revision="rev-gate",
                                     out_root=tmp_path / "snaps")
    meta = tmp_path / "meta"; meta.mkdir()
    collector = DynamicTraceCollector(runner=_stub_runner("rev-gate"), raw_dir=tmp_path / "raw",
                                      snapshots_root=tmp_path / "snaps", metadata_root=meta)
    with pytest.raises(RuntimeError, match="entry_command"):
        collector.collect(snapshot_id=manifest.snapshot_id)


def test_collect_refuses_missing_candidate_provenance(tmp_path: Path):
    """Entry command alone is not enough — snapshot must carry candidate_set_id."""
    from demotest.datasets.dynamic.snapshot import freeze_skill_snapshot
    from demotest.datasets.dynamic.skillleak_collector import DynamicTraceCollector

    skills_root = tmp_path / "skills"
    _skill(skills_root, "skill-a", {
        "run.sh": "echo hi",
        "demotest.skill.json": json.dumps({"entry_command": ["python", "/skills/run.sh"]}),
    })
    manifest = freeze_skill_snapshot(skills_root, pipeline_revision="rev-gate2",
                                     out_root=tmp_path / "snaps")
    meta = tmp_path / "meta"; meta.mkdir()
    collector = DynamicTraceCollector(runner=_stub_runner("rev-gate2"), raw_dir=tmp_path / "raw",
                                      snapshots_root=tmp_path / "snaps", metadata_root=meta)
    with pytest.raises(RuntimeError, match="candidate_set_id"):
        collector.collect(snapshot_id=manifest.snapshot_id)


def test_resume_refuses_candidate_set_drift(tmp_path: Path):
    """Resume against a different candidate set must be refused."""
    from demotest.datasets.dynamic.snapshot import freeze_skill_snapshot
    from demotest.datasets.dynamic.skillleak_collector import DynamicTraceCollector

    skills_root = _mat_root(tmp_path, ["skill-a"])
    manifest = freeze_skill_snapshot(skills_root, pipeline_revision="rev-drift",
                                     out_root=tmp_path / "snaps")
    raw = tmp_path / "raw"
    meta = tmp_path / "meta"; meta.mkdir()
    DynamicTraceCollector(runner=_stub_runner("rev-drift"), raw_dir=raw,
                          snapshots_root=tmp_path / "snaps", metadata_root=meta,
                          ).collect(snapshot_id=manifest.snapshot_id, limit=1)
    # Tamper: pretend the previous batch belonged to another candidate set
    meta_path = raw / "trace_meta.json"
    doc = json.loads(meta_path.read_text(encoding="utf-8"))
    doc["candidate_provenance"]["candidate_set_id"] = "p4-candidates-OTHER"
    meta_path.write_text(json.dumps(doc, indent=2, sort_keys=True), encoding="utf-8")
    with pytest.raises(RuntimeError, match="candidate_set_id changed"):
        DynamicTraceCollector(runner=_stub_runner("rev-drift"), raw_dir=raw,
                              snapshots_root=tmp_path / "snaps", metadata_root=meta,
                              ).collect(snapshot_id=manifest.snapshot_id, limit=1)


def test_external_runtime_spec_sidecar_keeps_skill_bytes_clean(tmp_path: Path):
    from demotest.datasets.dynamic.candidates import (
        import_local_candidates, load_candidates, load_runtime_specs,
        runtime_specs_sha256, upsert_runtime_spec,
    )
    src = tmp_path / "src"
    _skill(src, "agent", {"SKILL.md": "# a", "main.py": "print(1)"})
    pool = tmp_path / "pool"
    import_local_candidates(src, dest_root=pool, created_at="2026-01-01T00:00:00Z")
    cand = {c.skill_id: c for c in load_candidates(pool)}["agent"]
    assert cand.runtime_status == "AGENT_REQUIRED"
    staged = pool / cand.local_path
    before = {p.relative_to(staged).as_posix(): p.read_bytes()
              for p in sorted(staged.rglob("*")) if p.is_file()}
    upsert_runtime_spec(pool_root=pool, candidate_id="agent",
                        entry_command=("python", "/skills/main.py"),
                        declared_providers=("api.openai.com",))
    after = {p.relative_to(staged).as_posix(): p.read_bytes()
             for p in sorted(staged.rglob("*")) if p.is_file()}
    assert before == after  # staged Skill bytes untouched
    specs = load_runtime_specs(pool)
    assert specs["agent"]["entry_command"] == ["python", "/skills/main.py"]
    assert specs["agent"]["spec_version"] == "p4-runtime-v1"
    assert runtime_specs_sha256(pool)
    cand2 = {c.skill_id: c for c in load_candidates(pool)}["agent"]
    assert cand2.runtime_status == "RUNTIME_READY"
    assert cand2.entry_command == ("python", "/skills/main.py")
    assert cand2.declared_providers == ("api.openai.com",)
    assert cand2.execution_spec_source.endswith("runtime_specs.jsonl")


def test_skillsmp_import_consumes_skills_metadata(tmp_path: Path):
    from demotest.datasets.dynamic.candidates import import_skillsmp_candidates, load_candidates
    crawl = tmp_path / "crawl"
    _skill(crawl, "skill-1", {"SKILL.md": "# s", "main.py": "print(1)"})
    (crawl / "skills_metadata.json").write_text(json.dumps([{
        "skill_id": "skill-1",
        "skill_name": "Cool Skill",
        "repo_url": "https://github.com/acme/skills",
        "branch": "main",
        "skill_subdir": "skills/skill-1",
        "skill_url": "https://skillsmp.example/skills/skill-1",
        "updated_at": "2026-01-01T00:00:00Z",
    }]), encoding="utf-8")
    pool = tmp_path / "pool"
    import_skillsmp_candidates(crawl, dest_root=pool, created_at="2026-01-01T00:00:00Z")
    c = {c.skill_id: c for c in load_candidates(pool)}["skill-1"]
    assert c.source_uri == "https://skillsmp.example/skills/skill-1"
    assert c.source_revision == "main"
    assert c.skill_name == "Cool Skill"
    assert c.source_type == "skillsmp"


def test_review_empty_marker_fails_closed():
    from demotest.datasets.dynamic.review import TraceReview, validate_review
    from demotest.datasets.traces.models import CredentialTrace
    tr = CredentialTrace(trace_id="t1", skill_id="sk", skill_name="sk", issue_id="OPENAI_API_KEY",
                         academic_code="DYNAMIC", pattern="CREDENTIAL_FLOW", classification="Information Exposure", severity="high",
                         sink="stdout", gateway_channel="TOOL_RESULT", gateway_visibility="DIRECT",
                         flow_class="STDOUT_EXPOSURE", credential_marker="",
                         payload="nothing here", trace_hash="sha256:abc",
                         dynamic_confirmed=True, evidence_type="DYNAMIC_TRACE")
    r = TraceReview(trace_id="t1", review_status="ACCEPTED",
                    source_real=True, dynamic_execution_real=True, fake_credential_confirmed=True,
                    marker_observed=True, sink_confirmed=True, gateway_projection_valid=True,
                    expected_action_valid=True)
    probs = validate_review(r, tr)
    assert any("empty credential_marker" in p for p in probs)


def test_python_shim_does_not_mutate_pinned_dockerfile():
    """Shim lives only in the temp build context — pinned checkout stays clean."""
    df = Path("cache/datasets_v3/raw/skillleakbench_pipeline/code/phase3_dynamic/Dockerfile")
    if not df.exists():
        pytest.skip("pinned pipeline checkout not present")
    text = df.read_text(encoding="utf-8")
    assert "DemoTest shim" not in text
    assert "ln -sf /usr/bin/python3 /usr/local/bin/python" not in text
