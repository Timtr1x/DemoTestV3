"""source-bound-v1 credential bindings — schema, canary, wiring.

All offline — no Docker, no network. Covers the reviewer-mandated invariants:
  - sidecar is fail-closed: schema violations raise, never degrade to baseline
  - only CONFIRMED human-reviewed bindings; names must be real env-var names
    and must never collide with the official forged namespace
  - canaries are deterministic and pass the sandbox fake-only injection gate
  - bindings anchor to source_sha256; drift is reported, stale rows never projected
  - materialize → snapshot carries bindings; a tampered canary refuses the snapshot
  - collector merges binding canaries and labels rows with credential_profile
"""
from __future__ import annotations

import json
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


def _make_pool(tmp_path: Path) -> Path:
    from demotest.datasets.dynamic.candidates import import_local_candidates
    src = tmp_path / "src_skills"
    src.mkdir()
    _make_skill(src, "skill-a", {
        "SKILL.md": "# a",
        "main.py": "import os; print(os.environ.get('CRUN_API_KEY',''))",
    })
    pool = tmp_path / "pool"
    import_local_candidates(src, dest_root=pool, source_revision="rev1",
                            created_at="2026-01-01T00:00:00Z")
    return pool


def _bind(pool: Path, name: str = "CRUN_API_KEY"):
    from demotest.datasets.dynamic.credential_bindings import upsert_credential_binding
    return upsert_credential_binding(
        pool_root=pool,
        candidate_id="skill-a",
        credential_name=name,
        credential_kind="env_var",
        evidence_file="main.py",
        evidence="os.environ.get('CRUN_API_KEY')",
    )


# -- schema + canary --------------------------------------------------------

def test_canary_is_deterministic_and_fake_gate_compatible():
    from demotest.datasets.dynamic.credential_bindings import source_bound_canary
    from demotest.datasets.dynamic.sandbox import _is_fake_credential_value
    c1 = source_bound_canary("skill-a", "ab" * 32, "CRUN_API_KEY")
    c2 = source_bound_canary("skill-a", "ab" * 32, "CRUN_API_KEY")
    assert c1 == c2
    assert c1.startswith("leakbench-sourcebound-")
    assert _is_fake_credential_value(c1)
    # rotates with source bytes and with credential name
    assert c1 != source_bound_canary("skill-a", "cd" * 32, "CRUN_API_KEY")
    assert c1 != source_bound_canary("skill-a", "ab" * 32, "OTHER_TOKEN")


def test_schema_rejects_unconfirmed_and_wrong_profile():
    from demotest.datasets.dynamic.credential_bindings import (
        CredentialBinding, CredentialBindingError)
    base = dict(
        candidate_id="skill-a", source_sha256="ab" * 32,
        credential_name="CRUN_API_KEY", credential_kind="env_var",
        evidence_file="main.py", evidence="os.environ.get",
    )
    CredentialBinding.from_dict({**base, "review_status": "CONFIRMED",
                                 "profile": "source-bound-v1"})
    with pytest.raises(CredentialBindingError):
        CredentialBinding.from_dict({**base, "review_status": "PENDING",
                                     "profile": "source-bound-v1"})
    with pytest.raises(CredentialBindingError):
        CredentialBinding.from_dict({**base, "review_status": "CONFIRMED",
                                     "profile": "official-baseline"})
    with pytest.raises(CredentialBindingError):
        CredentialBinding.from_dict({k: v for k, v in base.items() if k != "evidence"})


def test_schema_rejects_bad_names_and_official_collisions():
    from demotest.datasets.dynamic.credential_bindings import (
        CredentialBinding, CredentialBindingError, OFFICIAL_FORGED_ENV_NAMES)
    base = dict(
        candidate_id="skill-a", source_sha256="ab" * 32,
        credential_kind="env_var", evidence_file="main.py", evidence="x",
        review_status="CONFIRMED", profile="source-bound-v1")
    for bad in ("crun_api_key", "CRUN-API-KEY", "1TOKEN", ""):
        with pytest.raises(CredentialBindingError):
            CredentialBinding.from_dict({**base, "credential_name": bad})
    for official in sorted(OFFICIAL_FORGED_ENV_NAMES):
        with pytest.raises(CredentialBindingError):
            CredentialBinding.from_dict({**base, "credential_name": official})


def test_loader_fail_closed_on_duplicates_and_bad_json(tmp_path: Path):
    from demotest.datasets.dynamic.credential_bindings import (
        CredentialBindingError, load_credential_bindings)
    pool = _make_pool(tmp_path)
    b = _bind(pool)
    p = pool / "credential_bindings" / "credential_bindings.jsonl"
    # duplicate (candidate_id, credential_name)
    p.write_text(json.dumps(b.to_dict()) + "\n" + json.dumps(b.to_dict()) + "\n",
                 encoding="utf-8")
    with pytest.raises(CredentialBindingError):
        load_credential_bindings(pool)
    # invalid JSON
    p.write_text("{not json}\n", encoding="utf-8")
    with pytest.raises(CredentialBindingError):
        load_credential_bindings(pool)
    # missing file is a legitimate empty sidecar
    p.unlink()
    assert load_credential_bindings(pool) == []


# -- upsert authority + drift -----------------------------------------------

def test_upsert_binds_current_source_sha_and_refuses_unknown(tmp_path: Path):
    from demotest.datasets.dynamic.candidates import load_candidates
    from demotest.datasets.dynamic.credential_bindings import (
        CredentialBindingError, load_credential_bindings, upsert_credential_binding)
    pool = _make_pool(tmp_path)
    cand = {c.candidate_id: c for c in load_candidates(pool)}["skill-a"]
    b = _bind(pool)
    assert b.source_sha256 == cand.source_sha256
    assert b.review_status == "CONFIRMED"
    assert b.profile == "source-bound-v1"
    assert load_credential_bindings(pool) == [b]
    with pytest.raises(CredentialBindingError):
        upsert_credential_binding(
            pool_root=pool, candidate_id="nope", credential_name="X_TOKEN",
            credential_kind="env_var", evidence_file="f", evidence="e")


def test_verify_reports_binding_source_drift(tmp_path: Path):
    from demotest.datasets.dynamic.candidates import (
        import_local_candidates, verify_candidates)
    pool = _make_pool(tmp_path)
    _bind(pool)
    assert verify_candidates(pool) == []
    # skill bytes change under the same candidate_id → binding is stale
    (tmp_path / "src_skills" / "skill-a" / "main.py").write_text(
        "import os; print(os.environ.get('CRUN_API_KEY',''))  # v2", encoding="utf-8")
    import_local_candidates(tmp_path / "src_skills", dest_root=pool,
                            source_revision="rev2", created_at="2026-01-02T00:00:00Z")
    problems = verify_candidates(pool)
    assert any("binding source drift" in p for p in problems)


def test_stale_binding_never_projected(tmp_path: Path):
    from demotest.datasets.dynamic.credential_bindings import (
        load_credential_bindings, materialization_bindings)
    pool = _make_pool(tmp_path)
    b = _bind(pool)
    bindings = load_credential_bindings(pool)
    assert materialization_bindings(bindings, "skill-a", b.source_sha256) == [
        {"credential_name": "CRUN_API_KEY", "credential_kind": "env_var",
         "canary": b.canary}]
    # a different revision gets nothing — stale rows are excluded, never carried
    assert materialization_bindings(bindings, "skill-a", "ff" * 32) == []


# -- materialize → snapshot wiring ------------------------------------------

def _materialize_with_binding(tmp_path: Path):
    from demotest.datasets.dynamic.candidates import (
        materialize_candidates, upsert_runtime_spec)
    pool = _make_pool(tmp_path)
    _bind(pool)
    upsert_runtime_spec(pool_root=pool, candidate_id="skill-a",
                        entry_command=("python", "/skills/main.py"))
    dest = tmp_path / "mat"
    materialize_candidates(pool_root=pool, dest_dir=dest,
                           require_runtime_ready=True)
    return pool, dest


def test_materialization_and_snapshot_carry_bindings(tmp_path: Path):
    from demotest.datasets.dynamic.snapshot import freeze_skill_snapshot, load_snapshot
    pool, dest = _materialize_with_binding(tmp_path)
    doc = json.loads((dest / "_p4_materialization.json").read_text(encoding="utf-8"))
    assert doc["credential_bindings_file_sha256"]
    proj = doc["skills"][0]["credential_bindings"]
    assert len(proj) == 1 and proj[0]["credential_name"] == "CRUN_API_KEY"
    assert proj[0]["canary"].startswith("leakbench-sourcebound-")

    snap_root = tmp_path / "snaps"
    m = freeze_skill_snapshot(dest, pipeline_revision="rev1", out_root=snap_root,
                              created_at="2026-01-01T00:00:00Z")
    entry = m.skills[0]
    assert entry.credential_bindings[0]["credential_name"] == "CRUN_API_KEY"
    assert m.candidate_provenance["credential_bindings_file_sha256"] == \
        doc["credential_bindings_file_sha256"]
    # round-trip through snapshot.json
    loaded = load_snapshot(m.snapshot_id, root=snap_root)
    assert loaded.skills[0].credential_bindings[0]["canary"] == proj[0]["canary"]


def test_snapshot_refuses_tampered_binding_canary(tmp_path: Path):
    from demotest.datasets.dynamic.snapshot import freeze_skill_snapshot
    pool, dest = _materialize_with_binding(tmp_path)
    doc = json.loads((dest / "_p4_materialization.json").read_text(encoding="utf-8"))
    doc["skills"][0]["credential_bindings"][0]["canary"] = "leakbench-sourcebound-tampered00-000000000000"
    (dest / "_p4_materialization.json").write_text(
        json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="canary mismatch"):
        freeze_skill_snapshot(dest, pipeline_revision="rev1",
                              out_root=tmp_path / "snaps")


# -- collector injection -----------------------------------------------------

class _StubRunner:
    """Offline runner double: records injected credentials, emits stdout."""

    pipeline_revision = "rev-test"
    isolation_level = "stub"
    pipeline_root = ""  # unused — collector's marker provider is overridden

    def __init__(self, stdout: str = "") -> None:
        self.stdout = stdout
        self.seen_credentials: dict[str, str] = {}

    def run_skill(self, *, skill_id, skill_dir, skill_snapshot_sha256, credentials,
                  condition, declared_providers, command, work_root):
        from demotest.datasets.dynamic.schemas import DynamicExecutionRecord
        self.seen_credentials = dict(credentials)
        return DynamicExecutionRecord(
            execution_id=f"exec-{skill_id}",
            skill_id=skill_id,
            skill_snapshot_sha256=skill_snapshot_sha256,
            condition=condition,
            execution_mode="deterministic",
            sandbox_provider="SkillLeakBench",
            pipeline_revision=self.pipeline_revision,
            sandbox_image_digest="sha256:stub",
            outcome="SUCCESS_NO_SECRET_FLOW",
            exit_code=0,
            stdout_text=self.stdout,
        )

    def image_digest(self) -> str:
        return "sha256:stub"

    def resource_profile(self) -> dict:
        return {"stub": True}


class _StubCollector:
    pass


def test_collector_injects_source_bound_canaries(tmp_path: Path):
    from demotest.datasets.dynamic.skillleak_collector import DynamicTraceCollector
    from demotest.datasets.dynamic.snapshot import freeze_skill_snapshot
    from demotest.datasets.dynamic.markers import TestSecretMarkerProvider

    pool, dest = _materialize_with_binding(tmp_path)
    snap_root = tmp_path / "snaps"
    m = freeze_skill_snapshot(dest, pipeline_revision="rev-test", out_root=snap_root,
                              created_at="2026-01-01T00:00:00Z")
    canary = m.skills[0].credential_bindings[0]["canary"]
    runner = _StubRunner(stdout=f"key={canary}\n")
    collector = DynamicTraceCollector(
        runner=runner, raw_dir=tmp_path / "raw", snapshots_root=snap_root,
        metadata_root=tmp_path / "meta")
    # offline: replace the pinned-pipeline marker provider with the legacy stub
    collector._marker_provider = lambda: TestSecretMarkerProvider("rev-test")  # type: ignore[method-assign]

    report = collector.collect(snapshot_id=m.snapshot_id, offset=0, limit=5)
    assert report.n_executions == 1
    # official TEST_SECRET canaries + the source-bound canary were injected
    assert runner.seen_credentials.get("CRUN_API_KEY") == canary
    # canary observed on stdout → exactly one STDOUT trace
    assert report.n_traces == 1
    assert report.n_stdout_block == 1
    # layered profile labels
    execs = [json.loads(l) for l in (tmp_path / "raw" / "executions.jsonl")
             .read_text(encoding="utf-8").splitlines() if l.strip()]
    assert execs[0]["metadata"]["credential_profile"] == "source-bound-v1"
    assert execs[0]["metadata"]["bound_credential_names"] == ["CRUN_API_KEY"]
    meta = json.loads((tmp_path / "raw" / "trace_meta.json").read_text(encoding="utf-8"))
    assert meta["credential_profiles"] == ["source-bound-v1"]
    assert meta["credential_bindings_file_sha256"]


def test_collector_official_baseline_when_no_bindings(tmp_path: Path):
    from demotest.datasets.dynamic.candidates import (
        import_local_candidates, materialize_candidates, upsert_runtime_spec)
    from demotest.datasets.dynamic.skillleak_collector import DynamicTraceCollector
    from demotest.datasets.dynamic.snapshot import freeze_skill_snapshot
    from demotest.datasets.dynamic.markers import TestSecretMarkerProvider

    src = tmp_path / "src_skills"
    src.mkdir()
    _make_skill(src, "skill-plain", {"SKILL.md": "# p", "main.py": "print('ok')"})
    pool = tmp_path / "pool2"
    import_local_candidates(src, dest_root=pool, created_at="2026-01-01T00:00:00Z")
    upsert_runtime_spec(pool_root=pool, candidate_id="skill-plain",
                        entry_command=("python", "/skills/main.py"))
    dest = tmp_path / "mat2"
    materialize_candidates(pool_root=pool, dest_dir=dest, require_runtime_ready=True)
    snap_root = tmp_path / "snaps2"
    m = freeze_skill_snapshot(dest, pipeline_revision="rev-test", out_root=snap_root,
                              created_at="2026-01-01T00:00:00Z")
    assert m.skills[0].credential_bindings == ()
    runner = _StubRunner(stdout="nothing here\n")
    collector = DynamicTraceCollector(
        runner=runner, raw_dir=tmp_path / "raw2", snapshots_root=snap_root,
        metadata_root=tmp_path / "meta2")
    collector._marker_provider = lambda: TestSecretMarkerProvider("rev-test")  # type: ignore[method-assign]
    report = collector.collect(snapshot_id=m.snapshot_id, offset=0, limit=5)
    assert report.n_traces == 0
    execs = [json.loads(l) for l in (tmp_path / "raw2" / "executions.jsonl")
             .read_text(encoding="utf-8").splitlines() if l.strip()]
    assert execs[0]["metadata"]["credential_profile"] == "official-baseline"
