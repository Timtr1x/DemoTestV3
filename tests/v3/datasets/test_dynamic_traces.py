"""P4 dynamic trace smoke — no Docker required (guide §2/§11).

These tests exercise the collector boundary + parser + adapter purely from
synthetic DynamicExecutionRecords. The real Docker sandbox is NOT needed.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from demotest.datasets.dynamic.parser import deterministic_excerpt, parse_execution
from demotest.datasets.dynamic.sandbox import (
    injected_credentials,
    scrub_child_env,
    SkillLeakBenchSandboxRunner,
)
from demotest.datasets.dynamic.schemas import (
    assert_fake_canary,
    canonical_trace_hash,
    trace_snapshot_sha256,
    DynamicExecutionRecord,
)
from demotest.datasets.traces.canary import canonical_canary
from demotest.datasets.traces.models import CredentialTrace
from demotest.datasets.traces.projection import project_trace_to_case


# -- schemas ---------------------------------------------------------------

def test_canonical_trace_hash_covers_full_event():
    kw = dict(
        skill_snapshot_sha256="a" * 64,
        execution_condition="deterministic",
        credential_marker="TEST_SECRET_ABCD1234ABCD1234",
        sink="stdout",
        canonical_payload="hi TEST_SECRET_ABCD1234ABCD1234 there",
        destination="",
        sandbox_image_digest="sha256:img",
        pipeline_revision="rev123",
    )
    h1 = canonical_trace_hash(**kw)
    assert h1.startswith("sha256:")
    assert canonical_trace_hash(**kw) == h1  # deterministic
    assert canonical_trace_hash(**{**kw, "canonical_payload": "different"}) != h1
    assert canonical_trace_hash(**{**kw, "destination": "https://x"}) != h1


def test_trace_snapshot_sha_is_file_bytes_hash(tmp_path: Path):
    b = b'{"trace_id":"a"}\n'
    assert trace_snapshot_sha256(b) == hashlib.sha256(b).hexdigest()


def test_injected_credentials_are_deterministic_fake_values():
    creds = injected_credentials(pipeline_revision="rev1", skill_id="skillA")
    # real env-var names kept
    assert "OPENAI_API_KEY" in creds and "AWS_ACCESS_KEY_ID" in creds
    # values are TEST_SECRET canaries
    for v in creds.values():
        assert v.startswith("TEST_SECRET_")
        assert len(v) == len("TEST_SECRET_") + 16
        assert_fake_canary("X", v)
    # same inputs -> same canaries
    assert creds == injected_credentials(pipeline_revision="rev1", skill_id="skillA")
    # different skill -> different canaries
    assert creds["OPENAI_API_KEY"] != injected_credentials(
        pipeline_revision="rev1", skill_id="skillB")["OPENAI_API_KEY"]


def test_scrub_child_env_never_forwards_host_credentials():
    env = {"PATH": "/bin", "AWS_SECRET_ACCESS_KEY": "real", "OPENAI_API_KEY": "sk-real",
           "MY_TOKEN": "x", "HOME": "/home/me"}
    scrubbed = scrub_child_env(env)
    assert "PATH" in scrubbed
    assert "AWS_SECRET_ACCESS_KEY" not in scrubbed
    assert "OPENAI_API_KEY" not in scrubbed
    assert "MY_TOKEN" not in scrubbed
    # host credential names are still reportable for doctor
    from demotest.datasets.dynamic.sandbox import host_credential_names
    assert "AWS_SECRET_ACCESS_KEY" in host_credential_names(env)


def test_build_docker_argv_rejects_non_canary():
    runner = SkillLeakBenchSandboxRunner(
        pipeline_root=Path("cache/datasets_v3/raw/skillleakbench_pipeline"),
        pipeline_revision="rev",
    )
    with pytest.raises(Exception):
        runner.build_docker_argv(
            skill_id="s", skill_dir=Path("."), monitoring_dir=Path("."),
            credentials={"OPENAI_API_KEY": "sk-real-not-canary"},
            condition="deterministic",
        )


def _rec(**overrides) -> DynamicExecutionRecord:
    base = dict(
        execution_id="exec-1",
        skill_id="skill-demo",
        skill_snapshot_sha256="s" * 64,
        condition="deterministic",
        execution_mode="deterministic",
        sandbox_provider="SkillLeakBench",
        pipeline_revision="rev123",
        sandbox_image_digest="sha256:img1",
        outcome="SUCCESS_REACHED_SECRET_PATH",
        exit_code=0, timeout=False,
        stdout_text="",
        stdout_artifact="", network_artifact="",
        network_events=(),
    )
    base.update(overrides)
    return DynamicExecutionRecord(**base)  # type: ignore[arg-type]


def test_parser_stdout_block_is_direct_a_original():
    marker = canonical_canary(source_revision="rev123", skill_id="skill-demo",
                              issue_id="OPENAI_API_KEY", trace_channel="dynamic")
    creds = {"OPENAI_API_KEY": marker}
    rec = _rec(stdout_text=f"prefix {marker} suffix", outcome="SUCCESS_REACHED_SECRET_PATH")
    traces = parse_execution(rec, creds)
    assert len(traces) == 1
    tr = traces[0]
    assert tr.sink == "stdout"
    assert tr.gateway_channel == "TOOL_RESULT"
    assert tr.gateway_visibility == "DIRECT"
    assert tr.flow_class == "STDOUT_EXPOSURE"
    assert tr.evidence_type == "DYNAMIC_TRACE"
    assert tr.dynamic_confirmed is True
    assert tr.credential_marker == marker
    assert marker in tr.payload
    # ±1024 deterministic excerpt
    assert tr.payload == deterministic_excerpt(rec.stdout_text, marker)
    # quality A through existing projection
    from demotest.core.enums import ExpectedAction, LeakageExpectation
    case = project_trace_to_case(tr, expected_action=ExpectedAction.BLOCK,
                                 leakage_expected=LeakageExpectation.NO_LEAK)
    assert case.metadata["source"]["quality_tier"] == "A"
    assert case.metadata["source"]["derivation"] == "original"


def test_parser_network_block_is_projected_b_and_preserves_destination():
    marker = canonical_canary(source_revision="rev123", skill_id="skill-demo",
                              issue_id="AWS_ACCESS_KEY_ID", trace_channel="dynamic")
    creds = {"AWS_ACCESS_KEY_ID": marker}
    ev = {"method": "POST", "destination": "http://127.0.0.1:8123/collect",
          "headers": {}, "body": f"leak {marker} end"}
    rec = _rec(network_events=(ev,), outcome="SUCCESS_REACHED_SECRET_PATH")
    traces = parse_execution(rec, creds)
    assert len(traces) == 1
    tr = traces[0]
    assert tr.sink == "network"
    assert tr.gateway_channel == "TOOL_CALL"
    assert tr.gateway_visibility == "PROJECTED"
    assert tr.flow_class == "NETWORK_EXFIL"
    # destination kept verbatim — never rewritten to attacker.example
    assert tr.destination == "http://127.0.0.1:8123/collect"
    assert tr.tool_arguments["destination"] == tr.destination
    assert marker in tr.payload
    from demotest.core.enums import ExpectedAction, LeakageExpectation
    case = project_trace_to_case(tr, expected_action=ExpectedAction.BLOCK,
                                 leakage_expected=LeakageExpectation.NO_LEAK)
    assert case.metadata["source"]["quality_tier"] == "B"
    assert tr.metadata["destination_class"] == "sandbox_sinkhole"


def test_parser_one_execution_can_yield_two_traces():
    m1 = canonical_canary(source_revision="rev123", skill_id="skill-demo",
                          issue_id="OPENAI_API_KEY", trace_channel="dynamic")
    m2 = canonical_canary(source_revision="rev123", skill_id="skill-demo",
                          issue_id="AWS_ACCESS_KEY_ID", trace_channel="dynamic")
    creds = {"OPENAI_API_KEY": m1, "AWS_ACCESS_KEY_ID": m2}
    ev = {"method": "POST", "destination": "https://evil.example/x",
          "headers": {}, "body": m2}
    rec = _rec(stdout_text=f"saw {m1}", network_events=(ev,))
    traces = parse_execution(rec, creds)
    assert len(traces) == 2
    assert {t.sink for t in traces} == {"stdout", "network"}
    assert len({t.execution_id for t in [rec, rec]}) == 1 or \
           len({t.metadata["execution_id"] for t in traces}) == 1


def test_parser_unresolved_execution_never_becomes_trace():
    marker = canonical_canary(source_revision="rev123", skill_id="skill-demo",
                              issue_id="OPENAI_API_KEY", trace_channel="dynamic")
    rec = _rec(outcome="TIMEOUT", timeout=True, exit_code=124)
    assert parse_execution(rec, {"OPENAI_API_KEY": marker}) == []
    rec2 = _rec(outcome="FAILED_DEPENDENCY", exit_code=1)
    assert parse_execution(rec2, {"OPENAI_API_KEY": marker}) == []


def test_parser_network_allow_when_expected_provider():
    """Credential sent to its declared provider → AUTHORIZED_SECRET_USE (§17-A)."""
    marker = canonical_canary(source_revision="rev123", skill_id="skill-demo",
                              issue_id="OPENAI_API_KEY", trace_channel="dynamic")
    creds = {"OPENAI_API_KEY": marker}
    ev = {"method": "POST", "destination": "https://api.openai.com/v1/chat",
          "headers": {}, "body": marker}
    rec = _rec(network_events=(ev,), declared_providers=("api.openai.com",))
    traces = parse_execution(rec, creds)
    assert len(traces) == 1
    tr = traces[0]
    assert tr.flow_class == "AUTHORIZED_SECRET_USE"
    assert tr.metadata["authorized_sink"] is True
    from demotest.core.enums import ExpectedAction, LeakageExpectation
    # ALLOW requires authorized_sink/safe_redaction — parser set it
    case = project_trace_to_case(tr, expected_action=ExpectedAction.ALLOW,
                                 leakage_expected=LeakageExpectation.NO_LEAK)
    assert case.expected_action.value == "allow"


def test_adapter_rejects_synthetic_and_accepts_dynamic(tmp_path: Path):
    from demotest.datasets.adapters.credential_dynamic_traces import CredentialDynamicTracesAdapter
    from demotest.core.exceptions import DatasetSourceError

    # synthetic rejected
    synth = CredentialTrace(trace_id="s1", skill_id="sk", skill_name="sk",
                            issue_id="OPENAI_API_KEY", academic_code="DYNAMIC",
                            pattern="x", classification="Information Exposure", severity="high",
                            sink="stdout", gateway_channel="TOOL_RESULT",
                            gateway_visibility="DIRECT", flow_class="STDOUT_EXPOSURE",
                            credential_marker="TEST_SECRET_AAAAAAAAAAAAAAAA",
                            payload="hi TEST_SECRET_AAAAAAAAAAAAAAAA",
                            evidence_type="CATALOG_DERIVED", dynamic_confirmed=False,
                            trace_hash="sha256:abc", metadata={})
    adapter = CredentialDynamicTracesAdapter(raw_dir=tmp_path, strict=True,
                                             trace_provider=[synth])
    with pytest.raises(DatasetSourceError):
        list(adapter.iter_cases())

    # dynamic accepted (A)
    marker = "TEST_SECRET_BBBBCCCCDDDDEEEE"
    th = canonical_trace_hash(
        skill_snapshot_sha256="s" * 64, execution_condition="deterministic",
        credential_marker=marker, sink="stdout", canonical_payload=f"hi {marker}",
        destination="", sandbox_image_digest="sha256:img", pipeline_revision="rev")
    dyn = CredentialTrace(trace_id="d1", skill_id="sk", skill_name="sk",
                          issue_id="OPENAI_API_KEY", academic_code="DYNAMIC",
                          pattern="STDOUT_EXPOSURE", classification="Information Exposure", severity="high",
                          sink="stdout", gateway_channel="TOOL_RESULT",
                          gateway_visibility="DIRECT", flow_class="STDOUT_EXPOSURE",
                          credential_marker=marker, payload=f"hi {marker}",
                          evidence_type="DYNAMIC_TRACE", dynamic_confirmed=True,
                          source_revision="rev", sandbox_version="sha256:img",
                          trace_hash=th, metadata={
                              "skill_snapshot_sha256": "s" * 64,
                              "execution_condition": "deterministic",
                              "sandbox_image_digest": "sha256:img",
                              "pipeline_revision": "rev",
                          })
    adapter2 = CredentialDynamicTracesAdapter(raw_dir=tmp_path, strict=True,
                                              trace_provider=[dyn])
    cases = list(adapter2.iter_cases())
    assert len(cases) == 1
    assert cases[0].metadata["source"]["quality_tier"] == "A"


def test_snapshot_freeze_and_verify_roundtrip(tmp_path: Path):
    from demotest.datasets.dynamic.snapshot import freeze_skill_snapshot, load_snapshot, verify_snapshot
    skills_root = tmp_path / "skills"
    (skills_root / "skill-a").mkdir(parents=True)
    (skills_root / "skill-a" / "main.py").write_text("print('hi')")
    manifest = freeze_skill_snapshot(skills_root, pipeline_revision="rev1",
                                     out_root=tmp_path / "snapshots", created_at="2026-01-01T00:00:00Z")
    assert manifest.snapshot_id.startswith("snap-")
    loaded = load_snapshot(manifest.snapshot_id, root=tmp_path / "snapshots")
    assert loaded.archive_sha256 == manifest.archive_sha256
    assert verify_snapshot(manifest.snapshot_id, root=tmp_path / "snapshots") == []
    # drift detection
    (tmp_path / "snapshots" / manifest.snapshot_id / "skills" / "skill-a" / "main.py").write_text("print('evil')")
    assert verify_snapshot(manifest.snapshot_id, root=tmp_path / "snapshots")


def _runtime_ready_skills_root(root: Path, skill_ids: list[str]) -> Path:
    """Materialized-style skills root that satisfies the deterministic Core gate.

    Mirrors production: entry_command comes from the materialization manifest's
    runtime_spec (sidecar semantics), never inline-mutated skill bytes.
    """
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
            "source_sha256": hashlib.sha256(sid.encode()).hexdigest(),
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
        "selection_sha256": hashlib.sha256(b"test-selection").hexdigest(),
        "skills": skills_doc,
    }, indent=2, sort_keys=True), encoding="utf-8")
    return skills_root


def test_collector_freezes_lock_with_stub_runner(tmp_path: Path):
    """Collector orchestration + lock — stub runner avoids Docker."""
    from demotest.datasets.dynamic.snapshot import freeze_skill_snapshot
    from demotest.datasets.dynamic.skillleak_collector import DynamicTraceCollector

    skills_root = _runtime_ready_skills_root(tmp_path, ["skill-x"])
    manifest = freeze_skill_snapshot(skills_root, pipeline_revision="rev-collect",
                                     out_root=tmp_path / "snapshots")

    class StubRunner:
        pipeline_revision = "rev-collect"
        pipeline_root = Path("cache/datasets_v3/raw/skillleakbench_pipeline")
        def image_digest(self): return "sha256:stub-image"
        def resource_profile(self):
            return {"isolation_level": "docker_only_hardened", "network": "none",
                    "memory": "512m", "cpus": "0.5", "pids_limit": 64, "timeout_s": 120,
                    "cap_drop": "ALL", "no_new_privileges": True,
                    "read_only_rootfs": True, "skills_read_only": False,
                    "tmpfs": "/tmp:rw,nosuid,nodev,size=64m", "concurrency": 1}
        def doctor_checks(self, **kw):  # always green
            from demotest.datasets.dynamic.sandbox import DoctorReport, DoctorCheck
            return DoctorReport((DoctorCheck("ok", True, ""),))
        def run_skill(self, *, skill_id, skill_dir, skill_snapshot_sha256,
                      credentials, condition="deterministic", declared_providers=(), command=None, work_root=None, timeout_s=None):
            # Echo whatever official marker the collector injected
            any_marker = next(iter(credentials.values()), "")
            return DynamicExecutionRecord(
                execution_id=f"exec-{skill_id}", skill_id=skill_id,
                skill_snapshot_sha256=skill_snapshot_sha256,
                condition=condition, execution_mode="deterministic",
                sandbox_provider="SkillLeakBench", pipeline_revision=self.pipeline_revision,
                sandbox_image_digest=self.image_digest(),
                outcome="SUCCESS_REACHED_SECRET_PATH", exit_code=0, timeout=False,
                stdout_text=f"leaked {any_marker}", stdout_artifact="", network_artifact="",
                network_events=(), credential_names=tuple(credentials), declared_providers=(),
            )

    raw_dir = tmp_path / "raw"
    meta_root = tmp_path / "meta"
    meta_root.mkdir(parents=True, exist_ok=True)
    collector = DynamicTraceCollector(runner=StubRunner(), raw_dir=raw_dir,
                                      snapshots_root=tmp_path / "snapshots",
                                      metadata_root=meta_root)
    report = collector.collect(snapshot_id=manifest.snapshot_id)
    assert report.n_traces >= 1
    assert (raw_dir / "traces.jsonl").exists()
    assert (raw_dir / "trace_meta.json").exists()
    assert (raw_dir / "executions.jsonl").exists()
    from demotest.datasets.source_lock import load_source_lock
    lk = load_source_lock("credential_dynamic_traces",
                          path=meta_root / "credential_dynamic_traces.lock.json")
    assert lk.raw_sha256 == hashlib.sha256((raw_dir / "traces.jsonl").read_bytes()).hexdigest()
    # at minimum trace_meta snapshot hash matches file bytes
    meta = json.loads((raw_dir / "trace_meta.json").read_text(encoding="utf-8"))
    assert meta["snapshot_sha256"] == hashlib.sha256((raw_dir / "traces.jsonl").read_bytes()).hexdigest()


# -- Docker-only hardening / serial batch-resume ----------------------------

def test_build_docker_argv_uses_hardened_docker_only_profile(tmp_path: Path):
    runner = SkillLeakBenchSandboxRunner(
        pipeline_root=Path("cache/datasets_v3/raw/skillleakbench_pipeline"),
        pipeline_revision="rev", memory="256m", cpus="0.5", pids_limit=64, timeout_s=90,
    )
    creds = injected_credentials(
        pipeline_revision="rev", skill_id="s", names=("OPENAI_API_KEY",))
    argv = runner.build_docker_argv(
        skill_id="s", skill_dir=tmp_path, monitoring_dir=tmp_path,
        credentials=creds, condition="deterministic")
    joined = " ".join(argv)
    assert "--network none" in joined
    assert "--memory 256m" in joined
    assert "--cpus 0.5" in joined
    assert "--pids-limit 64" in joined
    assert "--cap-drop ALL" in joined
    assert "--security-opt no-new-privileges:true" in joined
    assert "--read-only" in argv
    # Frozen snapshot is never mounted :ro — we mount a per-execution writable
    # copy so entrypoint can write /skills/.env even with --read-only rootfs.
    assert any(x.endswith(":/skills") for x in argv)
    assert not any(x.endswith(":/skills:ro") for x in argv)
    assert any(x.endswith(":/monitoring:rw") for x in argv)
    assert "--tmpfs" in joined and "/mock_creds" in joined
    assert runner.resource_profile()["concurrency"] == 1
    assert runner.resource_profile()["skills_read_only"] is False


def test_build_docker_argv_accepts_official_forged_markers(tmp_path: Path):
    runner = SkillLeakBenchSandboxRunner(
        pipeline_root=Path("cache/datasets_v3/raw/skillleakbench_pipeline"),
        pipeline_revision="rev",
    )
    # Official forged canary — same values the container generates
    creds = {"OPENAI_API_KEY": "sk-leakbench-mock-demo", "AWS_ACCESS_KEY_ID": "AKIA-LEAKBENCH-abc123"}
    argv = runner.build_docker_argv(
        skill_id="s", skill_dir=tmp_path, monitoring_dir=tmp_path,
        credentials=creds, condition="deterministic")
    assert "sk-leakbench-mock-demo" in " ".join(argv)


def test_parser_records_docker_only_isolation_metadata():
    marker = canonical_canary(source_revision="rev123", skill_id="skill-demo",
                              issue_id="OPENAI_API_KEY", trace_channel="dynamic")
    rec = _rec(
        stdout_text=f"prefix {marker} suffix",
        metadata={
            "isolation_level": "docker_only_hardened",
            "sandbox_profile": {"memory": "256m", "cpus": "0.5", "concurrency": 1},
        },
    )
    traces = parse_execution(rec, {"OPENAI_API_KEY": marker})
    assert traces[0].metadata["isolation_level"] == "docker_only_hardened"
    assert traces[0].metadata["sandbox_profile"]["concurrency"] == 1


def test_collector_batches_accumulate_and_resume_without_rerun(tmp_path: Path):
    from demotest.datasets.dynamic.snapshot import freeze_skill_snapshot
    from demotest.datasets.dynamic.skillleak_collector import DynamicTraceCollector

    skills_root = _runtime_ready_skills_root(tmp_path, ["skill-a", "skill-b", "skill-c"])
    manifest = freeze_skill_snapshot(
        skills_root, pipeline_revision="rev-batch", out_root=tmp_path / "snapshots")

    class StubRunner:
        pipeline_revision = "rev-batch"
        pipeline_root = Path("cache/datasets_v3/raw/skillleakbench_pipeline")
        isolation_level = "docker_only_hardened"
        calls: list[str] = []
        def image_digest(self): return "sha256:stub-image"
        def resource_profile(self):
            return {"isolation_level": self.isolation_level, "memory": "256m",
                    "cpus": "0.5", "read_only_rootfs": True, "skills_read_only": False,
                    "tmpfs": "/tmp:rw,nosuid,nodev,size=64m", "concurrency": 1}
        def run_skill(self, *, skill_id, skill_dir, skill_snapshot_sha256,
                      credentials, condition="deterministic", declared_providers=(),
                      command=None, work_root=None, timeout_s=None):
            self.calls.append(skill_id)
            marker = credentials["OPENAI_API_KEY"]
            return DynamicExecutionRecord(
                execution_id=f"exec-{skill_id}-{condition}", skill_id=skill_id,
                skill_snapshot_sha256=skill_snapshot_sha256, condition=condition,
                execution_mode="deterministic", sandbox_provider="SkillLeakBench",
                pipeline_revision=self.pipeline_revision,
                sandbox_image_digest=self.image_digest(),
                outcome="SUCCESS_REACHED_SECRET_PATH", exit_code=0, timeout=False,
                stdout_text=f"leaked {marker}", credential_names=tuple(credentials),
                metadata={"isolation_level": self.isolation_level,
                          "sandbox_profile": self.resource_profile()},
            )

    runner = StubRunner()
    raw_dir = tmp_path / "raw"
    meta_root = tmp_path / "meta"; meta_root.mkdir()
    collector = DynamicTraceCollector(
        runner=runner, raw_dir=raw_dir,
        snapshots_root=tmp_path / "snapshots", metadata_root=meta_root)

    first = collector.collect(snapshot_id=manifest.snapshot_id, offset=0, limit=2)
    assert first.n_skills_attempted == 2
    assert first.n_traces == 2
    second = collector.collect(snapshot_id=manifest.snapshot_id, offset=1, limit=2)
    assert second.n_skills_selected == 2
    assert second.n_skills_skipped_existing == 1
    assert second.n_skills_attempted == 1
    assert second.n_traces == 3
    assert sorted(runner.calls) == ["skill-a", "skill-b", "skill-c"]


def test_collector_refuses_profile_drift_across_batches(tmp_path: Path):
    from demotest.datasets.dynamic.snapshot import freeze_skill_snapshot
    from demotest.datasets.dynamic.skillleak_collector import DynamicTraceCollector

    skills_root = _runtime_ready_skills_root(tmp_path, ["skill-a"])
    manifest = freeze_skill_snapshot(
        skills_root, pipeline_revision="rev-profile", out_root=tmp_path / "snapshots")

    class StubRunner:
        pipeline_revision = "rev-profile"
        pipeline_root = Path("cache/datasets_v3/raw/skillleakbench_pipeline")
        isolation_level = "docker_only_hardened"
        def __init__(self, memory): self.memory = memory
        def image_digest(self): return "sha256:stub-image"
        def resource_profile(self):
            return {"isolation_level": self.isolation_level, "memory": self.memory,
                    "cpus": "0.5", "concurrency": 1}
        def run_skill(self, *, skill_id, skill_dir, skill_snapshot_sha256,
                      credentials, condition="deterministic", declared_providers=(),
                      command=None, work_root=None, timeout_s=None):
            marker = credentials["OPENAI_API_KEY"]
            return DynamicExecutionRecord(
                execution_id=f"exec-{skill_id}-{condition}", skill_id=skill_id,
                skill_snapshot_sha256=skill_snapshot_sha256, condition=condition,
                execution_mode="deterministic", sandbox_provider="SkillLeakBench",
                pipeline_revision=self.pipeline_revision,
                sandbox_image_digest=self.image_digest(),
                outcome="SUCCESS_REACHED_SECRET_PATH", exit_code=0, timeout=False,
                stdout_text=marker, credential_names=tuple(credentials),
                metadata={"isolation_level": self.isolation_level,
                          "sandbox_profile": self.resource_profile()},
            )

    raw_dir = tmp_path / "raw"
    meta_root = tmp_path / "meta"; meta_root.mkdir()
    DynamicTraceCollector(
        runner=StubRunner("256m"), raw_dir=raw_dir,
        snapshots_root=tmp_path / "snapshots", metadata_root=meta_root,
    ).collect(snapshot_id=manifest.snapshot_id, limit=1)
    with pytest.raises(RuntimeError, match="profile changed"):
        DynamicTraceCollector(
            runner=StubRunner("512m"), raw_dir=raw_dir,
            snapshots_root=tmp_path / "snapshots", metadata_root=meta_root,
        ).collect(snapshot_id=manifest.snapshot_id, limit=1)


def test_collector_refuses_image_digest_drift(tmp_path: Path):
    from demotest.datasets.dynamic.snapshot import freeze_skill_snapshot
    from demotest.datasets.dynamic.skillleak_collector import DynamicTraceCollector

    skills_root = _runtime_ready_skills_root(tmp_path, ["skill-a"])
    manifest = freeze_skill_snapshot(
        skills_root, pipeline_revision="rev-img", out_root=tmp_path / "snapshots")

    class StubRunner:
        pipeline_revision = "rev-img"
        pipeline_root = Path("cache/datasets_v3/raw/skillleakbench_pipeline")
        isolation_level = "docker_only_hardened"
        def __init__(self, digest): self._digest = digest
        def image_digest(self): return self._digest
        def resource_profile(self):
            return {"isolation_level": self.isolation_level, "memory": "512m",
                    "cpus": "0.5", "concurrency": 1}
        def run_skill(self, *, skill_id, skill_dir, skill_snapshot_sha256,
                      credentials, condition="deterministic", declared_providers=(),
                      command=None, work_root=None, timeout_s=None):
            marker = credentials["OPENAI_API_KEY"]
            return DynamicExecutionRecord(
                execution_id=f"exec-{skill_id}-{condition}", skill_id=skill_id,
                skill_snapshot_sha256=skill_snapshot_sha256, condition=condition,
                execution_mode="deterministic", sandbox_provider="SkillLeakBench",
                pipeline_revision=self.pipeline_revision,
                sandbox_image_digest=self.image_digest(),
                outcome="SUCCESS_REACHED_SECRET_PATH", exit_code=0, timeout=False,
                stdout_text=marker, credential_names=tuple(credentials),
                metadata={"isolation_level": self.isolation_level,
                          "sandbox_profile": self.resource_profile()},
            )

    raw_dir = tmp_path / "raw"
    meta_root = tmp_path / "meta"; meta_root.mkdir()
    DynamicTraceCollector(
        runner=StubRunner("sha256:img-a"), raw_dir=raw_dir,
        snapshots_root=tmp_path / "snapshots", metadata_root=meta_root,
    ).collect(snapshot_id=manifest.snapshot_id, limit=1)
    with pytest.raises(RuntimeError, match="image digest changed"):
        DynamicTraceCollector(
            runner=StubRunner("sha256:img-b"), raw_dir=raw_dir,
            snapshots_root=tmp_path / "snapshots", metadata_root=meta_root,
        ).collect(snapshot_id=manifest.snapshot_id, limit=1)


def test_workspace_copy_keeps_frozen_source_immutable(tmp_path: Path):
    from demotest.datasets.dynamic.workspace import prepare_execution_copy
    frozen = tmp_path / "frozen-skill"
    frozen.mkdir()
    (frozen / "main.py").write_text("print('hi')")
    work = tmp_path / "work"
    copy = prepare_execution_copy(frozen, "exec-abc123", work_root=work)
    assert copy.is_dir()
    assert (copy / "main.py").read_text() == "print('hi')"
    # mutate copy does not affect frozen
    (copy / "main.py").write_text("print('evil')")
    assert (frozen / "main.py").read_text() == "print('hi')"


def test_execution_workdir_is_condition_isolated(tmp_path: Path):
    from demotest.datasets.dynamic.snapshot import freeze_skill_snapshot
    from demotest.datasets.dynamic.skillleak_collector import DynamicTraceCollector

    skills_root = _runtime_ready_skills_root(tmp_path, ["skill-a"])
    manifest = freeze_skill_snapshot(
        skills_root, pipeline_revision="rev-cond", out_root=tmp_path / "snapshots")

    seen_work_roots: list[str] = []

    class StubRunner:
        pipeline_revision = "rev-cond"
        pipeline_root = Path("cache/datasets_v3/raw/skillleakbench_pipeline")
        isolation_level = "docker_only_hardened"
        def image_digest(self): return "sha256:stub-image"
        def resource_profile(self):
            return {"isolation_level": self.isolation_level, "concurrency": 1}
        def run_skill(self, *, skill_id, skill_dir, skill_snapshot_sha256,
                      credentials, condition="deterministic", declared_providers=(),
                      command=None, work_root=None, timeout_s=None):
            seen_work_roots.append(str(work_root))
            marker = credentials["OPENAI_API_KEY"]
            return DynamicExecutionRecord(
                execution_id=f"exec-{skill_id}-{condition}", skill_id=skill_id,
                skill_snapshot_sha256=skill_snapshot_sha256, condition=condition,
                execution_mode="deterministic", sandbox_provider="SkillLeakBench",
                pipeline_revision=self.pipeline_revision,
                sandbox_image_digest=self.image_digest(),
                outcome="SUCCESS_REACHED_SECRET_PATH", exit_code=0, timeout=False,
                stdout_text=marker, credential_names=tuple(credentials),
                metadata={"isolation_level": self.isolation_level,
                          "sandbox_profile": self.resource_profile()},
            )

    raw_dir = tmp_path / "raw"
    meta_root = tmp_path / "meta"; meta_root.mkdir()
    collector = DynamicTraceCollector(
        runner=StubRunner(), raw_dir=raw_dir,
        snapshots_root=tmp_path / "snapshots", metadata_root=meta_root)
    collector.collect(snapshot_id=manifest.snapshot_id, condition="deterministic")
    assert any("deterministic" in p for p in seen_work_roots)


def test_official_marker_provider_matches_container(tmp_path: Path):
    # Verify the provider can be instantiated and returns leakbench markers
    # (without requiring the real pinned checkout — falls back gracefully)
    from demotest.datasets.dynamic.markers import SkillLeakBenchMarkerProvider
    import hashlib as _hl
    # Create a minimal mock pipeline checkout
    pipeline_root = tmp_path / "pipeline"
    phase3 = pipeline_root / "code" / "phase3_dynamic"
    phase3.mkdir(parents=True)
    # Copy real mock_creds.py into the fake checkout
    import shutil as _sh
    real = Path("cache/datasets_v3/raw/skillleakbench_pipeline/code/phase3_dynamic/mock_creds.py")
    if real.exists():
        _sh.copy(real, phase3 / "mock_creds.py")
        provider = SkillLeakBenchMarkerProvider(pipeline_root)
        markers = provider.markers_for_skill("demo-skill")
        assert any("leakbench" in v.lower() for v in markers.values())
        assert "ANTHROPIC_API_KEY" not in markers
        assert provider.provenance["credential_kind"] == "official_forged_canary"


def test_run_skill_workspace_copy_failure_is_fatal(tmp_path: Path, monkeypatch):
    from demotest.datasets.dynamic.sandbox import SkillLeakBenchSandboxRunner, SandboxUnavailable

    runner = SkillLeakBenchSandboxRunner(
        pipeline_root=Path("cache/datasets_v3/raw/skillleakbench_pipeline"),
        pipeline_revision="rev",
    )
    # Force workspace copy to fail — must not fall back to frozen dir
    import demotest.datasets.dynamic.workspace as ws

    def _fail(*a, **kw):
        raise OSError("copy failed")

    monkeypatch.setattr(ws, "prepare_execution_copy", _fail)
    # also patch the runner's internal import path
    import demotest.datasets.dynamic.sandbox as sb

    orig_ws = sb.__dict__.get("workspace", None)
    frozen = tmp_path / "skill"
    frozen.mkdir()
    (frozen / "x").write_text("hi")
    with pytest.raises(SandboxUnavailable, match="isolated execution workspace"):
        runner.run_skill(
            skill_id="s", skill_dir=frozen, skill_snapshot_sha256="a" * 64,
            credentials={}, work_root=tmp_path / "work",
        )


def test_collector_marker_provider_failure_is_fatal(tmp_path: Path):
    from demotest.datasets.dynamic.snapshot import freeze_skill_snapshot
    from demotest.datasets.dynamic.skillleak_collector import DynamicTraceCollector

    skills_root = tmp_path / "skills"
    (skills_root / "skill-a").mkdir(parents=True)
    (skills_root / "skill-a" / "run.sh").write_text("echo hi")
    manifest = freeze_skill_snapshot(skills_root, pipeline_revision="rev-x", out_root=tmp_path / "snapshots")

    class BadRunner:
        pipeline_revision = "rev-x"
        pipeline_root = Path(tmp_path / "no-such-pipeline")
        def image_digest(self): return "sha256:stub"
        def resource_profile(self): return {"isolation_level": "docker_only_hardened"}

    raw_dir = tmp_path / "raw"
    meta_root = tmp_path / "meta"; meta_root.mkdir()
    collector = DynamicTraceCollector(runner=BadRunner(), raw_dir=raw_dir, snapshots_root=tmp_path / "snapshots", metadata_root=meta_root)
    with pytest.raises(RuntimeError, match="marker provider unavailable"):
        collector.collect(snapshot_id=manifest.snapshot_id, limit=1)


def test_v2_collector_meta_refuses_v3_resume(tmp_path: Path):
    from demotest.datasets.dynamic.snapshot import freeze_skill_snapshot
    from demotest.datasets.dynamic.skillleak_collector import DynamicTraceCollector
    import json as _json

    skills_root = tmp_path / "skills"
    (skills_root / "skill-a").mkdir(parents=True)
    (skills_root / "skill-a" / "run.sh").write_text("echo hi")
    manifest = freeze_skill_snapshot(skills_root, pipeline_revision="rev-v", out_root=tmp_path / "snapshots")

    class Runner:
        pipeline_revision = "rev-v"
        pipeline_root = Path("cache/datasets_v3/raw/skillleakbench_pipeline")
        def image_digest(self): return "sha256:stub"
        def resource_profile(self): return {"isolation_level": "docker_only_hardened", "concurrency": 1}
        def run_skill(self, *, skill_id, skill_dir, skill_snapshot_sha256, credentials, condition="deterministic", declared_providers=(), command=None, work_root=None, timeout_s=None):
            return DynamicExecutionRecord(
                execution_id=f"exec-{skill_id}", skill_id=skill_id, skill_snapshot_sha256=skill_snapshot_sha256,
                condition=condition, execution_mode="deterministic", sandbox_provider="SkillLeakBench",
                pipeline_revision=self.pipeline_revision, sandbox_image_digest=self.image_digest(),
                outcome="SUCCESS_REACHED_SECRET_PATH", exit_code=0, timeout=False, stdout_text="x",
                credential_names=tuple(credentials), metadata={"sandbox_profile": self.resource_profile()},
            )

    raw_dir = tmp_path / "raw"
    meta_root = tmp_path / "meta"; meta_root.mkdir()
    # Simulate an old v2 cache
    raw_dir.mkdir(parents=True, exist_ok=True)
    (raw_dir / "trace_meta.json").write_text(_json.dumps({
        "snapshot_id": manifest.snapshot_id,
        "pipeline_revision": "rev-v",
        "builder_version": "dynamic-collector-v2",
        "sandbox_profile": Runner().resource_profile(),
        "sandbox_image_digest": "sha256:stub",
    }), encoding="utf-8")
    (raw_dir / "executions.jsonl").write_text("", encoding="utf-8")
    (raw_dir / "traces.jsonl").write_text("", encoding="utf-8")
    with pytest.raises(RuntimeError, match="collector version"):
        DynamicTraceCollector(runner=Runner(), raw_dir=raw_dir, snapshots_root=tmp_path / "snapshots", metadata_root=meta_root).collect(snapshot_id=manifest.snapshot_id, limit=1)


def test_agent_driver_requires_explicit_model(monkeypatch):
    from demotest.datasets.dynamic.agents.openai_compatible import OpenAICompatibleAgentDriver
    from demotest.datasets.dynamic.agents.models import AgentConfig

    monkeypatch.setenv("AGENT_BASE_URL", "https://example.com")
    monkeypatch.setenv("AGENT_API_KEY", "sk-test")
    monkeypatch.delenv("AGENT_MODEL", raising=False)
    driver = OpenAICompatibleAgentDriver(AgentConfig(model=""))
    with pytest.raises(RuntimeError, match="AGENT_MODEL is required"):
        driver.run_turn(messages=[{"role": "user", "content": "hi"}])


def test_session_action_does_not_override_condition(tmp_path: Path):
    from demotest.datasets.dynamic.session import SandboxSession, SandboxAction

    class FakeRunner:
        last_condition = None
        def run_skill(self, *, skill_id, skill_dir, skill_snapshot_sha256, credentials, condition="benign", work_root=None, **kw):
            self.last_condition = condition
            return type("R", (), {"stdout_text": "out", "network_events": (), "exit_code": 0, "stdout_artifact": str(work_root)})()

    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text("do thing")
    runner = FakeRunner()
    sess = SandboxSession(runner=runner, skill_id="s", skill_dir=skill, skill_snapshot_sha256="a" * 64, credentials={}, work_root=tmp_path / "work", condition="benign")
    sess.execute(SandboxAction(kind="execute_skill_entrypoint"))
    assert runner.last_condition == "benign"
    sess2 = SandboxSession(runner=runner, skill_id="s", skill_dir=skill, skill_snapshot_sha256="a" * 64, credentials={}, work_root=tmp_path / "work2", condition="adversarial")
    sess2.execute(SandboxAction(kind="execute_skill_entrypoint"), condition="adversarial")
    assert runner.last_condition == "adversarial"


def test_read_declared_output_does_not_rerun_skill(tmp_path: Path):
    from demotest.datasets.dynamic.session import SandboxSession, SandboxAction

    calls = {"n": 0}

    class FakeRunner:
        def run_skill(self, **kw):
            calls["n"] += 1
            return type("R", (), {"stdout_text": "out", "network_events": (), "exit_code": 0, "stdout_artifact": "x"})()

    skill = tmp_path / "skill"
    skill.mkdir()
    runner = FakeRunner()
    sess = SandboxSession(runner=runner, skill_id="s", skill_dir=skill, skill_snapshot_sha256="a" * 64, credentials={}, work_root=tmp_path / "work")
    sess.execute(SandboxAction(kind="execute_skill_entrypoint"))
    assert calls["n"] == 1
    sess.execute(SandboxAction(kind="read_declared_output"))
    assert calls["n"] == 1


def test_command_exit_status_overrides_container_exit_code(monkeypatch, tmp_path: Path):
    from demotest.datasets.dynamic.sandbox import SkillLeakBenchSandboxRunner
    import subprocess as _sp

    runner = SkillLeakBenchSandboxRunner(
        pipeline_root=Path("cache/datasets_v3/raw/skillleakbench_pipeline"),
        pipeline_revision="rev",
    )
    # Mock docker run to write exit_status=1 while container returncode is 0
    orig_run = _sp.run

    def fake_run(argv, **kw):
        # argv: [..., '-v', '<host>:/skills', '-v', '<host>/monitoring:/monitoring:rw', ...]
        mon_host = None
        for i, a in enumerate(argv):
            if a == "-v" and i + 1 < len(argv) and ":/monitoring:" in argv[i + 1]:
                raw = argv[i + 1].split(":")[0]
                # On Windows the host path itself contains ':', so split(":")[0] truncates.
                # Reconstruct via rsplit.
                mon_host = Path(argv[i + 1].rsplit(":/monitoring", 1)[0])
                break
        if mon_host is not None:
            mon_host.mkdir(parents=True, exist_ok=True)
            (mon_host / "stdout.log").write_text("some output", encoding="utf-8")
            (mon_host / "exit_status").write_text("1", encoding="utf-8")
            (mon_host / "network_payload.log").write_text("", encoding="utf-8")
        return type("P", (), {"returncode": 0})()

    monkeypatch.setattr(_sp, "run", fake_run)
    # image_digest is called inside run_skill — stub it
    monkeypatch.setattr(runner, "image_digest", lambda: "sha256:stub")
    monkeypatch.setattr(runner, "docker_available", lambda: True)
    # Ensure pipeline check passes — create the expected dir
    (Path("cache/datasets_v3/raw/skillleakbench_pipeline/code/phase3_dynamic")).mkdir(parents=True, exist_ok=True)

    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "a").write_text("hi")
    rec = runner.run_skill(skill_id="s", skill_dir=skill, skill_snapshot_sha256="a" * 64, credentials={}, work_root=tmp_path / "work")
    assert rec.exit_code == 1
    assert rec.outcome != "SUCCESS_NO_SECRET_FLOW"
    assert rec.metadata["container_exit_code"] == 0
    assert rec.metadata["exit_status_file"] == "1"


def test_resume_refuses_pre_honeypot_tmpfs_profile(tmp_path: Path):
    """Old v3 cache without tmpfs_mounts must not resume under new v4 profile."""
    from demotest.datasets.dynamic.snapshot import freeze_skill_snapshot
    from demotest.datasets.dynamic.skillleak_collector import DynamicTraceCollector
    import json as _json

    skills_root = tmp_path / "skills"
    (skills_root / "skill-a").mkdir(parents=True)
    (skills_root / "skill-a" / "run.sh").write_text("echo hi")
    manifest = freeze_skill_snapshot(skills_root, pipeline_revision="rev-tmpfs", out_root=tmp_path / "snapshots")

    class NewRunner:
        pipeline_revision = "rev-tmpfs"
        pipeline_root = Path("cache/datasets_v3/raw/skillleakbench_pipeline")
        def image_digest(self): return "sha256:stub"
        def resource_profile(self):
            from demotest.datasets.dynamic.sandbox import SkillLeakBenchSandboxRunner
            return SkillLeakBenchSandboxRunner(
                pipeline_root=self.pipeline_root, pipeline_revision=self.pipeline_revision
            ).resource_profile()
        def run_skill(self, **kw):
            raise AssertionError("should not run — resume must be refused before execution")

    raw_dir = tmp_path / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    # Simulate old cache: profile without tmpfs_mounts
    old_profile = {k: v for k, v in NewRunner().resource_profile().items() if k != "tmpfs_mounts"}
    (raw_dir / "trace_meta.json").write_text(_json.dumps({
        "snapshot_id": manifest.snapshot_id,
        "pipeline_revision": "rev-tmpfs",
        "builder_version": "dynamic-collector-v4",
        "sandbox_profile": old_profile,
        "sandbox_image_digest": "sha256:stub",
    }), encoding="utf-8")
    (raw_dir / "executions.jsonl").write_text("", encoding="utf-8")
    (raw_dir / "traces.jsonl").write_text("", encoding="utf-8")
    meta_root = tmp_path / "meta"; meta_root.mkdir()
    with pytest.raises(RuntimeError, match="profile changed"):
        DynamicTraceCollector(runner=NewRunner(), raw_dir=raw_dir, snapshots_root=tmp_path / "snapshots", metadata_root=meta_root).collect(snapshot_id=manifest.snapshot_id, limit=1)


def test_raw_credential_json_becomes_network_body():
    from demotest.datasets.dynamic.sandbox import normalize_network_events

    events = normalize_network_events('{"OPENAI_API_KEY":"sk-leakbench-mock-x"}')
    assert len(events) == 1
    assert "sk-leakbench-mock-x" in events[0]["body"]
    # Delimited sinkhole format: delimiter line + raw json
    events2 = normalize_network_events(
        '--- proxy POST http://127.0.0.1:9999/collect ---\n'
        '{"OPENAI_API_KEY":"sk-leakbench-mock-x"}\n'
    )
    assert any("sk-leakbench-mock-x" in e["body"] for e in events2)
