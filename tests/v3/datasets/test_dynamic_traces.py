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


def test_collector_freezes_lock_with_stub_runner(tmp_path: Path):
    """Collector orchestration + lock — stub runner avoids Docker."""
    from demotest.datasets.dynamic.snapshot import freeze_skill_snapshot
    from demotest.datasets.dynamic.skillleak_collector import DynamicTraceCollector

    skills_root = tmp_path / "skills"
    (skills_root / "skill-x").mkdir(parents=True)
    (skills_root / "skill-x" / "run.sh").write_text("#!/bin/sh\necho hi\n")
    manifest = freeze_skill_snapshot(skills_root, pipeline_revision="rev-collect",
                                     out_root=tmp_path / "snapshots")

    marker = canonical_canary(source_revision="rev-collect", skill_id="skill-x",
                              issue_id="OPENAI_API_KEY", trace_channel="dynamic")

    class StubRunner:
        pipeline_revision = "rev-collect"
        def image_digest(self): return "sha256:stub-image"
        def doctor_checks(self, **kw):  # always green
            from demotest.datasets.dynamic.sandbox import DoctorReport, DoctorCheck
            return DoctorReport((DoctorCheck("ok", True, ""),))
        def run_skill(self, *, skill_id, skill_dir, skill_snapshot_sha256,
                      credentials, condition="deterministic", declared_providers=(), command=None, work_root=None, timeout_s=None):
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
    assert any(x.endswith(":/skills:ro") for x in argv)
    assert any(x.endswith(":/monitoring:rw") for x in argv)
    assert runner.resource_profile()["concurrency"] == 1


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

    skills_root = tmp_path / "skills"
    for sid in ("skill-a", "skill-b", "skill-c"):
        (skills_root / sid).mkdir(parents=True)
        (skills_root / sid / "run.sh").write_text("#!/bin/sh\necho hi\n")
    manifest = freeze_skill_snapshot(
        skills_root, pipeline_revision="rev-batch", out_root=tmp_path / "snapshots")

    class StubRunner:
        pipeline_revision = "rev-batch"
        isolation_level = "docker_only_hardened"
        calls: list[str] = []
        def image_digest(self): return "sha256:stub-image"
        def resource_profile(self):
            return {"isolation_level": self.isolation_level, "memory": "256m",
                    "cpus": "0.5", "concurrency": 1}
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

    skills_root = tmp_path / "skills"
    (skills_root / "skill-a").mkdir(parents=True)
    (skills_root / "skill-a" / "run.sh").write_text("#!/bin/sh\necho hi\n")
    manifest = freeze_skill_snapshot(
        skills_root, pipeline_revision="rev-profile", out_root=tmp_path / "snapshots")

    class StubRunner:
        pipeline_revision = "rev-profile"
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
