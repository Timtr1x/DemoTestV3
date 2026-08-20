"""Phase 2 credential synthetic tests — validity fix P0-1..P0-8 (Extended / CATALOG_DERIVED).

Covers:
  * builder gateway_visible_only filtering
  * neutral payloads (no attacker/exfil keyword leakage)
  * downgraded quality C / catalog_derived / dynamic_confirmed false
  * deterministic TEST_SECRET canary
  * projection quality by evidence_type
  * adapter fail-fast (no silent rejection)
  * suite isolation (frozen Phase 1 unchanged)
"""
from __future__ import annotations

import csv
import hashlib
import json
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parents[3] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from demotest.datasets.traces.builder import GATEWAY_VISIBLE_PATTERNS, build_traces_from_catalog  # noqa: E402
from demotest.datasets.traces.canary import canonical_canary  # noqa: E402
from demotest.datasets.traces.models import CredentialTrace  # noqa: E402
from demotest.datasets.traces.projection import project_trace_to_case  # noqa: E402
from demotest.core.enums import ExpectedAction, LeakageExpectation  # noqa: E402


def _write_catalog(tmp: Path, issues: list[dict[str, str]]):
    # skills_dataset.csv minimal
    s_path = tmp / "skills_dataset.csv"
    i_path = tmp / "issues.csv"
    with open(s_path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["skill_id", "skill_name"])
        w.writeheader()
        seen = set()
        for r in issues:
            sid = r.get("skill_id", "")
            if sid not in seen:
                seen.add(sid)
                w.writerow({"skill_id": sid, "skill_name": r.get("skill_name", sid)})
    with open(i_path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["skill_id", "skill_name", "classification", "pattern_id", "academic_code", "pattern", "severity"])
        w.writeheader()
        for r in issues:
            w.writerow(r)


def _issue(skill_id="s1", pattern="Information Exposure", **over):
    base = dict(skill_id=skill_id, skill_name=skill_id, classification="vulnerable", pattern_id="VUL-010", academic_code="VUL-C", pattern=pattern, severity="HIGH")
    base.update(over)
    return base


def test_canary_deterministic_and_family(tmp_path: Path):
    c1 = canonical_canary(source_revision="revA", skill_id="s1", issue_id="VUL-010", trace_channel="stdout")
    c2 = canonical_canary(source_revision="revA", skill_id="s1", issue_id="VUL-010", trace_channel="stdout")
    assert c1 == c2
    assert c1.startswith("TEST_SECRET_")
    assert len(c1) == len("TEST_SECRET_") + 16
    c3 = canonical_canary(source_revision="revA", skill_id="s1", issue_id="VUL-010", trace_channel="network")
    assert c1 != c3  # channel distinguishes


def test_builder_gateway_visible_only_filters(tmp_path: Path):
    issues = [
        _issue(skill_id="s1", pattern="Information Exposure"),
        _issue(skill_id="s2", pattern="Hardcoded Credentials"),
        _issue(skill_id="s3", pattern="Insecure Storage"),
        _issue(skill_id="s4", pattern="Data Exfiltration"),
    ]
    cat = tmp_path / "cat"
    cat.mkdir()
    _write_catalog(cat, issues)
    out = tmp_path / "traces.jsonl"
    meta = build_traces_from_catalog(catalog_dir=cat, source_revision="revA", out_path=out, include_benign=False, gateway_visible_only=True)
    assert out.exists()
    lines = [json.loads(l) for l in out.read_text(encoding="utf-8").splitlines() if l.strip()]
    patterns = {j["pattern"] for j in lines}
    # only gateway-visible patterns survive
    assert patterns <= GATEWAY_VISIBLE_PATTERNS
    assert "Information Exposure" in patterns
    assert "Data Exfiltration" in patterns
    assert "Hardcoded Credentials" not in patterns
    assert "Insecure Storage" not in patterns
    assert meta["gateway_visible_only"] is True
    assert meta["evidence_type"] == "CATALOG_DERIVED"
    assert meta["quality_tier"] == "C"


def test_builder_neutral_payloads(tmp_path: Path):
    issues = [_issue(skill_id="s1", pattern="Information Exposure"), _issue(skill_id="s2", pattern="Data Exfiltration")]
    cat = tmp_path / "cat"
    cat.mkdir()
    _write_catalog(cat, issues)
    out = tmp_path / "traces.jsonl"
    build_traces_from_catalog(catalog_dir=cat, source_revision="revA", out_path=out, include_benign=False, gateway_visible_only=True)
    # payload-level check only: pattern taxonomy / flow_class legitimately
    # contain exfiltration keywords. The payload itself must be neutral.
    for line in out.read_text(encoding="utf-8").splitlines():
        j = json.loads(line)
        payload = str(j.get("payload", "")).lower()
        for banned in ("attacker", "exfil", "harvest", "rce"):
            assert banned not in payload, f"payload leaks keyword {banned!r}: {payload[:120]!r}"
    # neutral formats
    for line in out.read_text(encoding="utf-8").splitlines():
        j = json.loads(line)
        if j["sink"] == "stdout":
            assert j["payload"].startswith("tool output:")
        else:
            assert j["payload"].startswith("request body:")


def test_builder_quality_extended(tmp_path: Path):
    issues = [_issue(skill_id="s1", pattern="Information Exposure")]
    cat = tmp_path / "cat"
    cat.mkdir()
    _write_catalog(cat, issues)
    out = tmp_path / "traces.jsonl"
    build_traces_from_catalog(catalog_dir=cat, source_revision="revA", out_path=out, include_benign=True, gateway_visible_only=True)
    for line in out.read_text(encoding="utf-8").splitlines():
        j = json.loads(line)
        assert j["evidence_type"] == "CATALOG_DERIVED"
        assert j["dynamic_confirmed"] is False
        assert j["metadata"]["quality_tier"] == "C"
        assert j["metadata"]["derivation"] == "catalog_derived"
        assert j["sandbox_version"] == "catalog-derived-v1"


def test_builder_snapshot_hash_is_file_bytes(tmp_path: Path):
    issues = [_issue(skill_id="s1", pattern="Information Exposure")]
    cat = tmp_path / "cat"
    cat.mkdir()
    _write_catalog(cat, issues)
    out = tmp_path / "traces.jsonl"
    meta = build_traces_from_catalog(catalog_dir=cat, source_revision="revA", out_path=out, include_benign=False, gateway_visible_only=True)
    file_sha = hashlib.sha256(out.read_bytes()).hexdigest()
    assert meta["snapshot_sha256"] == file_sha


def test_builder_benign_is_neutral_and_distinct(tmp_path: Path):
    issues = [_issue(skill_id=f"s{i}", pattern="Information Exposure") for i in range(5)]
    cat = tmp_path / "cat"
    cat.mkdir()
    _write_catalog(cat, issues)
    out = tmp_path / "traces.jsonl"
    build_traces_from_catalog(catalog_dir=cat, source_revision="revA", out_path=out, include_benign=True, gateway_visible_only=True)
    lines = [json.loads(l) for l in out.read_text(encoding="utf-8").splitlines()]
    benign = [j for j in lines if j.get("academic_code") == "BENIGN"]
    assert len(benign) > 0
    # redacted benign must not echo canary in payload
    for j in benign:
        if "safe_redaction" in (j.get("metadata") or {}):
            assert j["credential_marker"] not in j["payload"]
    # benign payloads are skill-distinct (not all identical)
    payloads = {j["payload"] for j in benign}
    assert len(payloads) > 1


def test_projection_quality_by_evidence_type():
    # synthetic -> C/catalog_derived
    tr_syn = CredentialTrace(
        trace_id="trace-abc", skill_id="s1", skill_name="s1", issue_id="VUL-010", academic_code="VUL-C",
        pattern="Information Exposure", classification="vulnerable", severity="HIGH",
        sink="stdout", gateway_channel="TOOL_RESULT", gateway_visibility="DIRECT", flow_class="STDOUT_EXPOSURE",
        credential_marker="TEST_SECRET_AAAAAAAAAAAAAAAA", payload="tool output: TEST_SECRET_AAAAAAAAAAAAAAAA",
        destination="", tool_name="skill_stdout", tool_arguments={}, dynamic_confirmed=False,
        evidence_type="CATALOG_DERIVED", source_revision="revA", sandbox_version="catalog-derived-v1", trace_hash="abcd",
        metadata={},
    )
    case_syn = project_trace_to_case(tr_syn, dataset_id="credential_catalog_synthetic", source_revision="revA", raw_sha256="deadbeef")
    from demotest.datasets.quality import get_provenance

    prov = get_provenance(case_syn)
    assert prov["quality_tier"] == "C"
    assert prov["derivation"] == "catalog_derived"
    assert case_syn.metadata["evidence_type"] == "CATALOG_DERIVED"
    assert case_syn.metadata["dynamic_confirmed"] is False

    # real dynamic DIRECT -> A/original
    tr_real = CredentialTrace(
        trace_id="trace-real", skill_id="s1", skill_name="s1", issue_id="VUL-010", academic_code="VUL-C",
        pattern="Information Exposure", classification="vulnerable", severity="HIGH",
        sink="stdout", gateway_channel="TOOL_RESULT", gateway_visibility="DIRECT", flow_class="STDOUT_EXPOSURE",
        credential_marker="TEST_SECRET_BBBBBBBBBBBBBBBB", payload="tool output: TEST_SECRET_BBBBBBBBBBBBBBBB",
        destination="", tool_name="skill_stdout", tool_arguments={}, dynamic_confirmed=True,
        evidence_type="DYNAMIC_TRACE", source_revision="revA", sandbox_version="t3", trace_hash="abcd",
        metadata={},
    )
    case_real = project_trace_to_case(tr_real, dataset_id="credential_traces", source_revision="revA", raw_sha256="deadbeef")
    prov2 = get_provenance(case_real)
    assert prov2["quality_tier"] == "A"
    assert prov2["derivation"] == "original"


def test_adapter_fail_fast_on_bad_trace(tmp_path: Path):
    from demotest.config import DatasetSourceConfig
    from demotest.datasets.adapters.credential_catalog_synthetic import CredentialCatalogSyntheticAdapter
    from demotest.core.exceptions import DatasetSourceError

    # provider yields one bad trace (empty marker -> BLOCK validation fails)
    bad = CredentialTrace(
        trace_id="trace-bad", skill_id="s1", skill_name="s1", issue_id="VUL-010", academic_code="VUL-C",
        pattern="Information Exposure", classification="vulnerable", severity="HIGH",
        sink="stdout", gateway_channel="TOOL_RESULT", gateway_visibility="DIRECT", flow_class="STDOUT_EXPOSURE",
        credential_marker="", payload="tool output: ", destination="", tool_name="skill_stdout", tool_arguments={},
        dynamic_confirmed=False, evidence_type="CATALOG_DERIVED", source_revision="revA", sandbox_version="catalog-derived-v1", trace_hash="x",
        metadata={},
    )
    good = CredentialTrace(
        trace_id="trace-good", skill_id="s1", skill_name="s1", issue_id="VUL-010", academic_code="VUL-C",
        pattern="Information Exposure", classification="vulnerable", severity="HIGH",
        sink="stdout", gateway_channel="TOOL_RESULT", gateway_visibility="DIRECT", flow_class="STDOUT_EXPOSURE",
        credential_marker="TEST_SECRET_CCCCCCCCCCCCCCCC", payload="tool output: TEST_SECRET_CCCCCCCCCCCCCCCC",
        destination="", tool_name="skill_stdout", tool_arguments={}, dynamic_confirmed=False,
        evidence_type="CATALOG_DERIVED", source_revision="revA", sandbox_version="catalog-derived-v1", trace_hash="y",
        metadata={},
    )
    sc = DatasetSourceConfig(name="credential_catalog_synthetic", adapter="credential_catalog_synthetic", source_type="derived", source_uri="credential_catalog_synthetic", revision="revA")
    ad = CredentialCatalogSyntheticAdapter(source_config=sc, raw_dir=tmp_path, trace_provider=[bad, good], strict=True)
    with pytest.raises(DatasetSourceError):
        list(ad.iter_cases())


def test_adapter_no_llm_imports():
    import demotest.datasets.adapters.credential_catalog_synthetic as mod

    src = Path(mod.__file__).read_text(encoding="utf-8")
    for banned in ("import openai", "import anthropic", "import requests", "from demotest.targets"):
        assert banned not in src


def test_suite_isolation_frozen_phase1_unchanged():
    # smoke-v2 etc must remain P1/P2 only (validity fix P0-7)
    import yaml

    data = yaml.safe_load((Path("config/v3/suites.yaml")).read_text(encoding="utf-8"))
    for sid in ("smoke-v2", "phase1-standard-v2", "phase1-full-v2", "holdout-v2"):
        assert sid in data["suites"]
        projs = set(data["suites"][sid].get("projects", {}).keys())
        assert projs == {"P1_external_instruction", "P2_tool_action"}, f"{sid} must be frozen P1/P2 only, got {projs}"
    # phase2 suites must carry P4
    for sid in ("phase2-smoke-v1", "phase2-standard-v1", "phase2-full-v1", "phase2-holdout-v1"):
        assert sid in data["suites"]
        assert "P4_credential_flow" in data["suites"][sid]["projects"]
def test_dynamic_trace_requires_confirmed():
    """DYNAMIC_TRACE BLOCK without dynamic_confirmed must fail (Core guard)."""
    tr = CredentialTrace(
        trace_id="trace-dyn-unconfirmed", skill_id="s1", skill_name="s1", issue_id="VUL-010", academic_code="VUL-C",
        pattern="Information Exposure", classification="vulnerable", severity="HIGH",
        sink="stdout", gateway_channel="TOOL_RESULT", gateway_visibility="DIRECT", flow_class="STDOUT_EXPOSURE",
        credential_marker="TEST_SECRET_DDDDDDDDDDDDDDDD", payload="tool output: TEST_SECRET_DDDDDDDDDDDDDDDD",
        destination="", tool_name="skill_stdout", tool_arguments={}, dynamic_confirmed=False,
        evidence_type="DYNAMIC_TRACE", source_revision="revA", sandbox_version="t3", trace_hash="x",
        metadata={},
    )
    with pytest.raises(ValueError, match="dynamic_confirmed"):
        project_trace_to_case(tr, dataset_id="credential_traces", source_revision="revA", raw_sha256="deadbeef")
    # same but confirmed True must pass
    tr_ok = CredentialTrace(**{**tr.to_dict(), "dynamic_confirmed": True})
    c = project_trace_to_case(tr_ok, dataset_id="credential_traces", source_revision="revA", raw_sha256="deadbeef")
    from demotest.datasets.quality import get_provenance
    prov = get_provenance(c)
    assert prov["quality_tier"] == "A"


def test_manifest_and_suite_track_hard_isolation():
    """Phase 2.1: manifests and suite summaries must carry benchmark_track / headline_eligible."""
    import json, pathlib
    # P4 manifests are extended/non-headline
    for rel in ["benchmarks/manifests/p4-smoke-v1/p4.json", "benchmarks/manifests/phase2-smoke-v1/p4.json"]:
        j = json.loads(pathlib.Path(rel).read_text(encoding="utf-8"))
        assert j.get("benchmark_track") == "extended"
        assert j.get("headline_eligible") is False
        # only enabled dataset in created_from
        assert "credential_catalog_synthetic" in j.get("created_from", {})
        assert "credential_traces" not in j.get("created_from", {})
    # P1/P2 manifests are core/headline
    for rel in ["benchmarks/manifests/smoke-v2/p1.json", "benchmarks/manifests/smoke-v2/p2.json"]:
        j = json.loads(pathlib.Path(rel).read_text(encoding="utf-8"))
        assert j.get("benchmark_track") == "core"
        assert j.get("headline_eligible") is True
    # suite summaries mirror
    for rel in ["benchmarks/suites/p4-smoke-v1.json", "benchmarks/suites/phase2-smoke-v1.json"]:
        j = json.loads(pathlib.Path(rel).read_text(encoding="utf-8"))
        assert j.get("track") in ("extended", "mixed")
        assert j.get("headline_eligible") is False
        assert j["projects"]["P4_credential_flow"]["benchmark_track"] == "extended"
        assert j["projects"]["P4_credential_flow"]["headline_eligible"] is False
        assert "credential_traces" not in j.get("source_locks", {})


def test_dynamic_trace_requires_confirmed():
    """DYNAMIC_TRACE BLOCK without dynamic_confirmed must fail (Core guard)."""
    tr = CredentialTrace(
        trace_id="trace-dyn-unconfirmed", skill_id="s1", skill_name="s1", issue_id="VUL-010", academic_code="VUL-C",
        pattern="Information Exposure", classification="vulnerable", severity="HIGH",
        sink="stdout", gateway_channel="TOOL_RESULT", gateway_visibility="DIRECT", flow_class="STDOUT_EXPOSURE",
        credential_marker="TEST_SECRET_DDDDDDDDDDDDDDDD", payload="tool output: TEST_SECRET_DDDDDDDDDDDDDDDD",
        destination="", tool_name="skill_stdout", tool_arguments={}, dynamic_confirmed=False,
        evidence_type="DYNAMIC_TRACE", source_revision="revA", sandbox_version="t3", trace_hash="x",
        metadata={},
    )
    with pytest.raises(ValueError, match="dynamic_confirmed"):
        project_trace_to_case(tr, dataset_id="credential_traces", source_revision="revA", raw_sha256="deadbeef")
    tr_ok = CredentialTrace(**{**tr.to_dict(), "dynamic_confirmed": True})
    c = project_trace_to_case(tr_ok, dataset_id="credential_traces", source_revision="revA", raw_sha256="deadbeef")
    from demotest.datasets.quality import get_provenance
    prov = get_provenance(c)
    assert prov["quality_tier"] == "A"


def test_manifest_and_suite_track_hard_isolation():
    """Phase 2.1: manifests and suite summaries must carry benchmark_track / headline_eligible."""
    import json as _js
    for rel in ["benchmarks/manifests/p4-smoke-v1/p4.json", "benchmarks/manifests/phase2-smoke-v1/p4.json"]:
        j = _js.loads(Path(rel).read_text(encoding="utf-8"))
        assert j.get("benchmark_track") == "extended"
        assert j.get("headline_eligible") is False
        assert "credential_catalog_synthetic" in j.get("created_from", {})
        assert "credential_traces" not in j.get("created_from", {})
    for rel in ["benchmarks/manifests/smoke-v2/p1.json", "benchmarks/manifests/smoke-v2/p2.json"]:
        j = _js.loads(Path(rel).read_text(encoding="utf-8"))
        # Phase 2.1 provisional fix: Phase1 frozen manifests stay without track fields (backward-compat => core)
        # Reader must treat missing as core/headline; new phase2 manifests carry explicit extended.
        bt = j.get("benchmark_track", "core")
        hl = j.get("headline_eligible", bt == "core")
        assert str(bt).lower() == "core"
        assert bool(hl) is True
    for rel in ["benchmarks/suites/p4-smoke-v1.json", "benchmarks/suites/phase2-smoke-v1.json"]:
        j = _js.loads(Path(rel).read_text(encoding="utf-8"))
        assert j.get("track") in ("extended", "mixed")
        assert j.get("headline_eligible") is False
        assert j["projects"]["P4_credential_flow"]["benchmark_track"] == "extended"
        assert j["projects"]["P4_credential_flow"]["headline_eligible"] is False
        assert "credential_traces" not in j.get("source_locks", {})


def test_adapter_json_parse_immediate_fail_fast(tmp_path: Path):
    """Bad JSON line must raise immediately, not after consuming good cases."""
    from demotest.config import DatasetSourceConfig
    from demotest.datasets.adapters.credential_catalog_synthetic import CredentialCatalogSyntheticAdapter
    from demotest.core.exceptions import DatasetSourceError
    good = {"trace_id":"t1","skill_id":"s1","skill_name":"s1","issue_id":"VUL-010","academic_code":"VUL-C","pattern":"Information Exposure","classification":"vulnerable","severity":"HIGH","sink":"stdout","gateway_channel":"TOOL_RESULT","gateway_visibility":"DIRECT","flow_class":"STDOUT_EXPOSURE","credential_marker":"TEST_SECRET_AAAAAAAAAAAAAAAA","payload":"tool output: TEST_SECRET_AAAAAAAAAAAAAAAA","destination":"","tool_name":"skill_stdout","tool_arguments":{},"dynamic_confirmed":False,"evidence_type":"CATALOG_DERIVED","source_revision":"revA","sandbox_version":"catalog-derived-v1","trace_hash":"x","metadata":{}}
    good_line = json.dumps(good)
    (tmp_path / "traces.jsonl").write_text(good_line + "\nNOT JSON\n" + good_line + "\n", encoding="utf-8")
    sc = DatasetSourceConfig(name="credential_catalog_synthetic", adapter="credential_catalog_synthetic", source_type="derived", source_uri="x", revision="revA", raw_dir=str(tmp_path), normalized_dir=str(tmp_path / "norm"))
    ad = CredentialCatalogSyntheticAdapter(source_config=sc, raw_dir=tmp_path, strict=True)
    with pytest.raises(DatasetSourceError, match="line 2"):
        list(ad.iter_cases())


def test_analyzer_report_extended_marking():
    """Analyzer and markdown must mark extended as non-headline."""
    from demotest.analysis.analyzer import AnalysisReport
    from demotest.reporting.markdown import render_markdown
    rep = AnalysisReport(project="P4_credential_flow", benchmark_track="extended", headline_eligible=False)
    md = render_markdown(rep)
    assert "Extended Synthetic" in md
    assert "non-headline" in md.lower()
    assert "extended" in md.lower()
    rep2 = AnalysisReport(project="P1_external_instruction", benchmark_track="core", headline_eligible=True)
    md2 = render_markdown(rep2)
    assert "Extended" not in md2
