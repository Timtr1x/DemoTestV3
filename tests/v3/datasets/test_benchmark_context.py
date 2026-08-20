"""P0 report bypass + run provenance tests."""
from pathlib import Path
import json
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))

from demotest.datasets.context import resolve_benchmark_context


def test_report_and_analyze_share_resolver():
    src = Path("src/demotest/cli/report.py").read_text(encoding="utf-8")
    assert "resolve_benchmark_context" in src
    src2 = Path("src/demotest/cli/analyze.py").read_text(encoding="utf-8")
    assert "resolve_benchmark_context" in src2


def test_extended_manifest_resolves_extended():
    ctx = resolve_benchmark_context("manifest:benchmarks/manifests/phase2-smoke-v1/p4.json", project="P4_credential_flow")
    assert ctx.benchmark_track == "extended"
    assert ctx.headline_eligible is False
    assert ctx.manifest_sha256 is not None


def test_legacy_phase1_no_track_compat_core():
    ctx = resolve_benchmark_context("manifest:benchmarks/manifests/smoke-v2/p1.json", project="P1_external_instruction")
    assert ctx.benchmark_track == "core"
    assert ctx.headline_eligible is True


def test_invalid_track_fail_closed(tmp_path: Path):
    import json as _js
    j = _js.loads(Path("benchmarks/manifests/phase2-smoke-v1/p4.json").read_text(encoding="utf-8"))
    j["benchmark_track"] = "extneded"
    # write without updating manifest_sha256 to trigger verify failure
    p = tmp_path / "bad.json"
    p.write_text(_js.dumps(j), encoding="utf-8")
    try:
        resolve_benchmark_context(f"manifest:{p}", project="P4_credential_flow")
        assert False, "should have raised"
    except Exception as e:
        assert "benchmark_track" in str(e).lower() or "verify" in str(e).lower()


def test_run_writes_meta(tmp_path: Path):
    # dry-run should still write _run_meta.json
    from demotest.cli.run import run as run_cmd
    import types
    args = types.SimpleNamespace(
        project="P1_external_instruction",
        target="linemod",
        source="manifest:benchmarks/manifests/smoke-v2/p1.json",
        run_version="test-provenance-1",
        gap=0.01, dry_run=True, max_attempts=1, fidelity="auto",
    )
    rc = run_cmd(args)
    assert rc == 0
    meta = Path(f"cache/results_v3/P1_external_instruction/linemod/test-provenance-1/_run_meta.json")
    assert meta.exists()
    j = json.loads(meta.read_text(encoding="utf-8"))
    assert j["manifest_sha256"] is not None
    assert j["benchmark_track"] == "core"
