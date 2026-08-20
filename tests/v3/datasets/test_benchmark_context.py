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
        adopt_legacy_run=False,
    )
    rc = run_cmd(args)
    assert rc == 0
    meta = Path(f"cache/results_v3/P1_external_instruction/linemod/test-provenance-1/_run_meta.json")
    assert meta.exists()
    j = json.loads(meta.read_text(encoding="utf-8"))
    assert j["manifest_sha256"] is not None
    assert j["benchmark_track"] == "core"
    assert "experiment_hash" in j
    assert "fidelity" in j
    import shutil
    shutil.rmtree(meta.parent, ignore_errors=True)


def test_run_preflight_rejects_different_experiment(tmp_path: Path):
    """Existing run dir with different experiment_hash must fail before resume."""
    from demotest.cli.run import run as run_cmd
    import types
    # First run
    args = types.SimpleNamespace(
        project="P1_external_instruction", target="linemod",
        source="manifest:benchmarks/manifests/smoke-v2/p1.json",
        run_version="test-preflight-1", gap=0.01, dry_run=True, max_attempts=1,
        fidelity="auto", adopt_legacy_run=False,
    )
    assert run_cmd(args) == 0
    # Second run with different fidelity → different experiment_hash
    args2 = types.SimpleNamespace(
        project="P1_external_instruction", target="linemod",
        source="manifest:benchmarks/manifests/smoke-v2/p1.json",
        run_version="test-preflight-1", gap=0.01, dry_run=True, max_attempts=1,
        fidelity="labeled", adopt_legacy_run=False,
    )
    rc = run_cmd(args2)
    assert rc == 1, "should reject different experiment_hash"
    import shutil
    from demotest.paths import RESULTS_DIR as _RD
    shutil.rmtree(_RD / "P1_external_instruction" / "linemod" / "test-preflight-1", ignore_errors=True)


def test_run_preflight_rejects_missing_meta_with_results(tmp_path: Path):
    """Run dir with results but no meta must fail (unknown provenance)."""
    from demotest.cli.run import run as run_cmd
    import types
    from demotest.paths import RESULTS_DIR
    base = RESULTS_DIR / "P1_external_instruction" / "linemod" / "test-preflight-nometa"
    base.mkdir(parents=True, exist_ok=True)
    (base / "email.jsonl").write_text("{}\n", encoding="utf-8")
    args = types.SimpleNamespace(
        project="P1_external_instruction", target="linemod",
        source="manifest:benchmarks/manifests/smoke-v2/p1.json",
        run_version="test-preflight-nometa", gap=0.01, dry_run=True, max_attempts=1,
        fidelity="auto", adopt_legacy_run=False,
    )
    rc = run_cmd(args)
    assert rc == 1, "should reject run dir with results but no meta"
    # cleanup
    import shutil
    shutil.rmtree(base, ignore_errors=True)


def test_analyze_missing_meta_fails_for_manifest():
    from demotest.cli.analyze import run as analyze_cmd
    import types
    args = types.SimpleNamespace(
        project="P4_credential_flow", target="linemod",
        source="manifest:benchmarks/manifests/phase2-smoke-v1/p4.json",
        run_version="nonexistent-run", json=False, allow_legacy_run_without_meta=False,
    )
    rc = analyze_cmd(args)
    assert rc == 1, "should fail without meta"


def test_compare_requires_same_manifest(tmp_path: Path):
    """Compare with mismatched manifest SHA must fail."""
    from demotest.cli.compare import run as compare_cmd
    import types
    # use same run twice but corrupt meta SHA for one side
    from demotest.paths import RESULTS_DIR
    base = RESULTS_DIR / "P1_external_instruction" / "linemod" / "test-cmp-1"
    base.mkdir(parents=True, exist_ok=True)
    (base / "email.jsonl").write_text("{}\n", encoding="utf-8")
    (base / "_run_meta.json").write_text(json.dumps({
        "manifest_sha256": "sha256:bad", "project": "P1_external_instruction",
        "target": "linemod", "run_version": "test-cmp-1",
    }), encoding="utf-8")
    args = types.SimpleNamespace(
        project="P1_external_instruction", source="manifest:benchmarks/manifests/smoke-v2/p1.json",
        run_a="linemod/test-cmp-1", run_b="linemod/test-cmp-1", json=False,
        allow_legacy_run_without_meta=False,
    )
    rc = compare_cmd(args)
    assert rc == 1, "should reject mismatched manifest SHA"
    import shutil
    shutil.rmtree(base, ignore_errors=True)


# --- Review 6fba07e: real behavior regression tests -------------------------

def _ctx_p1():
    return resolve_benchmark_context(
        "manifest:benchmarks/manifests/smoke-v2/p1.json", project="P1_external_instruction")


def test_fixture_source_is_adhoc_never_headline():
    ctx = resolve_benchmark_context("fixture:whatever", project="P1_external_instruction")
    assert ctx.benchmark_track == "adhoc"
    assert ctx.headline_eligible is False
    assert ctx.manifest_path is None
    assert ctx.manifest_sha256 is None
    ctx2 = resolve_benchmark_context("legacy:v2-something", project="P1_external_instruction")
    assert ctx2.benchmark_track == "adhoc"
    assert ctx2.headline_eligible is False


def test_verify_run_meta_corrupt_fails(tmp_path: Path):
    from demotest.datasets.context import verify_run_meta
    from demotest.core.exceptions import ManifestError
    (tmp_path / "_run_meta.json").write_text("{not json", encoding="utf-8")
    try:
        verify_run_meta(tmp_path, _ctx_p1(), expected_project="P1_external_instruction",
                        expected_target="linemod", expected_run_version="v1")
        assert False, "corrupt meta must fail"
    except ManifestError as e:
        assert "corrupt" in str(e).lower()


def test_verify_run_meta_sha_mismatch_fails(tmp_path: Path):
    from demotest.datasets.context import verify_run_meta
    from demotest.core.exceptions import ManifestError
    (tmp_path / "_run_meta.json").write_text(json.dumps({
        "manifest_sha256": "sha256:" + "0" * 64, "project": "P1_external_instruction",
        "target": "linemod", "run_version": "v1",
    }), encoding="utf-8")
    try:
        verify_run_meta(tmp_path, _ctx_p1(), expected_project="P1_external_instruction",
                        expected_target="linemod", expected_run_version="v1")
        assert False, "sha mismatch must fail"
    except ManifestError as e:
        assert "mismatch" in str(e).lower()


def test_verify_run_meta_project_mismatch_fails(tmp_path: Path):
    from demotest.datasets.context import verify_run_meta
    from demotest.core.exceptions import ManifestError
    sha = _ctx_p1().manifest_sha256
    (tmp_path / "_run_meta.json").write_text(json.dumps({
        "manifest_sha256": sha, "project": "P4_credential_flow",
        "target": "linemod", "run_version": "v1",
    }), encoding="utf-8")
    try:
        verify_run_meta(tmp_path, _ctx_p1(), expected_project="P1_external_instruction",
                        expected_target="linemod", expected_run_version="v1")
        assert False, "project mismatch must fail"
    except ManifestError as e:
        assert "project" in str(e)


def test_verify_run_meta_target_mismatch_fails(tmp_path: Path):
    from demotest.datasets.context import verify_run_meta
    from demotest.core.exceptions import ManifestError
    sha = _ctx_p1().manifest_sha256
    (tmp_path / "_run_meta.json").write_text(json.dumps({
        "manifest_sha256": sha, "project": "P1_external_instruction",
        "target": "other-target", "run_version": "v1",
    }), encoding="utf-8")
    try:
        verify_run_meta(tmp_path, _ctx_p1(), expected_project="P1_external_instruction",
                        expected_target="linemod", expected_run_version="v1")
        assert False, "target mismatch must fail"
    except ManifestError as e:
        assert "target" in str(e)


def test_different_manifest_different_auto_run_id(tmp_path: Path, capsys):
    """Same cases, different manifest identity -> different auto run_id."""
    import json as _js
    import re
    import shutil
    import types
    from demotest.cli.run import run as run_cmd
    from demotest.datasets.manifest_builder import manifest_sha256
    from demotest.paths import RESULTS_DIR

    src_a = "manifest:benchmarks/manifests/smoke-v2/p1.json"
    m2 = _js.loads(Path("benchmarks/manifests/smoke-v2/p1.json").read_text(encoding="utf-8"))
    m2["variant_note"] = "test-second-manifest-identity"
    m2.pop("manifest_sha256", None)
    m2["manifest_sha256"] = manifest_sha256(m2)
    p2 = tmp_path / "p1-variant.json"
    p2.write_text(_js.dumps(m2, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def _mk(src):
        return types.SimpleNamespace(
            project="P1_external_instruction", target="linemod", source=src,
            run_version=None, gap=0.01, dry_run=True, max_attempts=1,
            fidelity="auto", adopt_legacy_run=False)

    assert run_cmd(_mk(src_a)) == 0
    rv_a = re.search(r"run_version=(\S+)", capsys.readouterr().out).group(1)
    assert run_cmd(_mk(f"manifest:{p2}")) == 0
    rv_b = re.search(r"run_version=(\S+)", capsys.readouterr().out).group(1)
    assert rv_a != rv_b, "different manifest identity must produce different auto run_id"
    for rv in (rv_a, rv_b):
        shutil.rmtree(RESULTS_DIR / "P1_external_instruction" / "linemod" / rv, ignore_errors=True)


def test_compare_b_wrong_manifest_fails(tmp_path: Path):
    """A side good, B side bad sha -> compare must fail on B."""
    import shutil
    import types
    from demotest.cli.compare import run as compare_cmd
    from demotest.paths import RESULTS_DIR

    sha = _ctx_p1().manifest_sha256
    root = RESULTS_DIR / "P1_external_instruction" / "linemod"
    base_a = root / "test-cmpB-goodA"
    base_b = root / "test-cmpB-badB"
    for base, msha in ((base_a, sha), (base_b, "sha256:" + "0" * 64)):
        base.mkdir(parents=True, exist_ok=True)
        (base / "email.jsonl").write_text("{}\n", encoding="utf-8")
        rv = base.name
        (base / "_run_meta.json").write_text(json.dumps({
            "manifest_sha256": msha, "project": "P1_external_instruction",
            "target": "linemod", "run_version": rv,
        }), encoding="utf-8")
    args = types.SimpleNamespace(
        project="P1_external_instruction",
        source="manifest:benchmarks/manifests/smoke-v2/p1.json",
        run_a="linemod/test-cmpB-goodA", run_b="linemod/test-cmpB-badB",
        json=False, allow_legacy_run_without_meta=False,
    )
    try:
        assert compare_cmd(args) == 1, "compare must fail when B binds to a different manifest"
    finally:
        shutil.rmtree(base_a, ignore_errors=True)
        shutil.rmtree(base_b, ignore_errors=True)


# --- Review d3a3bb3 housekeeping: adhoc validator + legacy experiment_hash --

def _minimal_result_row(run_version: str) -> dict:
    return {
        "case_id": "fixture-case-1", "run_id": run_version,
        "project": "P1_external_instruction", "channel": "email",
        "expected": "block", "target": "linemod", "request_hash": "x",
        "http_status": 200, "outcome": "block",
    }


def test_adhoc_fixture_run_and_analyze_ok(tmp_path: Path):
    """fixture: runs are adhoc (manifest_sha256=None) and must analyze fine."""
    import shutil
    import types
    from demotest.cli.run import run as run_cmd
    from demotest.cli.analyze import run as analyze_cmd
    from demotest.paths import RESULTS_DIR

    rv = "test-adhoc-1"
    base = RESULTS_DIR / "P1_external_instruction" / "linemod" / rv
    args = types.SimpleNamespace(
        project="P1_external_instruction", target="linemod",
        source="fixture:p1_external_instruction", run_version=rv,
        gap=0.01, dry_run=True, max_attempts=1, fidelity="auto",
        adopt_legacy_run=False,
    )
    try:
        assert run_cmd(args) == 0
        meta = json.loads((base / "_run_meta.json").read_text(encoding="utf-8"))
        assert meta["manifest_sha256"] is None
        assert meta["benchmark_track"] == "adhoc"
        assert meta["headline_eligible"] is False
        # add one result row, then analyze must pass provenance (regression:
        # validator used to reject adhoc for missing manifest_sha256)
        (base / "email.jsonl").write_text(
            json.dumps(_minimal_result_row(rv)) + "\n", encoding="utf-8")
        aargs = types.SimpleNamespace(
            project="P1_external_instruction", target="linemod",
            source="fixture:p1_external_instruction", run_version=rv,
            json=False, allow_legacy_run_without_meta=False,
        )
        assert analyze_cmd(aargs) == 0, "adhoc run must analyze without manifest SHA"
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_adhoc_run_binding_manifest_fails(tmp_path: Path):
    """An adhoc run whose meta suddenly carries a manifest SHA is corruption."""
    from demotest.datasets.context import verify_run_meta
    from demotest.core.exceptions import ManifestError
    ctx = resolve_benchmark_context("fixture:p1_external_instruction", project="P1_external_instruction")
    (tmp_path / "_run_meta.json").write_text(json.dumps({
        "manifest_sha256": "sha256:" + "1" * 64, "project": "P1_external_instruction",
        "target": "linemod", "run_version": "v1",
    }), encoding="utf-8")
    try:
        verify_run_meta(tmp_path, ctx, expected_project="P1_external_instruction",
                        expected_target="linemod", expected_run_version="v1")
        assert False, "adhoc run with manifest SHA must fail"
    except ManifestError as e:
        assert "adhoc" in str(e).lower()


def test_preflight_legacy_meta_without_experiment_hash_requires_adopt():
    """Old-style meta (no experiment_hash) must be explicitly adopted."""
    import shutil
    import types
    from demotest.cli.run import run as run_cmd
    from demotest.paths import RESULTS_DIR

    rv = "test-legacy-nohash"
    base = RESULTS_DIR / "P1_external_instruction" / "linemod" / rv
    base.mkdir(parents=True, exist_ok=True)
    (base / "email.jsonl").write_text(
        json.dumps(_minimal_result_row(rv)) + "\n", encoding="utf-8")
    (base / "_run_meta.json").write_text(json.dumps({
        "source": "manifest:benchmarks/manifests/smoke-v2/p1.json",
        "source_type": "manifest",
        "manifest": "benchmarks/manifests/smoke-v2/p1.json",
        "manifest_sha256": _ctx_p1().manifest_sha256,
        "benchmark_track": "core", "headline_eligible": True,
        "project": "P1_external_instruction", "target": "linemod",
        "run_version": rv,
        # no experiment_hash / no fidelity — pre-d3a3bb3 meta
    }), encoding="utf-8")

    def _mk(adopt):
        return types.SimpleNamespace(
            project="P1_external_instruction", target="linemod",
            source="manifest:benchmarks/manifests/smoke-v2/p1.json",
            run_version=rv, gap=0.01, dry_run=True, max_attempts=1,
            fidelity="auto", adopt_legacy_run=adopt)

    try:
        assert run_cmd(_mk(False)) == 1, "legacy meta without experiment_hash must fail"
        assert run_cmd(_mk(True)) == 0, "--adopt-legacy-run must allow the resume"
    finally:
        shutil.rmtree(base, ignore_errors=True)
