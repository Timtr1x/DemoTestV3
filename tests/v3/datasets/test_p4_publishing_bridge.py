"""P4 Dataset Publishing Bridge — end-to-end (no Dynamic acquisition required).

Proves the decoupling contract end to end:

    human-frozen reviewed_traces.jsonl + review_meta.json
      -> dataset prepare (CredentialDynamicTracesAdapter)
      -> normalized/cases.jsonl (committed under benchmarks/frozen/...)
      -> manifest build
      -> load_frozen_manifest_cases

through the SAME V3 pipeline as any dataset, with a sys.modules guardian that
RAISES if any Dynamic-acquisition module is even imported. This is the guarantee
that a frozen P4 dataset runs with zero Docker / SkillsMP / SkillLeakBench /
candidate / snapshot / credential binding.
"""
from __future__ import annotations

import contextlib
import json
import sys
import types
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parents[3] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from demotest.config import get_dataset  # noqa: E402
from demotest.datasets.manifest_builder import build_manifest, write_manifest  # noqa: E402

DYNAMIC_MODULES = [
    "demotest.datasets.dynamic",
    "demotest.datasets.dynamic.sandbox",
    "demotest.datasets.dynamic.skillleak_collector",
    "demotest.datasets.dynamic.candidates",
    "demotest.datasets.dynamic.snapshot",
    "demotest.datasets.dynamic.credential_bindings",
    "demotest.datasets.dynamic.review",
    "demotest.datasets.dynamic.split",
    "demotest.datasets.dynamic.markers",
    "demotest.datasets.dynamic.parser",
    "demotest.datasets.dynamic.schemas",
    "demotest.datasets.dynamic.session",
    "demotest.datasets.dynamic.workspace",
]


def _guard() -> None:
    """Install raising sentinels so any Dynamic import fails loudly."""
    for name in DYNAMIC_MODULES:
        sentinel = types.ModuleType(name)
        sentinel.__getattr__ = lambda attr: (_ for _ in ()).throw(
            RuntimeError(f"Dynamic acquisition module '{name}' must not be imported by benchmark path")
        )
        sentinel.__path__ = []
        sys.modules[name] = sentinel


@contextlib.contextmanager
def _no_dynamic_guard():
    """Assert the benchmark path never imports Dynamic-acquisition modules.

    Installs raising sentinels for each Dynamic module, runs the block, and
    restores the real modules afterward so later tests are unaffected.
    """
    saved = {name: sys.modules.get(name) for name in DYNAMIC_MODULES}
    _guard()
    try:
        yield
    finally:
        for name, mod in saved.items():
            if mod is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = mod



def test_p4_dataset_is_in_manifest_project_mapping():
    from demotest.cli import manifest as m

    assert "credential_dynamic_traces" in m._DATASETS_BY_PROJECT["P4_credential_flow"]


def test_frozen_reviewed_artifact_committed_and_valid():
    ds = get_dataset("credential_dynamic_traces")
    rp = ds.raw_path / "reviews" / "reviewed_traces.jsonl"
    mp = ds.raw_path / "reviews" / "review_meta.json"
    assert rp.exists(), "reviewed artifact must be committed under benchmarks/frozen"
    assert mp.exists(), "review_meta must be committed under benchmarks/frozen"
    from demotest.datasets.adapters.credential_dynamic_traces import CredentialDynamicTracesAdapter

    ad = CredentialDynamicTracesAdapter(source_config=ds)
    rep = ad.validate_raw()
    assert rep.ok, f"validate_raw failed: {rep.errors}"


def test_end_to_end_publish_bridge_no_dynamic():
    from demotest.cli import _dataset_pipeline as pipeline
    from demotest.cases import load_frozen_manifest_cases

    ds = get_dataset("credential_dynamic_traces")

    # 1) normalize the reviewed artifact (idempotent, offline)
    report = pipeline.prepare_dataset(ds)
    assert report.n_kept >= 1
    norm = pipeline.load_normalized(ds)
    assert norm, "no normalized cases produced"
    for c in norm:
        src = (c.metadata or {}).get("source", {})
        assert c.dataset_id == "credential_dynamic_traces"
        assert c.project_id == "P4_credential_flow"
        assert src.get("quality_tier") in ("A", "B")
        assert src.get("derivation") in ("original", "deterministic_projection")

    # 2) build + write a manifest containing the frozen P4 case
    m = build_manifest(
        suite_id="p4-bridge-test", project_id="P4_credential_flow",
        cases=norm, seed=42, split=["dev", "eval", "holdout"], target=1,
        benchmark_track="core",
    )
    assert m["n"] >= 1, "manifest must select the frozen P4 case"
    fname = "p4-bridge-test-" + m["manifest_sha256"].replace(":", "-") + ".json"
    out = write_manifest(m, Path(__file__).resolve().parents[3] / "cache" / fname)

    # 3) resolve the manifest through the standard path — must NOT touch Dynamic.
    try:
        loaded = None
        with _no_dynamic_guard():  # any Dynamic import now raises RuntimeError
            from demotest.cases import load_frozen_manifest_cases

            loaded = load_frozen_manifest_cases(str(out), project="P4_credential_flow")
    finally:
        out.unlink(missing_ok=True)
    assert loaded
    wanted = {e["case_id"] for e in m["cases"]}
    assert {c.case_id for c in loaded} == wanted
    assert loaded[0].metadata["source"]["quality_tier"] in ("A", "B")


def test_adapter_fail_closed_on_reviewed_artifact(tmp_path: Path):
    from demotest.datasets.adapters.credential_dynamic_traces import CredentialDynamicTracesAdapter
    from demotest.core.exceptions import DatasetSourceError

    ad = CredentialDynamicTracesAdapter(raw_dir=tmp_path, strict=True)
    # no artifact -> fail closed
    with pytest.raises(DatasetSourceError, match="reviewed artifact invalid"):
        list(ad.iter_cases())

    # build a valid reviewed artifact, then tamper each integrity gate
    from demotest.datasets.traces.models import CredentialTrace
    from demotest.datasets.dynamic.review import TraceReview, freeze_reviewed_traces

    tr = CredentialTrace(
        trace_id="d1", skill_id="sk", skill_name="sk", issue_id="OPENAI_API_KEY",
        academic_code="DYNAMIC", pattern="STDOUT_EXPOSURE",
        classification="Information Exposure", severity="high",
        sink="stdout", gateway_channel="TOOL_RESULT", gateway_visibility="DIRECT",
        flow_class="STDOUT_EXPOSURE", credential_marker="TEST_SECRET_AAAABBBBCCCCDDDD",
        payload="hi TEST_SECRET_AAAABBBBCCCCDDDD",
        evidence_type="DYNAMIC_TRACE", dynamic_confirmed=True,
        source_revision="rev", sandbox_version="img", trace_hash="sha256:abc",
        metadata={"skill_snapshot_sha256": "s" * 64, "execution_condition": "deterministic",
                  "sandbox_image_digest": "img", "pipeline_revision": "rev"},
    )
    reviews = [TraceReview(trace_id="d1", review_status="ACCEPTED",
                           source_real=True, dynamic_execution_real=True,
                           fake_credential_confirmed=True, marker_observed=True,
                           sink_confirmed=True, gateway_projection_valid=True,
                           expected_action_valid=True)]
    freeze_reviewed_traces([tr], raw_dir=tmp_path, reviews=reviews)
    # valid base
    ad = CredentialDynamicTracesAdapter(raw_dir=tmp_path, strict=True)
    assert len(list(ad.iter_cases())) == 1

    # SHA drift
    meta_p = tmp_path / "reviews" / "review_meta.json"
    meta = json.loads(meta_p.read_text(encoding="utf-8"))
    meta["sha256"] = "0" * 64
    meta_p.write_text(json.dumps(meta), encoding="utf-8")
    with pytest.raises(DatasetSourceError, match="SHA"):
        list(CredentialDynamicTracesAdapter(raw_dir=tmp_path, strict=True).iter_cases())

    # pending != 0
    meta["sha256"] = __import__("hashlib").sha256(
        (tmp_path / "reviews" / "reviewed_traces.jsonl").read_bytes()).hexdigest()
    meta["n_pending"] = 3
    meta_p.write_text(json.dumps(meta), encoding="utf-8")
    with pytest.raises(DatasetSourceError, match="n_pending"):
        list(CredentialDynamicTracesAdapter(raw_dir=tmp_path, strict=True).iter_cases())
