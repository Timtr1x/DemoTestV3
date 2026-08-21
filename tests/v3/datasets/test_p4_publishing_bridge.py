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


@contextlib.contextmanager
def _no_dynamic_guard():
    """Assert the benchmark path never imports Dynamic-acquisition modules.

    Order is load-bearing:
      1. Purge every already-imported ``demotest.*`` module so the benchmark
         path must be imported FRESH inside the guard (no cached-module
         shortcuts hiding an acquisition dependency). This must happen BEFORE
         the sentinels are installed — purging after would delete them.
      2. Install raising sentinels for each Dynamic acquisition module, so any
         fresh import attempt fails loudly.
    All ``sys.modules`` entries are restored afterward for later tests.
    """
    saved_all = dict(sys.modules)
    for name in [n for n in list(sys.modules) if n == "demotest" or n.startswith("demotest.")]:
        del sys.modules[name]
    for name in DYNAMIC_MODULES:
        sentinel = types.ModuleType(name)
        sentinel.__getattr__ = lambda attr, _n=name: (_ for _ in ()).throw(
            RuntimeError(f"Dynamic acquisition module '{_n}' must not be imported by benchmark path")
        )
        sentinel.__path__ = []
        sys.modules[name] = sentinel
    try:
        yield
    finally:
        sys.modules.clear()
        sys.modules.update(saved_all)



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

    # sha256 missing entirely — must also fail closed (no empty-string pass-through)
    meta["n_pending"] = 0
    meta["n_accepted"] = 1
    del meta["sha256"]
    meta_p.write_text(json.dumps(meta), encoding="utf-8")
    with pytest.raises(DatasetSourceError, match="sha256 is missing"):
        list(CredentialDynamicTracesAdapter(raw_dir=tmp_path, strict=True).iter_cases())


def test_full_chain_no_dynamic_frozen_manifest(monkeypatch, tmp_path: Path):
    """Frozen manifest -> validate -> render -> HTTP run -> analyze -> report.

    Every command goes through the REAL ``demotest.cli.main.main([...])``
    (argparse parser + dispatcher, not module functions), inside the purge+
    guard context (fresh demotest imports + raising sentinels), and the run
    POSTs to a local scripted gateway reusing tests/v3/contract/fake_server.py
    (blocked_body) — no sockets to real services, no Docker, no SkillsMP, no
    SkillLeakBench, no candidate/snapshot/credential binding.
    """
    import http.server
    import os
    import threading
    import time

    _contract = Path(__file__).resolve().parents[1] / "contract"
    if str(_contract) not in sys.path:
        sys.path.insert(0, str(_contract))
    from fake_server import blocked_body  # tests/v3/contract/fake_server.py

    manifest = (Path(__file__).resolve().parents[3]
                / "benchmarks" / "manifests" / "p4-core-bridge-v1" / "p4.json")
    source = f"manifest:{manifest}"

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 — always block
            body = blocked_body(scanner="guardrail").encode()
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args) -> None:  # quiet
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setenv("LINEMOD_URL", f"http://127.0.0.1:{port}/v1/chat/completions")
    monkeypatch.setenv("LINEMOD_API_KEY", "test-key")
    monkeypatch.setenv("LINEMOD_MODEL", "test-model")
    run_version = f"p4-bridge-it-{os.getpid()}-{time.time_ns()}"
    out_dir = tmp_path / "report"
    try:
        with _no_dynamic_guard():  # any Dynamic import now raises RuntimeError
            from demotest.cli.main import main

            def step(name: str, argv: list[str]) -> None:
                rc = main(argv)
                assert rc == 0, f"demotest {name} returned rc={rc} (expected 0)"

            step("validate", ["validate", "--project", "P4_credential_flow",
                              "--target", "linemod", "--source", source,
                              "--no-key-check"])
            step("render", ["render", "--project", "P4_credential_flow",
                            "--source", source, "--limit", "1",
                            "--target", "linemod", "--show-request"])
            step("run", ["run", "--project", "P4_credential_flow",
                         "--target", "linemod", "--source", source,
                         "--run-version", run_version, "--gap", "0.0",
                         "--max-attempts", "4"])
            step("analyze", ["analyze", "--project", "P4_credential_flow",
                             "--source", source, "--target", "linemod",
                             "--run-version", run_version])
            step("report", ["report", "--project", "P4_credential_flow",
                            "--source", source, "--target", "linemod",
                            "--run-version", run_version,
                            "--out-dir", str(out_dir)])
    finally:
        srv.shutdown()
        srv.server_close()

    summary = out_dir / "SUMMARY.md"
    assert summary.exists(), "report SUMMARY.md was not written"
    text = summary.read_text(encoding="utf-8")
    assert "TP=`1`" in text and "TPR=`100.00%`" in text
    assert "headline_eligible=`false`" in text


def test_dynamic_cli_lazy_registration_intact(capsys):
    """Lazy registration must keep `dynamic ...` usable AND keep benchmark
    invocations Dynamic-free at the dispatcher level.

      1. ``main(["dynamic", "--help"])`` exits SystemExit(0) only if the
         subcommand was registered on demand — argparse would exit 2 with
         "invalid choice" otherwise.
      2. A benchmark invocation (render --help) must register nothing and
         import zero demotest.datasets.dynamic.* modules.
    """
    from demotest.cli.main import main

    with pytest.raises(SystemExit) as ei:
        main(["dynamic", "--help"])
    assert ei.value.code == 0
    out = capsys.readouterr().out
    assert "candidates" in out, "dynamic help lost its acquisition subcommands"
    assert "review-apply" in out, "dynamic help lost its review subcommands"

    # Drop what `dynamic --help` cached, so the delta below is decisive —
    # otherwise the sentinel modules would already be in `before`.
    for name in [n for n in list(sys.modules)
                 if n == "demotest.datasets.dynamic" or n.startswith("demotest.datasets.dynamic.")]:
        del sys.modules[name]
    before = set(sys.modules)
    with pytest.raises(SystemExit) as ei2:
        main(["render", "--help"])
    assert ei2.value.code == 0
    capsys.readouterr()
    leaked = [k for k in set(sys.modules) - before
              if k == "demotest.datasets.dynamic"
              or k.startswith("demotest.datasets.dynamic.")]
    assert not leaked, f"benchmark CLI imported Dynamic-acquisition modules: {leaked}"


def test_frozen_manifest_not_headline_single_real_case():
    """p4-core-bridge-v1 covers 1 real reviewed trace — core track but NOT headline,
    and its provenance must not imply a Core/Synthetic mixed pool."""
    import json as _json

    from demotest.datasets.manifest_builder import load_manifest

    m = load_manifest(
        Path(__file__).resolve().parents[3] / "benchmarks" / "manifests" / "p4-core-bridge-v1" / "p4.json"
    )
    assert m["benchmark_track"] == "core"
    assert m["headline_eligible"] is False
    assert m["n"] >= 1
    # every entry is from the real dataset
    for e in m["cases"]:
        assert e["dataset_id"] == "credential_dynamic_traces"
    # created_from provenance: only the dataset that actually contributes cases
    cf = m.get("created_from") or {}
    assert "credential_dynamic_traces" in cf
    assert "credential_catalog_synthetic" not in cf
    assert "credential_traces" not in cf
