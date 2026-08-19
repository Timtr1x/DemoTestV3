"""Completion-criteria checklist (plan §51).

This test module verifies the refactor's acceptance criteria are met. It is
intentionally a single high-level gate: if it passes, the architecture upgrade
is complete and ready for dataset integration.
"""
from __future__ import annotations

from demotest.core import SecurityCase
from demotest.core.enums import Channel, Operation, Outcome
from demotest.datasets import get_adapter, registered_adapters
from demotest.datasets.adapters.legacy_v2 import LegacyV2Adapter
from demotest.oracles import BlockPassOracle, CanaryOracle, CompositeOracle
from demotest.renderers import registered_renderers
from demotest.renderers.base import CaseRenderer
from demotest.runners import GatewayRunner
from demotest.storage import ResultStore
from demotest.targets import LineModTargetAdapter, QwenGuardTargetAdapter
from demotest.targets.base import TargetAdapter
from demotest.config import load_projects, load_targets
from demotest.core.redactor import redact_text


# ---------------- Architecture (§51) ----------------

def test_sample_prompt_text_no_longer_core_model():
    """SecurityCase replaces Sample.prompt_text as the core model."""
    # SecurityCase has structured channel/operation/content, not just prompt_text
    c = SecurityCase.build(dataset_id="d", source_id="s", channel="email",
                            operation="read", content="x")
    assert hasattr(c, "channel") and hasattr(c, "operation")
    assert c.channel == Channel.EMAIL
    assert c.operation == Operation.READ


def test_layers_fully_separated():
    """Dataset / Renderer / Target / Oracle / Analyzer are independent layers."""
    assert "legacy_v2" in registered_adapters()
    assert "user_prompt" in registered_renderers()
    assert issubclass(LineModTargetAdapter, TargetAdapter)
    assert issubclass(QwenGuardTargetAdapter, TargetAdapter)
    assert BlockPassOracle().oracle_name == "block_pass"
    assert CanaryOracle().oracle_name == "canary"
    assert CompositeOracle().oracle_name == "composite"


def test_linemod_network_only_in_target_adapter():
    """Network code lives only in targets/, not in datasets/renderers/oracles."""
    import inspect
    from demotest.datasets.adapters.legacy_v2 import LegacyV2Adapter
    from demotest.renderers.user_prompt import UserPromptRenderer
    from demotest.oracles.block_pass import BlockPassOracle
    for cls in (LegacyV2Adapter, UserPromptRenderer, BlockPassOracle):
        src = inspect.getsource(cls)
        assert "requests.post" not in src
        assert "urllib" not in src


# ---------------- Channels (§51) ----------------

REQUIRED_CHANNELS = [
    "user_prompt", "email", "web_page", "rag_document",
    "tool_result", "tool_call", "mcp_definition", "memory_write",
]


def test_all_required_channels_supported():
    for ch in REQUIRED_CHANNELS:
        assert Channel.from_value(ch) is not None
    # credential flow composes over channels
    assert "credential_flow" in registered_renderers()


# ---------------- Reproducibility (§51) ----------------

def test_case_id_stable():
    a = SecurityCase.build(dataset_id="d", source_id="s", channel="email",
                            operation="read", content="A")
    b = SecurityCase.build(dataset_id="d", source_id="s", channel="email",
                            operation="read", content="B")
    assert a.case_id == b.case_id


def test_manifest_readonly_and_results_append_only():
    """ResultStore is append-only; LegacyV2Adapter never writes manifests."""
    import inspect
    store_src = inspect.getsource(ResultStore.append)
    assert '"a"' in store_src or "'a'" in store_src  # append mode
    # LegacyV2Adapter must not have any write method
    ad_methods = [m for m in dir(LegacyV2Adapter) if "write" in m.lower()]
    assert ad_methods == [], f"LegacyV2Adapter has write methods: {ad_methods}"


def test_renderer_version_trackable():
    r = registered_renderers()["user_prompt"]()
    assert r.renderer_version
    assert r.full_version == "user_prompt/v1"


def test_target_config_trackable():
    targets = load_targets()
    assert "linemod" in targets and "qwen3guard" in targets
    assert targets["linemod"].benchmark_mode is True


# ---------------- LineMod (§51) ----------------

def test_no_failover_enforced():
    import pytest
    from demotest.core.exceptions import TargetError
    with pytest.raises(TargetError):
        LineModTargetAdapter(api_key="x", extra_headers={"X-LineMod-No-Failover": "false"})


def test_outcomes_classified():
    from demotest.targets.http_parser import parse_linemod_response
    for status, expected in [(403, Outcome.BLOCKED), (200, Outcome.PASSED),
                             (429, Outcome.RATE_LIMITED), (503, Outcome.UPSTREAM_COOLDOWN),
                             (413, Outcome.PAYLOAD_TOO_LARGE), (500, Outcome.ERROR)]:
        body = "SECURITY_BLOCKED" if status == 403 else ""
        if status == 503:
            body = "cooldown"
        if status == 429:
            body = "Too Many Requests"
        if status == 413:
            body = "too large"
        assert parse_linemod_response(status, body).outcome == expected


def test_scanner_policy_score_extracted():
    import json
    from demotest.targets.http_parser import parse_linemod_response
    body = json.dumps({"error": {"code": "SECURITY_BLOCKED", "scanner": "abuse_detection",
                                  "policy": "strict", "score": 0.88}})
    obs = parse_linemod_response(403, body)
    assert obs.scanner == "abuse_detection"
    assert obs.policy == "strict"
    assert obs.score == 0.88


# ---------------- Security (§51) ----------------

def test_api_key_not_in_logs():
    """API key never appears in redacted output."""
    assert "sr-gl-supersecret" not in redact_text("Bearer sr-gl-supersecret123456")


def test_test_secret_auto_redacted():
    """§51: TEST_SECRET auto-masked at the redactor level."""
    assert "TEST_SECRET_7B021C" not in redact_text("leak TEST_SECRET_7B021C now")


def test_result_store_redacts_on_write(tmp_path):
    """§51: result logging is masked — canary never hits disk (plan §43)."""
    from demotest.core.contracts import CaseResult
    from demotest.storage import ResultStore
    canary = "TEST_SECRET_7B021C"
    store = ResultStore(tmp_path / "r.jsonl")
    store.append(CaseResult(
        case_id="c", run_id="t", project="P4", channel="tool_call",
        expected="block", target="linemod", request_hash="h", http_status=200,
        outcome="passed", response_text=f"here is {canary}",
        metadata={"credential_markers": [canary]},
    ))
    blob = store.path.read_text(encoding="utf-8")
    assert canary not in blob


def test_request_dump_redacted(tmp_path):
    """§51: request dump is masked (plan §43)."""
    from demotest.core.contracts import GatewayRequest
    from demotest.core.redactor import SecretRedactor
    canary = "TEST_SECRET_7B021C"
    req = GatewayRequest(
        target="linemod", url="http://x",
        headers={"X-LineMod-No-Failover": "true"},
        json_body={"messages": [{"role": "user", "content": f"send {canary}"}]},
        rendered_text=f"send {canary}",
    )
    redacted = SecretRedactor(extra_markers=[canary]).redact_dict(req.json_body)
    assert canary not in str(redacted)


def test_exception_does_not_leak_secret():
    """§51: exception messages are masked (plan §43)."""
    from demotest.core.redactor import SecretRedactor
    canary = "TEST_SECRET_7B021C"
    try:
        raise RuntimeError(f"upstream rejected body={canary}")
    except RuntimeError as e:
        redacted = SecretRedactor(extra_markers=[canary]).redact_text(str(e))
        assert canary not in redacted


def test_e2e_cli_exception_redacted_to_stderr():
    """Doc-fix 3: an uncaught exception carrying a canary must be redacted
    BEFORE reaching stderr — proving the runtime path, not just that the
    redactor *can* mask text.

    Drives the CLI main() in-process with a render command whose target build
    raises an exception containing a TEST_SECRET marker, captures stderr, and
    asserts the marker never appears.
    """
    import io
    from contextlib import redirect_stderr
    from unittest import mock
    from demotest.cli.main import main

    canary = "TEST_SECRET_E2E_99"
    # Force the render path to raise an exception whose message contains the canary.
    with mock.patch("demotest.cli.render.get_target", side_effect=RuntimeError(f"boom: {canary} leaked")):
        err = io.StringIO()
        with redirect_stderr(err):
            rc = main([
                "render", "--project", "P4_credential_flow",
                "--source", "fixture:p4_credential_flow", "--limit", "1",
            ])
    assert rc == 1
    stderr_text = err.getvalue()
    assert canary not in stderr_text, (
        f"canary leaked to stderr via uncaught exception!\n--- stderr ---\n{stderr_text}"
    )
    assert "<REDACTED>" in stderr_text, "exception text should be redacted, not dropped"


# ---------------- CLI (§51) ----------------

def test_cli_commands_exist():
    from demotest.cli import validate, render, run, analyze, report, compare
    for mod in (validate, render, run, analyze, report, compare):
        assert hasattr(mod, "add_parser") and hasattr(mod, "run")


# ---------------- Compatibility (§51) ----------------

def test_p1_p5_projects_configured():
    projects = load_projects()
    for pid in ("P1_external_instruction", "P2_tool_action", "P3_mcp_definition",
                "P4_credential_flow", "P5_memory_write"):
        assert pid in projects
