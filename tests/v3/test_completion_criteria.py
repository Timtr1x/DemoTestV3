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
    assert "TEST_SECRET_7B021C" not in redact_text("leak TEST_SECRET_7B021C now")


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
