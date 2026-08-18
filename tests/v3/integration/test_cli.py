"""CLI + fixtures integration tests (Commit 14-16)."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
SRC = REPO / "src"


def _run_cli(*args, env_extra=None):
    import os
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SRC) + os.pathsep + env.get("PYTHONPATH", "")
    if env_extra:
        env.update(env_extra)
    r = subprocess.run(
        [sys.executable, "-m", "demotest.cli.main", *args],
        capture_output=True, text=True, cwd=str(REPO), env=env,
    )
    return r


def test_validate_p1_fixture():
    r = _run_cli("validate", "--project", "P1_external_instruction",
                 "--source", "fixture:p1_external_instruction", "--no-key-check")
    assert r.returncode == 0, r.stderr
    assert "cases=5" in r.stdout


def test_validate_rejects_unknown_project():
    r = _run_cli("validate", "--project", "NOPE",
                 "--source", "fixture:p1_external_instruction", "--no-key-check")
    assert r.returncode != 0
    assert "NOPE" in r.stderr


def test_render_p1_email():
    r = _run_cli("render", "--project", "P1_external_instruction",
                 "--source", "fixture:p1_external_instruction", "--limit", "1")
    assert r.returncode == 0, r.stderr
    assert "channel=email" in r.stdout
    assert "[UNTRUSTED_EXTERNAL_CONTENT]" in r.stdout
    assert "source_type: email" in r.stdout


def test_render_p2_tool_call_with_request():
    r = _run_cli("render", "--project", "P2_tool_action",
                 "--source", "fixture:p2_tool_action", "--limit", "1", "--show-request")
    assert r.returncode == 0, r.stderr
    assert "[TOOL_CALL_REQUEST]" in r.stdout
    assert "delete_server" in r.stdout
    assert "request_hash:" in r.stdout


def test_run_dry_run_p5():
    r = _run_cli("run", "--project", "P5_memory_write",
                 "--source", "fixture:p5_memory_write", "--dry-run")
    assert r.returncode == 0, r.stderr
    assert "dry-run=3" in r.stdout
    assert "dry_run=True" in r.stdout


def test_run_dry_run_p4_credential():
    r = _run_cli("run", "--project", "P4_credential_flow",
                 "--source", "fixture:p4_credential_flow", "--dry-run")
    assert r.returncode == 0, r.stderr
    # P4 cases span 2 channels (memory_write + tool_call); total ran=3
    assert "ran=3" in r.stdout
    assert "dry_run=True" in r.stdout


def test_all_p1_p5_fixtures_load_and_validate():
    """plan §40-44: each project has acceptance fixtures that load + pass validate."""
    for proj, fixture in [
        ("P1_external_instruction", "fixture:p1_external_instruction"),
        ("P2_tool_action", "fixture:p2_tool_action"),
        ("P3_mcp_definition", "fixture:p3_mcp_definition"),
        ("P4_credential_flow", "fixture:p4_credential_flow"),
        ("P5_memory_write", "fixture:p5_memory_write"),
    ]:
        r = _run_cli("validate", "--project", proj, "--source", fixture, "--no-key-check")
        assert r.returncode == 0, f"{proj} validate failed: {r.stderr}"


def test_case_ids_unique_within_fixture():
    from demotest.cases import load_fixture_cases, validate_case_ids_unique
    for name in ("p1_external_instruction", "p2_tool_action", "p3_mcp_definition",
                 "p4_credential_flow", "p5_memory_write"):
        cases = load_fixture_cases(name)
        validate_case_ids_unique(cases)  # raises on dup
        assert len(cases) >= 2
