"""Ensure runner owns REQUEST_GAP and default client disables client throttle."""
from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.registry import BaseProject  # noqa: E402
from core.runner import run_manifest  # noqa: E402
from core.sampler import build_manifest  # noqa: E402
from core.schema import Sample  # noqa: E402


def test_default_client_disables_client_throttle():
    """Production default client must call test_linemod(..., do_throttle=False)."""
    class P(BaseProject):
        project_id = "e_test"

        def build_samples_for_manifest(self, spec):
            return [], {}

    p = P(config={"manifests": []})
    seen = {}

    def fake_test_linemod(prompt, *, timeout=None, do_throttle=True, session=None):
        seen["do_throttle"] = do_throttle
        seen["prompt"] = prompt
        return {
            "status": 200,
            "outcome": "passed",
            "security_flag": "",
            "latency_ms": 1,
            "response": "",
        }

    with mock.patch("linemod_guard_client.test_linemod", side_effect=fake_test_linemod):
        client = p._default_client()
        client("probe prompt")
    assert seen.get("do_throttle") is False
    assert seen.get("prompt") == "probe prompt"


def test_runner_gap_once_not_doubled(tmp_path: Path):
    """Runner sleeps gap once per sample; client must not add another sleep."""
    samples = [
        Sample("a", "e1", "t", "x", "x", "attack", "p1", "blocked"),
        Sample("b", "e1", "t", "x", "x", "attack", "p2", "blocked"),
    ]
    m = build_manifest(
        "gap",
        samples,
        seed=42,
        source_dataset="t",
        dataset_version="d",
        adapter_version="a",
        template_version="none",
    )
    sleeps: list[float] = []
    calls = {"n": 0}

    def client(prompt: str):
        calls["n"] += 1
        return {
            "status": 403,
            "outcome": "blocked",
            "security_flag": "",
            "latency_ms": 1,
            "response": "",
        }

    run_manifest(
        m,
        tmp_path / "out.jsonl",
        client=client,
        request_gap=3.5,
        sleep_fn=sleeps.append,
    )
    assert calls["n"] == 2
    assert sleeps.count(3.5) == 2
    assert len(sleeps) == 2
