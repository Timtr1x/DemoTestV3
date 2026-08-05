"""Convert frozen promptfoo redteam JSON into canonical Samples for E11."""
from __future__ import annotations

import json
from pathlib import Path

from core.schema import Sample

GENERATOR_VERSION = "1.0"


def convert_promptfoo(
    path: Path,
    *,
    project: str = "e11",
) -> list[Sample]:
    data = json.loads(path.read_text(encoding="utf-8"))
    # promptfoo shapes vary: list of tests, or {tests: [...]} / {prompts: [...]}
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("tests") or data.get("prompts") or data.get("results") or []
    else:
        items = []

    samples: list[Sample] = []
    for i, item in enumerate(items):
        if isinstance(item, str):
            prompt, plugin = item, "unknown"
        else:
            prompt = str(
                item.get("prompt")
                or item.get("vars", {}).get("prompt")
                or item.get("message")
                or item.get("text")
                or ""
            )
            plugin = str(
                item.get("plugin")
                or item.get("provider")
                or item.get("metadata", {}).get("plugin")
                or "unknown"
            )
        if not prompt:
            continue
        samples.append(
            Sample(
                sample_id=f"{project}:promptfoo_{plugin}:{i}",
                project=project,
                source_dataset="promptfoo_redteam",
                subset=plugin,
                category=plugin,
                label="attack",
                prompt_text=prompt,
                expected="blocked",
                generator_meta={
                    "generator": "promptfoo_gen",
                    "version": GENERATOR_VERSION,
                    "source_file": path.name,
                },
            )
        )
    return samples


def ensure_fixture(path: Path, n_per_plugin: int = 10) -> Path:
    """Write a tiny offline promptfoo-like fixture for sampling without LLM."""
    plugins = ["rbac", "bfla", "bola", "imitation"]
    tests = []
    for plug in plugins:
        for i in range(n_per_plugin):
            tests.append(
                {
                    "prompt": f"[{plug}] privilege induction test case {i}",
                    "plugin": plug,
                }
            )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"tests": tests}, ensure_ascii=False, indent=2), encoding="utf-8")
    return path
