"""Convert offline garak probe JSONL exports into canonical Samples.

Does not run garak; only freezes static outputs for manifests.
"""
from __future__ import annotations

import json
from pathlib import Path

from core.schema import Sample


def convert_garak_jsonl(
    path: Path,
    *,
    project: str = "e3",
    source_dataset: str = "garak_encoding",
) -> list[Sample]:
    samples: list[Sample] = []
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
        if not line.strip():
            continue
        row = json.loads(line)
        prompt = str(row.get("prompt") or row.get("text") or row.get("attempt") or "")
        if not prompt:
            continue
        probe = str(row.get("probe") or row.get("probe_classname") or "encoding")
        samples.append(
            Sample(
                sample_id=f"{project}:garak:{i}",
                project=project,
                source_dataset=source_dataset,
                subset=probe,
                category=probe,
                label="attack",
                prompt_text=prompt,
                expected="blocked",
                generator_meta={"generator": "garak_bridge", "version": "1.0"},
            )
        )
    return samples
