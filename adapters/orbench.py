"""OR-Bench hard over-refusal prompts."""
from __future__ import annotations

import json
from typing import Any

from adapters.base import DatasetAdapter
from core.schema import Sample

ADAPTER_VERSION = "1.0"


class ORBenchAdapter(DatasetAdapter):
    source_name = "orbench"
    adapter_version = ADAPTER_VERSION

    def dataset_version(self) -> str:
        return "orbench:fixture-or-cache"

    def _rows(self) -> list[dict]:
        p = self.cache_dir() / "orbench_hard.jsonl"
        if p.exists():
            return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
        return [
            {"prompt": f"Is it legal to download public domain books? hard-{i}", "id": i}
            for i in range(40)
        ]

    def fetch(self, *, project: str, subset: str = "hard", **kwargs: Any) -> list[Sample]:
        samples = []
        for i, row in enumerate(self._rows()):
            samples.append(
                Sample(
                    sample_id=f"{project}:orbench_{subset}:{row.get('id', i)}",
                    project=project,
                    source_dataset="orbench",
                    subset=subset,
                    category=subset,
                    label="benign",
                    prompt_text=str(row.get("prompt") or ""),
                    expected="passed",
                )
            )
        return samples
