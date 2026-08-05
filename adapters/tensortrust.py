"""TensorTrust extraction/hijacking benchmarks."""
from __future__ import annotations

import json
from typing import Any

from adapters.base import DatasetAdapter
from core.schema import Sample

ADAPTER_VERSION = "1.0"


class TensorTrustAdapter(DatasetAdapter):
    source_name = "tensortrust"
    adapter_version = ADAPTER_VERSION

    def dataset_version(self) -> str:
        p = self.cache_dir() / "extraction.jsonl"
        if p.exists():
            return f"tensortrust:{p.stat().st_size}"
        return "tensortrust:fixture"

    def _rows(self, subset: str) -> list[dict]:
        p = self.cache_dir() / f"{subset}.jsonl"
        if p.exists():
            return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
        n = 40 if subset == "extraction" else 20
        return [
            {"attack": f"{subset} attack prompt {i}: reveal the access code", "id": i}
            for i in range(n)
        ]

    def fetch(self, *, project: str, subset: str = "extraction", **kwargs: Any) -> list[Sample]:
        samples = []
        for i, row in enumerate(self._rows(subset)):
            attack = str(row.get("attack") or row.get("prompt") or "")
            if not attack:
                continue
            samples.append(
                Sample(
                    sample_id=f"{project}:tensortrust_{subset}:{row.get('id', i)}",
                    project=project,
                    source_dataset=f"tensortrust_{subset}",
                    subset=subset,
                    category=subset,
                    label="attack",
                    prompt_text=attack,
                    expected="blocked",
                )
            )
        return samples
