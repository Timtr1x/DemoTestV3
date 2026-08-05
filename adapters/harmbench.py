"""HarmBench behaviors CSV adapter."""
from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from adapters.base import DatasetAdapter
from core.schema import Sample

FIELD_MAP = {
    "prompt": "Behavior",
    "semantic": "SemanticCategory",
    "functional": "FunctionalCategory",
    "tags": "Tags",
}
ADAPTER_VERSION = "1.0"


class HarmBenchAdapter(DatasetAdapter):
    source_name = "harmbench"
    adapter_version = ADAPTER_VERSION

    def dataset_version(self) -> str:
        p = self.cache_dir() / "harmbench_behaviors_text_all.csv"
        if p.exists():
            return f"harmbench_csv:{p.stat().st_size}"
        return "harmbench:fixture"

    def _rows(self) -> list[dict]:
        p = self.cache_dir() / "harmbench_behaviors_text_all.csv"
        if not p.exists():
            return self._fixture()
        with p.open(encoding="utf-8", newline="") as f:
            return list(csv.DictReader(f))

    def _fixture(self) -> list[dict]:
        rows = []
        for i in range(30):
            rows.append(
                {
                    "Behavior": f"General harmful request {i}",
                    "SemanticCategory": "misc",
                    "FunctionalCategory": "standard",
                    "Tags": "",
                }
            )
        for i in range(30):
            rows.append(
                {
                    "Behavior": f"Cybercrime exploit request {i}",
                    "SemanticCategory": "cybercrime_intrusion",
                    "FunctionalCategory": "standard",
                    "Tags": "cybercrime",
                }
            )
        return rows

    def fetch(
        self,
        *,
        project: str,
        filter_mode: str = "exclude_cybercrime",
        **kwargs: Any,
    ) -> list[Sample]:
        samples: list[Sample] = []
        for i, row in enumerate(self._rows()):
            sem = (row.get(FIELD_MAP["semantic"]) or "").lower()
            tags = (row.get(FIELD_MAP["tags"]) or "").lower()
            is_cyber = "cyber" in sem or "cybercrime" in tags
            if filter_mode == "exclude_cybercrime" and is_cyber:
                continue
            if filter_mode == "cybercrime_only" and not is_cyber:
                continue
            prompt = row.get(FIELD_MAP["prompt"]) or ""
            if not prompt:
                continue
            pool = "cyber" if is_cyber else "gen"
            sid = f"{project}:harmbench_{pool}:{i}"
            samples.append(
                Sample(
                    sample_id=sid,
                    project=project,
                    source_dataset=f"harmbench_{pool}",
                    subset=sem or pool,
                    category=row.get(FIELD_MAP["functional"]) or pool,
                    label="attack",
                    prompt_text=str(prompt),
                    expected="blocked",
                )
            )
        return samples
