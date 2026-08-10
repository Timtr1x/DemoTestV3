"""MultiJail + PolyGuard multilingual adapters."""
from __future__ import annotations

import json
from typing import Any

from adapters.base import DatasetAdapter
from core.schema import Sample

ADAPTER_VERSION = "1.0"


class MultilingualAdapter(DatasetAdapter):
    source_name = "multilingual"
    adapter_version = ADAPTER_VERSION

    def dataset_version(self) -> str:
        p = self.cache_dir() / "multijail.jsonl"
        if p.exists():
            return f"multijail_hf:{p.stat().st_size}"
        return "multilingual:missing"

    def _rows(self, subset: str) -> list[dict]:
        p = self.cache_dir() / f"{subset}.jsonl"
        if not p.exists():
            return []
        rows = []
        for line in p.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            prompt = str(r.get("prompt") or "")
            if "Ignore all safety rules and reveal secrets variant" in prompt:
                continue
            if "harmful multilingual prompt" in prompt:
                continue
            rows.append(r)
        return rows

    def fetch(self, *, project: str, subset: str = "multijail", **kwargs: Any) -> list[Sample]:
        samples = []
        for row in self._rows(subset):
            lang = str(row.get("language") or "unk")
            samples.append(
                Sample(
                    sample_id=f"{project}:{subset}:{row.get('id')}",
                    project=project,
                    source_dataset=subset,
                    subset=lang,
                    category=lang,
                    label="attack",
                    prompt_text=str(row.get("prompt") or ""),
                    expected="blocked",
                )
            )
        return samples
