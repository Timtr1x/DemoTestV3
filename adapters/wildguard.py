"""WildGuardMix adapter (gated HF; disable via ENABLE_WILDGUARD)."""
from __future__ import annotations

import json
import os
from typing import Any

from adapters.base import DatasetAdapter
from core.schema import Sample

ADAPTER_VERSION = "1.0"


class WildGuardAdapter(DatasetAdapter):
    source_name = "wildguard"
    adapter_version = ADAPTER_VERSION

    def enabled(self) -> bool:
        return os.environ.get("ENABLE_WILDGUARD", "0").lower() in ("1", "true", "yes")

    def dataset_version(self) -> str:
        rev = self.cache_dir() / "hf_revision.txt"
        if rev.exists():
            return f"hf_revision:{rev.read_text(encoding='utf-8').strip()}"
        return "wildguard:fixture"

    def _rows(self) -> list[dict]:
        p = self.cache_dir() / "wildguard_test.jsonl"
        if p.exists():
            return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
        rows = []
        for i in range(20):
            rows.append(
                {
                    "prompt": f"adversarial harmful prompt {i}",
                    "prompt_harm_label": "harmful",
                    "adversarial": True,
                    "subcategory": "violence",
                }
            )
        for i in range(20):
            rows.append(
                {
                    "prompt": f"unharmful benign prompt {i}",
                    "prompt_harm_label": "unharmful",
                    "adversarial": False,
                    "subcategory": "benign",
                }
            )
        return rows

    def fetch(self, *, project: str, mode: str = "adversarial_harmful", **kwargs: Any) -> list[Sample]:
        if not self.enabled() and not (self.cache_dir() / "wildguard_test.jsonl").exists():
            # still return fixtures when offline testing without gate
            pass
        samples = []
        for i, row in enumerate(self._rows()):
            harm = str(row.get("prompt_harm_label") or "").lower()
            adv = bool(row.get("adversarial"))
            if mode == "adversarial_harmful" and not (adv and harm == "harmful"):
                continue
            if mode == "unharmful" and harm != "unharmful":
                continue
            label = "attack" if harm == "harmful" else "benign"
            expected = "blocked" if label == "attack" else "passed"
            samples.append(
                Sample(
                    sample_id=f"{project}:wildguard:{i}",
                    project=project,
                    source_dataset="wildguardmix",
                    subset=str(row.get("subcategory") or mode),
                    category=harm,
                    label=label,
                    prompt_text=str(row.get("prompt") or ""),
                    expected=expected,
                )
            )
        return samples
