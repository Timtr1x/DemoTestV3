"""Agent Security Bench payload export adapter."""
from __future__ import annotations

import json
from typing import Any

from adapters.base import DatasetAdapter
from core.registry import render_template, template_version_string
from core.schema import Sample

ADAPTER_VERSION = "1.0"


class ASBAdapter(DatasetAdapter):
    source_name = "asb"
    adapter_version = ADAPTER_VERSION

    def dataset_version(self) -> str:
        return "asb:static-or-fixture"

    def _rows(self, kind: str) -> list[dict]:
        p = self.cache_dir() / f"{kind}.jsonl"
        if p.exists():
            return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
        n = 40
        return [
            {"attack": f"ASB {kind} payload {i}", "attack_type": kind, "id": i}
            for i in range(n)
        ]

    def fetch(
        self,
        *,
        project: str,
        subset: str = "dpi_opi",
        template: str = "tool_result_v1",
        **kwargs: Any,
    ) -> list[Sample]:
        kinds: list[str]
        if subset == "dpi_opi":
            kinds = ["dpi", "opi"]
        elif subset == "memory_poison":
            kinds = ["mp"]
        elif subset == "mixed":
            kinds = ["mixed"]
        else:
            kinds = [subset]

        samples: list[Sample] = []
        for kind in kinds:
            for row in self._rows(kind):
                payload = str(row.get("attack") or "")
                prompt = render_template(template, payload)
                i = row.get("id", len(samples))
                samples.append(
                    Sample(
                        sample_id=f"{project}:asb_{kind}:{i}",
                        project=project,
                        source_dataset=f"asb_{kind}",
                        subset=kind,
                        category=kind,
                        label="attack",
                        prompt_text=prompt,
                        expected="blocked",
                        generator_meta={"template": template, "template_version": template_version_string()},
                    )
                )
        return samples
