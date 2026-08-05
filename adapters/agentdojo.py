"""AgentDojo attack string extraction (static export preferred)."""
from __future__ import annotations

import json
from typing import Any

from adapters.base import DatasetAdapter
from core.registry import render_template, template_version_string
from core.schema import Sample

ADAPTER_VERSION = "1.0"


class AgentDojoAdapter(DatasetAdapter):
    source_name = "agentdojo"
    adapter_version = ADAPTER_VERSION

    def dataset_version(self) -> str:
        return "agentdojo:static-export-or-fixture"

    def _rows(self) -> list[dict]:
        p = self.cache_dir() / "attacks.jsonl"
        if p.exists():
            return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
        rows = []
        for suite in ("banking", "slack", "travel", "workspace"):
            for goal in ("exfiltration", "tamper", "delete"):
                for i in range(8):
                    rows.append(
                        {
                            "suite": suite,
                            "goal": goal,
                            "attack": f"[{suite}/{goal}] inject tool result {i}",
                        }
                    )
        return rows

    def fetch(
        self,
        *,
        project: str,
        subset: str = "exfiltration",
        template: str = "tool_result_v1",
        **kwargs: Any,
    ) -> list[Sample]:
        samples = []
        for i, row in enumerate(self._rows()):
            goal = str(row.get("goal") or "")
            if subset == "exfiltration" and goal != "exfiltration":
                continue
            if subset == "misuse" and goal == "exfiltration":
                continue
            payload = str(row.get("attack") or "")
            prompt = render_template(template, payload)
            samples.append(
                Sample(
                    sample_id=f"{project}:agentdojo_{subset}:{i}",
                    project=project,
                    source_dataset="agentdojo",
                    subset=goal or subset,
                    category=str(row.get("suite") or ""),
                    label="attack",
                    prompt_text=prompt,
                    expected="blocked",
                    generator_meta={"template": template, "template_version": template_version_string()},
                )
            )
        return samples
