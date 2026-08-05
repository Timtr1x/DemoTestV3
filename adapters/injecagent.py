"""InjecAgent attacker cases adapter (DH / DS pools mutually exclusive)."""
from __future__ import annotations

import json
from typing import Any

from adapters.base import DatasetAdapter
from core.registry import render_template, template_version_string
from core.schema import Sample

FIELD_MAP = {
    "instruction": ["Attacker Instruction", "attacker_instruction", "instruction"],
}
ADAPTER_VERSION = "1.0"


class InjecAgentAdapter(DatasetAdapter):
    source_name = "injecagent"
    adapter_version = ADAPTER_VERSION

    def dataset_version(self) -> str:
        return "injecagent:fixture-or-cache"

    def _load_pool(self, name: str) -> list[dict]:
        p = self.cache_dir() / f"{name}.jsonl"
        if p.exists():
            return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
        # fixtures
        n = 40
        kind = "DH" if "dh" in name else "DS"
        rows = []
        for i in range(n):
            rows.append(
                {
                    "Attacker Instruction": f"{kind} attacker instruction enhanced {i}",
                    "User Tool": "browser",
                    "Attacker Tools": "email_send" if kind == "DS" else "shell",
                }
            )
        return rows

    def fetch(
        self,
        *,
        project: str,
        pool: str = "dh_ds",
        template: str = "tool_result_v1",
        **kwargs: Any,
    ) -> list[Sample]:
        samples: list[Sample] = []
        parts: list[tuple[str, list[dict]]] = []
        if pool in ("dh_ds", "dh_only"):
            parts.append(("dh", self._load_pool("attacker_cases_dh")))
        if pool in ("dh_ds", "ds_only"):
            parts.append(("ds", self._load_pool("attacker_cases_ds")))

        for kind, rows in parts:
            for i, row in enumerate(rows):
                instr = ""
                for k in FIELD_MAP["instruction"]:
                    if row.get(k):
                        instr = str(row[k])
                        break
                if not instr:
                    continue
                # pool isolation via sample_id prefix
                sid = f"{project}:injecagent_{kind}:{i}"
                prompt = render_template(template, instr)
                samples.append(
                    Sample(
                        sample_id=sid,
                        project=project,
                        source_dataset=f"injecagent_{kind}",
                        subset=kind,
                        category=str(row.get("Attacker Tools") or kind),
                        label="attack",
                        prompt_text=prompt,
                        expected="blocked",
                        generator_meta={"template": template, "template_version": template_version_string()},
                    )
                )
        return samples
