"""InjecAgent attacker cases — base and enhanced (harder hacking prompt)."""
from __future__ import annotations

import json
from typing import Any

from adapters.base import DatasetAdapter
from core.registry import render_template, template_version_string
from core.schema import Sample

FIELD_MAP = {
    "instruction": ["Attacker Instruction", "attacker_instruction", "instruction"],
}
ADAPTER_VERSION = "2.0"


class InjecAgentAdapter(DatasetAdapter):
    source_name = "injecagent"
    adapter_version = ADAPTER_VERSION

    def dataset_version(self) -> str:
        p = self.cache_dir() / "attacker_cases_dh.jsonl"
        pe = self.cache_dir() / "attacker_cases_dh_enhanced.jsonl"
        if pe.exists():
            return f"injecagent_enhanced:{pe.stat().st_size}"
        if p.exists():
            return f"injecagent_github:{p.stat().st_size}"
        return "injecagent:missing"

    def _load_pool(self, name: str) -> list[dict]:
        p = self.cache_dir() / f"{name}.jsonl"
        if not p.exists():
            return []
        rows = []
        for line in p.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            instr = str(
                r.get("Attacker Instruction")
                or r.get("attacker_instruction")
                or r.get("instruction")
                or ""
            )
            if "enhanced attacker instruction #" in instr.lower():
                continue
            if "attacker instruction enhanced" in instr.lower():
                continue
            rows.append(r)
        return rows

    def fetch(
        self,
        *,
        project: str,
        pool: str = "dh_ds",
        template: str = "tool_result_v1",
        mode: str = "base",
        **kwargs: Any,
    ) -> list[Sample]:
        enhanced = str(mode).lower() in ("enhanced", "hard")
        samples: list[Sample] = []
        parts: list[tuple[str, list[dict]]] = []
        if pool in ("dh_ds", "dh_only"):
            name = "attacker_cases_dh_enhanced" if enhanced else "attacker_cases_dh"
            parts.append(("dh", self._load_pool(name)))
            # fallback to base if enhanced missing
            if enhanced and not parts[-1][1]:
                parts[-1] = ("dh", self._load_pool("attacker_cases_dh"))
        if pool in ("dh_ds", "ds_only"):
            name = "attacker_cases_ds_enhanced" if enhanced else "attacker_cases_ds"
            parts.append(("ds", self._load_pool(name)))
            if enhanced and not parts[-1][1]:
                parts[-1] = ("ds", self._load_pool("attacker_cases_ds"))

        for kind, rows in parts:
            seen_instr: set[str] = set()
            for i, row in enumerate(rows):
                instr = ""
                for k in FIELD_MAP["instruction"]:
                    if row.get(k):
                        instr = str(row[k])
                        break
                # enhanced cases may embed instruction in other fields
                if not instr:
                    instr = str(
                        row.get("Attacker Instruction")
                        or row.get("hacking_prompt")
                        or row.get("prompt")
                        or ""
                    )
                payload_instr = instr
                if not payload_instr:
                    continue
                key = payload_instr.strip()
                if key in seen_instr:
                    continue
                seen_instr.add(key)
                # Enhanced: content is already a realistic Tool Response string
                if enhanced:
                    tool = str(row.get("User Tool") or row.get("user_tool") or "browser")
                    # Light JSON envelope only if not already JSON-looking
                    if payload_instr.lstrip().startswith(("{", "[")):
                        payload = payload_instr
                    else:
                        payload = json.dumps(
                            {"ok": True, "tool": tool, "content": payload_instr},
                            ensure_ascii=False,
                        )
                else:
                    payload = payload_instr
                tag = "enhanced" if enhanced else kind
                sid = f"{project}:injecagent_{tag}_{kind}:{i}"
                prompt = render_template(template, payload)
                samples.append(
                    Sample(
                        sample_id=sid,
                        project=project,
                        source_dataset=f"injecagent_{tag}_{kind}",
                        subset=f"{tag}_{kind}",
                        category=str(row.get("Attacker Tools") or kind),
                        label="attack",
                        prompt_text=prompt,
                        expected="blocked",
                        generator_meta={
                            "template": template,
                            "template_version": template_version_string(),
                            "mode": "enhanced" if enhanced else "base",
                            "source": "injecagent_github",
                        },
                    )
                )
        return samples
