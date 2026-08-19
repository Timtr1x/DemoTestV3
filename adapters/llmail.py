"""LLMail-Inject challenge adapter (offline jsonl preferred)."""
from __future__ import annotations

import json
from typing import Any

from adapters.base import DatasetAdapter
from core.registry import render_template, template_version_string
from core.schema import Sample

FIELD_MAP = {
    "prompt": ["attack", "attack_email", "email_body", "text", "prompt", "payload"],
    "level": ["level", "scenario_level", "difficulty"],
    "scenario": ["scenario", "scenario_name", "task"],
    "success": ["success", "bypassed", "label_success", "is_success"],
}
ADAPTER_VERSION = "1.0"


def _pick(d: dict, keys: list[str], default: Any = None) -> Any:
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    return default


class LLMailAdapter(DatasetAdapter):
    source_name = "llmail"
    adapter_version = ADAPTER_VERSION

    def dataset_version(self) -> str:
        p = self.cache_dir() / "llmail.jsonl"
        if p.exists():
            return f"llmail_hf:{p.stat().st_size}"
        return "llmail:missing"

    def _rows(self) -> list[dict]:
        p = self.cache_dir() / "llmail.jsonl"
        if not p.exists():
            return []
        rows = []
        for line in p.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            attack = str(r.get("attack") or r.get("body") or "")
            if "attacker@evil.test" in attack and "Please ignore previous instructions. Level" in attack:
                continue
            rows.append(r)
        return rows

    def fetch(
        self,
        *,
        project: str,
        subset: str = "all",
        template: str = "email_v1",
        **kwargs: Any,
    ) -> list[Sample]:
        samples: list[Sample] = []
        for i, row in enumerate(self._rows()):
            scenario = str(_pick(row, FIELD_MAP["scenario"], "email") or "email")
            payload = str(
                _pick(row, FIELD_MAP["prompt"], "")
                or row.get("body")
                or ""
            )
            if not payload and row.get("subject"):
                payload = f"Subject: {row.get('subject')}\n\n{row.get('body') or ''}"
            if not payload:
                continue
            if subset == "exfil":
                # real LLMail: prefer rows whose objectives/body mention exfil/send/email tools
                blob = (
                    str(row.get("objectives") or "")
                    + " "
                    + payload
                    + " "
                    + scenario
                ).lower()
                if not any(
                    k in blob
                    for k in (
                        "exfil",
                        "send",
                        "forward",
                        "api_call",
                        "email",
                        "contact@",
                        "mailto",
                    )
                ):
                    continue
            prompt = render_template(template, payload)
            level = str(_pick(row, FIELD_MAP["level"], "na"))
            sid = f"{project}:llmail:{i}"
            samples.append(
                Sample(
                    sample_id=sid,
                    project=project,
                    source_dataset="llmail_inject",
                    subset=f"level_{level}",
                    category=scenario,
                    label="attack",
                    prompt_text=prompt,
                    expected="blocked",
                    generator_meta={"template": template, "template_version": template_version_string()},
                )
            )
        return samples
