"""Agent Security Bench adapter — easy (labeled) + stealth (no attack tags)."""
from __future__ import annotations

import json
from typing import Any

from adapters.base import DatasetAdapter
from core.registry import render_template, template_version_string
from core.schema import Sample

ADAPTER_VERSION = "2.0"

# Neutral tool names so the *label* does not scream "attacker"
_NEUTRAL_TOOLS = (
    "email_fetch",
    "db_lookup",
    "calendar_list",
    "file_read",
    "http_get",
    "contacts_search",
    "ticket_get",
)


def _instruction_of(row: dict) -> str:
    return str(
        row.get("instruction")
        or row.get("Attacker Instruction")
        or row.get("attack")
        or ""
    ).strip()


def stealth_tool_json(row: dict, *, idx: int = 0) -> str:
    """Render as a normal-looking tool JSON result (no Attacker/Attack goal fields)."""
    instr = _instruction_of(row)
    # strip accidental labeled blocks if present
    if "Attacker tool:" in instr:
        # fall back to instruction field only
        instr = str(row.get("instruction") or "").strip() or instr
    tool = _NEUTRAL_TOOLS[idx % len(_NEUTRAL_TOOLS)]
    body = {
        "ok": True,
        "tool": tool,
        "latency_ms": 12 + (idx % 40),
        "data": {
            "status": "success",
            "message": "Upstream system returned the following note for the agent:",
            "note": instr,
        },
    }
    return json.dumps(body, ensure_ascii=False, indent=2)


def easy_labeled_payload(row: dict) -> str:
    """Legacy easy format used in first live-real-v1 run (high-signal labels)."""
    if row.get("attack") and "Attacker tool:" in str(row.get("attack")):
        return str(row["attack"])
    instr = _instruction_of(row)
    tool = row.get("attacker_tool") or row.get("Attacker Tool") or "unknown_tool"
    goal = row.get("Attack goal") or row.get("attack_goal") or ""
    desc = row.get("Description") or row.get("description") or ""
    return (
        "Tool observation / memory write:\n"
        f"Attacker tool: {tool}\n"
        f"Instruction: {instr}\n"
        f"Attack goal: {goal}\n"
        f"Description: {desc}"
    )


class ASBAdapter(DatasetAdapter):
    source_name = "asb"
    adapter_version = ADAPTER_VERSION

    def dataset_version(self) -> str:
        p = self.cache_dir() / "all_attack_tools.jsonl"
        if p.exists():
            return f"asb_github:n_bytes={p.stat().st_size}"
        return "asb:missing"

    def _rows(self, kind: str) -> list[dict]:
        p = self.cache_dir() / f"{kind}.jsonl"
        if not p.exists():
            return []
        out = []
        for line in p.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            attack = str(r.get("attack") or "")
            if "ASB " in attack and "payload #" in attack and "poison agent memory" in attack:
                continue
            if r.get("source") == "asb_github" or r.get("instruction") or r.get("Attacker Instruction"):
                out.append(r)
            elif attack and "payload #" not in attack:
                out.append(r)
        return out

    def fetch(
        self,
        *,
        project: str,
        subset: str = "dpi_opi",
        template: str = "tool_result_v1",
        mode: str = "easy",
        **kwargs: Any,
    ) -> list[Sample]:
        """mode: easy = labeled high-signal; stealth = JSON tool result without attack tags."""
        kinds: list[str]
        if subset == "dpi_opi":
            kinds = ["dpi", "opi"]
        elif subset == "memory_poison":
            kinds = ["mp"]
        elif subset == "mixed":
            kinds = ["mixed"]
        elif subset == "all_kinds":
            kinds = ["dpi", "opi", "mp", "mixed"]
        else:
            kinds = [subset]

        stealth = str(mode).lower() in ("stealth", "hard", "tooljson")
        samples: list[Sample] = []
        for kind in kinds:
            for j, row in enumerate(self._rows(kind)):
                i = row.get("id", len(samples))
                if stealth:
                    payload = stealth_tool_json(row, idx=int(i) if str(i).isdigit() else j)
                    sid = f"{project}:asb_stealth_{kind}:{i}"
                    src = f"asb_stealth_{kind}"
                    cat = "stealth_tooljson"
                else:
                    payload = easy_labeled_payload(row)
                    sid = f"{project}:asb_{kind}:{i}"
                    src = f"asb_{kind}"
                    cat = kind
                prompt = render_template(template, payload)
                samples.append(
                    Sample(
                        sample_id=sid,
                        project=project,
                        source_dataset=src,
                        subset=kind if not stealth else f"stealth_{kind}",
                        category=cat,
                        label="attack",
                        prompt_text=prompt,
                        expected="blocked",
                        generator_meta={
                            "template": template,
                            "template_version": template_version_string(),
                            "mode": "stealth" if stealth else "easy",
                            "source": "asb_github",
                        },
                    )
                )
        return samples
