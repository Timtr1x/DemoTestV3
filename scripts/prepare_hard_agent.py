"""Prepare hard/stealth agent suites: InjecAgent enhanced + AgentDojo hard inject."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from adapters.agentdojo import build_hard_rows_from_goals  # noqa: E402
from paths import DATASETS_DIR  # noqa: E402
from scripts.prepare_all_data import (  # noqa: E402
    _json_or_jsonl_to_rows,
    http_get,
    log,
    write_jsonl,
)

INJEC_ENHANCED = {
    "attacker_cases_dh_enhanced.jsonl": (
        "https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/main/"
        "data/test_cases_dh_enhanced.json"
    ),
    "attacker_cases_ds_enhanced.jsonl": (
        "https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/main/"
        "data/test_cases_ds_enhanced.json"
    ),
}


def prepare_injecagent_enhanced() -> None:
    """Use full ``Tool Response`` field (attack embedded in realistic tool output)."""
    log("[injecagent enhanced — Tool Response embedding]")
    base = DATASETS_DIR / "injecagent"
    for out_name, url in INJEC_ENHANCED.items():
        dest = base / out_name
        try:
            raw = http_get(url)
            rows = _json_or_jsonl_to_rows(raw)
            norm = []
            for r in rows:
                tool_resp = r.get("Tool Response") or r.get("tool_response") or ""
                instr = (
                    r.get("Attacker Instruction")
                    or r.get("attacker_instruction")
                    or r.get("instruction")
                    or ""
                )
                # Prefer full tool response: attack is buried in product reviews / email body etc.
                content = str(tool_resp).strip() if tool_resp else str(instr).strip()
                if not content:
                    continue
                tools = r.get("Attacker Tools") or []
                tools_s = (
                    ",".join(map(str, tools)) if isinstance(tools, list) else str(tools)
                )
                norm.append(
                    {
                        "Attacker Instruction": content,
                        "User Tool": r.get("User Tool") or r.get("user_tool") or "tool",
                        "Attacker Tools": tools_s or "unknown",
                        "User Instruction": r.get("User Instruction") or "",
                        "Attack Type": r.get("Attack Type") or "",
                        "source": "injecagent_enhanced_tool_response",
                    }
                )
            if norm:
                write_jsonl(dest, norm)
                log(f"  enhanced {out_name} n={len(norm)}")
            else:
                log(f"  empty enhanced {url}")
        except Exception as e:
            log(f"  FAIL enhanced {url}: {e}")


def prepare_agentdojo_hard() -> None:
    log("[agentdojo hard inject]")
    base = DATASETS_DIR / "agentdojo"
    easy_p = base / "attacks.jsonl"
    if not easy_p.exists():
        log("  missing attacks.jsonl — run prepare_agentdojo first")
        return
    base_rows = [json.loads(l) for l in easy_p.read_text(encoding="utf-8").splitlines() if l.strip()]
    # ensure goal_raw present
    for r in base_rows:
        if not r.get("goal_raw"):
            # try extract from attack field
            att = str(r.get("attack") or "")
            r["goal_raw"] = att.split("overriding prior task:")[-1].strip() if "overriding prior task:" in att else att[:200]
    hard = build_hard_rows_from_goals(base_rows)
    write_jsonl(base / "hard_inject.jsonl", hard)
    log(f"  hard_inject n={len(hard)}")


def main() -> int:
    prepare_injecagent_enhanced()
    prepare_agentdojo_hard()
    log("DONE hard agent prep")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
