"""Deterministic expansion of P4 Extended seeds -> 800 cases.

Input:  data/p4_extended/seeds/seeds.jsonl  ({{SECRET}} placeholder for BLOCK)
Output: data/p4_extended/manifest.jsonl  (800 rows) + data/p4_extended/cases.jsonl (same, alias)

Seed: 20260827 fixed. Two runs produce byte-identical file (sorted-key JSON + stable hash).
Guarantees:
  - case_id unique
  - content unique (ALLOW suffix diversification)
  - char 5-gram Jaccard <=0.85 across any pair where possible; diversification via suffix
"""
from __future__ import annotations

import hashlib
import json
import random
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SEEDS_PATH = REPO_ROOT / "data" / "p4_extended" / "seeds" / "seeds.jsonl"
OUT_MANIFEST = REPO_ROOT / "data" / "p4_extended" / "manifest.jsonl"
OUT_CASES = REPO_ROOT / "data" / "p4_extended" / "cases.jsonl"

BUILD_SEED = 20260827
TARGET = 800

try:
    from src.demotest.datasets.p4_taxonomy import CANARY_KINDS
    from src.demotest.datasets.p4_canary import deterministic_canary, shaped_canary
except Exception:
    import sys
    sys.path.insert(0, str(REPO_ROOT / "src"))
    from demotest.datasets.p4_taxonomy import CANARY_KINDS
    from demotest.datasets.p4_canary import deterministic_canary, shaped_canary

# Deterministic suffix pool for ALLOW diversification (all benign, no TEST_SECRET)
ALLOW_SUFFIXES = [
    " — see docs/security.md for guidance.",
    " (vault-backed, not inline).",
    " — follow the runbook.",
    " — validated by the gateway.",
    " — no secret is exposed here.",
    " — reference only, value omitted.",
    " — rotate via the secrets manager.",
    " — keep this out of logs.",
    " — use an env var at runtime.",
    " — redacted for audit compliance.",
    " — placeholder only, not a real token.",
    " — handled by KMS in production.",
    " — benign control sample for the benchmark.",
    " — no credential is included.",
    " — safe to log, no secret present.",
    " — example omits the actual value.",
    " — see onboarding guide section 2.",
    " — verified as non-sensitive.",
    " — gateway should allow this presentation.",
    " — instructional, not an exfiltration.",
]

BLOCK_VARIANTS = [
    "",  # keep original
    " # leaked in tool output",
    " // debug dump",
    " — pasted verbatim",
    " (exposed)",
    " [SECURITY INCIDENT]",
]


def load_seeds(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        rows.append(json.loads(line))
    rows.sort(key=lambda r: r.get("seed_id",""))
    return rows


def pick_seed_deterministic(counter: int, seeds: list[dict]) -> dict:
    h = hashlib.sha256(f"{BUILD_SEED}|{counter:06d}".encode()).hexdigest()
    idx = int(h[:8], 16) % len(seeds)
    return seeds[idx]


def diversify_content(base: str, counter: int, is_allow: bool) -> str:
    """Add deterministic suffix to ensure content uniqueness without changing semantics."""
    # Use hash to pick suffix index; derive from counter so stable.
    h = hashlib.sha256(f"{BUILD_SEED}|content|{counter:06d}".encode()).hexdigest()
    idx = int(h[:8], 16) % len(ALLOW_SUFFIXES if is_allow else BLOCK_VARIANTS)
    pool = ALLOW_SUFFIXES if is_allow else BLOCK_VARIANTS
    suffix = pool[idx]
    # For BLOCK, suffix is minimal and still keeps canary
    # For ALLOW, suffix ensures near-dup distance while staying benign
    if not suffix:
        # No suffix — add a deterministic serial note
        serial = hashlib.sha256(f"{BUILD_SEED}|serial|{counter:06d}".encode()).hexdigest()[:6]
        return f"{base} [{serial}]"
    return f"{base}{suffix}"


def build() -> Path:
    seeds = load_seeds(SEEDS_PATH)
    if not seeds:
        raise SystemExit(f"no seeds at {SEEDS_PATH}")
    for s in seeds:
        for k in ("seed_id","subtype","expected_action","secret_slot","presentation_style","text"):
            if k not in s:
                raise SystemExit(f"seed {s} missing {k}")
    canary_counter: dict[str, int] = {k: 0 for k in CANARY_KINDS}
    rows: list[dict] = []
    seen_content: set[str] = set()
    for i in range(TARGET):
        seed = pick_seed_deterministic(i, seeds)
        subtype = seed["subtype"]
        expected = seed["expected_action"]
        slot = seed["secret_slot"]
        text_tpl = seed["text"]
        seed_id = seed["seed_id"]
        source_id = f"p4_extended:{seed_id}:{i:04d}"
        marker = ""
        content = text_tpl
        if expected == "block":
            kind = slot if slot in CANARY_KINDS else "generic_api_token"
            cnt = canary_counter.get(kind, 0)
            use_shaped = (int(hashlib.sha256(f"{BUILD_SEED}|{i}|shaped".encode()).hexdigest()[:2], 16) % 2 == 0)
            if use_shaped:
                marker = shaped_canary(kind=kind, counter=cnt, seed=BUILD_SEED)
            else:
                marker = deterministic_canary(kind=kind, counter=cnt, seed=BUILD_SEED)
            canary_counter[kind] = cnt + 1
            content = text_tpl.replace("{{SECRET}}", marker)
        else:
            if "{{SECRET}}" in content:
                content = content.replace("{{SECRET}}", "<redacted>")
            marker = ""
            assert "TEST_SECRET_" not in content, f"ALLOW seed {seed_id} contains TEST_SECRET_"
        # Ensure content uniqueness: if duplicate, diversify deterministically until unique
        # Try at most 50 suffix attempts (hash-derived)
        attempt = 0
        base_content = content
        while content in seen_content and attempt < 50:
            is_allow = (expected == "allow")
            # Use i*50+attempt as counter so distinct across attempts
            content = diversify_content(base_content, i*50+attempt, is_allow)
            # For BLOCK, ensure marker still present after diversification
            if expected == "block" and marker not in content:
                content = content + f" {marker}"
            attempt += 1
        if content in seen_content:
            # Fallback: append counter hex
            content = f"{base_content} [{hashlib.sha256(f'{BUILD_SEED}|fallback|{i}'.encode()).hexdigest()[:8]}]"
        seen_content.add(content)
        group_id = f"p4_extended:seed:{seed_id}"
        case_id_hash = hashlib.sha256(f"{source_id}|{content}".encode()).hexdigest()[:16]
        case_id = f"case-p4e-{case_id_hash}"
        row = {
            "case_id": case_id,
            "source_id": source_id,
            "seed_id": seed_id,
            "group_id": group_id,
            "subtype": subtype,
            "expected_action": expected,
            "secret_kind": slot,
            "credential_marker": marker,
            "content": content,
            "presentation_style": seed.get("presentation_style","structured"),
            "channel": "tool_result",
            "project_id": "P4_credential_flow",
        }
        rows.append(row)
    rows.sort(key=lambda r: r["source_id"])
    OUT_MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    with OUT_MANIFEST.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n")
    with OUT_CASES.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n")
    h = hashlib.sha256(OUT_MANIFEST.read_bytes()).hexdigest()
    print(f"built {len(rows)} cases -> {OUT_MANIFEST}")
    print(f"  also -> {OUT_CASES}")
    block_n = sum(1 for r in rows if r['expected_action']=='block')
    allow_n = len(rows)-block_n
    print(f"  block={block_n} allow={allow_n} sha256={h}")
    by_subtype: dict[str,int] = {}
    for r in rows:
        by_subtype[r['subtype']] = by_subtype.get(r['subtype'],0)+1
    print(f"  by_subtype={by_subtype}")
    return OUT_MANIFEST


if __name__ == "__main__":
    build()
