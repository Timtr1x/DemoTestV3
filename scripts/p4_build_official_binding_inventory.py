#!/usr/bin/env python
"""Generate P4 official issue binding inventory (reproducible, no secrets).

Inputs (read-only, pinned):
  - cache/datasets_v3/raw/skillleakbench_catalog/issues.csv        (1708 rows)
  - cache/datasets_v3/raw/skillleakbench_catalog/skills_dataset.csv (520 rows)
  - cache/datasets_v3/raw/p4_skill_candidates/candidates.jsonl      (165)

Outputs (gitignored, under cache/p4_evidence/):
  - official_issue_binding.jsonl  (one row per official issue)
  - binding_summary.json

Algorithm (fixed, no fuzzy):
  1. Read 1708 official issues; count distinct skill_name.
  2. Read candidate pool; count distinct skill_name.
  3. Exact string join on skill_name only for NAME_EXACT_MATCH.
  4. OFFICIAL_BINDING_EXACT requires strong provenance (repo URL /
     source SHA / SKILL.md path / private master File:Line). Public CSV
     has none, so without private master it stays UNRESOLVED even if
     name matches. No fuzzy matching is used.

Usage:
  python scripts/p4_build_official_binding_inventory.py
  python scripts/p4_build_official_binding_inventory.py --check  # assert only, no write
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ISSUES = ROOT / "cache/datasets_v3/raw/skillleakbench_catalog/issues.csv"
DEFAULT_SKILLS = ROOT / "cache/datasets_v3/raw/skillleakbench_catalog/skills_dataset.csv"
DEFAULT_CANDS = ROOT / "cache/datasets_v3/raw/p4_skill_candidates/candidates.jsonl"
OUT_DIR = ROOT / "cache/p4_evidence"
OUT_BINDING = OUT_DIR / "official_issue_binding.jsonl"
OUT_SUMMARY = OUT_DIR / "binding_summary.json"

EXPECTED_ISSUES = 1708
EXPECTED_SKILLS = 520
EXPECTED_UNIQUE_NAMES = 487
EXPECTED_CANDS = 165
EXPECTED_CAND_UNIQUE = 162


def load_issues(p: Path) -> list[dict[str, str]]:
    with p.open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def load_skills(p: Path) -> list[dict[str, str]]:
    with p.open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def load_cands(p: Path) -> list[dict]:
    rows = []
    with p.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description="Build P4 official binding inventory")
    ap.add_argument("--issues", type=Path, default=DEFAULT_ISSUES)
    ap.add_argument("--skills", type=Path, default=DEFAULT_SKILLS)
    ap.add_argument("--candidates", type=Path, default=DEFAULT_CANDS)
    ap.add_argument("--out-dir", type=Path, default=OUT_DIR)
    ap.add_argument("--check", action="store_true", help="assert counts only, no write")
    args = ap.parse_args()

    issues = load_issues(args.issues)
    skills = load_skills(args.skills)
    cands = load_cands(args.candidates)

    # hard assertions — any drift fails fast
    assert len(issues) == EXPECTED_ISSUES, f"issues {len(issues)} != {EXPECTED_ISSUES}"
    assert len(skills) == EXPECTED_SKILLS, f"skills {len(skills)} != {EXPECTED_SKILLS}"
    uniq_names = len({r["skill_name"] for r in issues})
    assert uniq_names == EXPECTED_UNIQUE_NAMES, f"unique skill_name {uniq_names} != {EXPECTED_UNIQUE_NAMES}"
    assert len(cands) == EXPECTED_CANDS, f"candidates {len(cands)} != {EXPECTED_CANDS}"
    cand_names = {c.get("skill_name", "") for c in cands}
    # distinct names: 165 rows but 3 duplicates by skill_name
    uniq_cand = len(cand_names)
    assert uniq_cand == EXPECTED_CAND_UNIQUE, f"candidate unique names {uniq_cand} != {EXPECTED_CAND_UNIQUE}"

    # exact name join (no fuzzy, no normalization beyond exact string)
    cand_by_name = {c.get("skill_name", ""): c for c in cands}
    official_names = {r["skill_name"] for r in issues}
    name_exact_set = official_names & cand_names

    # NAME_EXACT_MATCH is pure string equality; OFFICIAL_BINDING_* requires strong provenance
    # Public CSV has no repo URL / source SHA / SKILL.md path, so OFFICIAL stays UNRESOLVED
    name_exact_count = len(name_exact_set)
    # also count per-issue rows where name would match
    per_issue_name_match = sum(1 for r in issues if r["skill_name"] in cand_names)

    # frozen real skill check
    frozen_skill_name = "portfolio"  # andytrust candidate skill_name
    frozen_is_official = frozen_skill_name in official_names

    # assertions for current state
    assert name_exact_count == 0, f"NAME_EXACT_MATCH {name_exact_count} != 0"
    assert per_issue_name_match == 0, f"per-issue name match {per_issue_name_match} != 0"
    assert not frozen_is_official, "portfolio should not be in official 487"

    summary = {
        "generated_at": "2026-08-26",
        "inputs": {
            "issues": str(args.issues.relative_to(ROOT)),
            "skills": str(args.skills.relative_to(ROOT)),
            "candidates": str(args.candidates.relative_to(ROOT)),
        },
        "official_issues": len(issues),
        "official_skills_by_id": len({r["skill_id"] for r in issues}),
        "official_skills_by_name": uniq_names,
        "candidate_pool": len(cands),
        "candidate_distinct_names": uniq_cand,
        # terminology per review: NAME_EXACT vs OFFICIAL_BINDING
        "NAME_EXACT_MATCH_skills": name_exact_count,
        "NAME_EXACT_MATCH_issues": per_issue_name_match,
        "OFFICIAL_BINDING_EXACT": 0,
        "OFFICIAL_BINDING_PROBABLE": 0,
        "OFFICIAL_BINDING_UNRESOLVED": len(issues),
        "frozen_real_skill_name": frozen_skill_name,
        "frozen_candidate_id": "andytrust-portfolio-claude-code-skill-md",
        "frozen_binding_status": "REAL_SKILL_UNBOUND",
        "frozen_in_official": frozen_is_official,
        "method": "exact string join on skill_name only; OFFICIAL requires repo URL / source SHA / SKILL.md path / private master File:Line; no fuzzy",
        "note": "Public SkillLeakBench CSV has skill_name/classification/pattern only, no repo URL or source SHA; EXACT repo-level join needs private master or targeted re-crawl of 520 affected names.",
    }

    if args.check:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        print("CHECK PASS: Official bound = 0, Real = 1 (UNBOUND)")
        return 0

    out_dir = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    binding_path = out_dir / "official_issue_binding.jsonl"
    summary_path = out_dir / "binding_summary.json"

    # write per-issue binding rows (1708)
    with binding_path.open("w", encoding="utf-8", newline="\n") as out:
        for idx, r in enumerate(issues):
            skill_name = r["skill_name"]
            local = cand_by_name.get(skill_name)
            # NAME_EXACT is string equality; OFFICIAL requires strong provenance
            name_match = skill_name in cand_names
            # without repo/SHA/path, official binding stays UNRESOLVED
            binding_status = "UNRESOLVED"
            binding_method = "no_candidate_match_in_165_pool"
            if name_match:
                # name matches but still not OFFICIAL without provenance
                binding_method = "name_exact_but_no_strong_provenance"
            row = {
                "official_issue_id": f"{r['skill_id']}:{r['pattern_id']}:{idx}",
                "official_skill_id": r["skill_id"],
                "official_skill_name": skill_name,
                "official_pattern": r["pattern"],
                "official_pattern_id": r["pattern_id"],
                "official_academic_code": r["academic_code"],
                "official_classification": r["classification"],
                "official_severity": r["severity"],
                "source_repo": "",
                "source_revision": "",
                "local_candidate_id": local["candidate_id"] if local else "",
                # keep legacy EXACT field for compatibility, but primary is OFFICIAL
                "name_exact_match": bool(name_match),
                "binding_status": binding_status,
                "official_binding": binding_status,
                "binding_method": binding_method,
            }
            out.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {binding_path} ({len(issues)} rows)")
    print(f"wrote {summary_path}")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
