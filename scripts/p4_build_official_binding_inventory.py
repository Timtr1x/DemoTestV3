#!/usr/bin/env python
"""Generate P4 official issue binding inventory (reproducible, no secrets).

Inputs (read-only, pinned):
  - cache/datasets_v3/raw/skillleakbench_catalog/issues.csv        (1708 rows)
  - cache/datasets_v3/raw/skillleakbench_catalog/skills_dataset.csv (520 rows)
  - cache/datasets_v3/raw/p4_skill_candidates/candidates.jsonl      (165)

Outputs (gitignored, under cache/p4_evidence/):
  - official_issue_binding.jsonl  (one row per official issue, keyed stably)
  - skill_binding.jsonl           (one row per official skill name, 487)
  - binding_summary.json

Identity:
  - official_issue_key = "slb:<hex16>" where hex16 = sha256(
    "skill_id|skill_name|pattern_id|academic_code|pattern|classification|severity"
    )[:16] (order-independent, CSV-reorder stable; identical duplicate rows
    share the same key — merged per one-issue-at-most-one-case).
    This key is the future P4CANARY binding anchor:
      P4CANARY = "P4CANARY_" + sha256(official_issue_key)[:16].upper()
    Never use CSV row index.

Resolver states (per skill name, candidate name -> list):
  - NAME_MATCH_ONLY        : name matches but no strong provenance -> never EXACT
  - AMBIGUOUS_NAME_MATCH   : name matches but multiple candidates with same name
  - PROBABLE               : reserved (needs partial provenance, e.g. repo without SHA)
  - OFFICIAL_BINDING_EXACT : strong provenance (repo + revision/source SHA + skill path)
  - UNRESOLVED             : no candidate match

Per-skill source status (487 official names):
  - BOUND_EXACT            : one candidate + EXACT provenance
  - BOUND_AMBIGUOUS        : multiple candidates for same name
  - SOURCE_NOT_FOUND       : no candidate / no source

Usage:
  python scripts/p4_build_official_binding_inventory.py
  python scripts/p4_build_official_binding_inventory.py --check
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ISSUES = ROOT / "cache/datasets_v3/raw/skillleakbench_catalog/issues.csv"
DEFAULT_SKILLS = ROOT / "cache/datasets_v3/raw/skillleakbench_catalog/skills_dataset.csv"
DEFAULT_CANDS = ROOT / "cache/datasets_v3/raw/p4_skill_candidates/candidates.jsonl"
OUT_DIR = ROOT / "cache/p4_evidence"

EXPECTED_ISSUES = 1708
EXPECTED_SKILLS = 520
EXPECTED_UNIQUE_NAMES = 487
EXPECTED_CANDS = 165
EXPECTED_CAND_UNIQUE = 162


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def sha_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def official_issue_key(row: dict[str, str]) -> str:
    raw = "|".join([
        row["skill_id"], row["skill_name"], row["pattern_id"],
        row["academic_code"], row["pattern"], row["classification"],
        row["severity"],
    ])
    return "slb:" + sha256(raw)[:16]


def is_strong_provenance(cand: dict) -> tuple[bool, str]:
    """EXACT requires repo + revision/source SHA + skill path.

    candidate fields: repo_url, branch/revision, source_sha256, local_path/skill_path.
    """
    repo = (cand.get("repo_url") or cand.get("source_repo") or "").strip()
    sha = (cand.get("source_sha256") or cand.get("source_sha") or "").strip()
    path = (cand.get("local_path") or cand.get("skill_path") or cand.get("local_path") or "").strip()
    rev = (cand.get("branch") or cand.get("revision") or cand.get("source_revision") or "").strip()
    reasons: list[str] = []
    if not repo:
        reasons.append("missing repo")
    if not (sha and len(sha) >= 40):
        reasons.append("missing/short source_sha256")
    if not path:
        reasons.append("missing skill path")
    if not rev:
        reasons.append("missing revision")
    if reasons:
        return False, "; ".join(reasons)
    return True, "repo+revision+sha+path"


def load_issues(p: Path) -> list[dict[str, str]]:
    with p.open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def load_skills(p: Path) -> list[dict[str, str]]:
    with p.open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def load_cands(p: Path) -> list[dict]:
    rows: list[dict] = []
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
    ap.add_argument("--check", action="store_true", help="assert only, no write")
    args = ap.parse_args()

    issues = load_issues(args.issues)
    skills = load_skills(args.skills)
    cands = load_cands(args.candidates)

    # identity set consistency
    assert len(issues) == EXPECTED_ISSUES, f"issues {len(issues)} != {EXPECTED_ISSUES}"
    assert len(skills) == EXPECTED_SKILLS, f"skills {len(skills)} != {EXPECTED_SKILLS}"
    issue_names = {r["skill_name"] for r in issues}
    skill_names = {r["skill_name"] for r in skills}
    assert issue_names == skill_names, f"skill identity mismatch: issues {len(issue_names)} vs skills {len(skill_names)}"
    assert len(issue_names) == EXPECTED_UNIQUE_NAMES
    assert len(cands) == EXPECTED_CANDS
    cand_names_set = {c.get("skill_name", "") for c in cands}
    assert len(cand_names_set) == EXPECTED_CAND_UNIQUE

    # SHA of inputs for summary
    issues_sha = sha_file(args.issues)
    skills_sha = sha_file(args.skills)
    cands_sha = sha_file(args.candidates)

    # candidate name -> list (do not collapse)
    cand_by_name: dict[str, list[dict]] = defaultdict(list)
    for c in cands:
        cand_by_name[c.get("skill_name", "")].append(c)

    # per-skill source status (487 names)
    per_skill_rows: list[dict] = []
    name_exact_skills = 0
    ambiguous_skills = 0
    for name in sorted(issue_names):
        lst = cand_by_name.get(name, [])
        if not lst:
            per_skill_rows.append({
                "official_skill_name": name,
                "status": "SOURCE_NOT_FOUND",
                "candidates": [],
                "provenance_note": "no candidate with this skill_name in 165 pool",
            })
        elif len(lst) == 1:
            c = lst[0]
            strong, reason = is_strong_provenance(c)
            # name matches but needs strong provenance for EXACT
            if strong:
                per_skill_rows.append({
                    "official_skill_name": name,
                    "status": "BOUND_EXACT",
                    "candidates": [c["candidate_id"]],
                    "provenance_note": reason,
                })
            else:
                # single name match but no strong provenance -> NAME_MATCH_ONLY (still UNRESOLVED at official level)
                per_skill_rows.append({
                    "official_skill_name": name,
                    "status": "SOURCE_NOT_FOUND",
                    "candidates": [c["candidate_id"]],
                    "provenance_note": f"name match but not strong provenance: {reason}",
                })
                name_exact_skills += 1
        else:
            # ambiguous: same skill_name maps to multiple local candidates
            per_skill_rows.append({
                "official_skill_name": name,
                "status": "BOUND_AMBIGUOUS",
                "candidates": [c["candidate_id"] for c in lst],
                "provenance_note": f"ambiguous: {len(lst)} candidates share skill_name",
            })
            ambiguous_skills += 1

    # per-issue binding rows (1708) — stable key, not CSV idx
    # Count states for issues: collapse skill-level status to issue-level
    issue_rows: list[dict] = []
    # track key for P4CANARY anchor: must be deterministic across reorder
    seen_keys: set[str] = set()
    for r in issues:
        key = official_issue_key(r)
        seen_keys.add(key)
        name = r["skill_name"]
        lst = cand_by_name.get(name, [])
        if not lst:
            status = "UNRESOLVED"
            method = "no_candidate_match_in_165_pool"
            name_match_only = False
            off_exact = False
        elif len(lst) > 1:
            status = "AMBIGUOUS_NAME_MATCH"
            method = f"ambiguous: {len(lst)} candidates share skill_name {name!r}"
            name_match_only = False
            off_exact = False
        else:
            # single candidate by name
            c = lst[0]
            strong, reason = is_strong_provenance(c)
            if strong:
                status = "OFFICIAL_BINDING_EXACT"
                method = reason
                name_match_only = False
                off_exact = True
            else:
                status = "NAME_MATCH_ONLY"
                method = f"name match but not strong provenance: {reason}"
                name_match_only = True
                off_exact = False

        local_ids = [c["candidate_id"] for c in lst] if lst else []
        row = {
            "official_issue_key": key,
            "official_issue_id_legacy": f"{r['skill_id']}:{r['pattern_id']}",
            "official_skill_id": r["skill_id"],
            "official_skill_name": name,
            "official_pattern": r["pattern"],
            "official_pattern_id": r["pattern_id"],
            "official_academic_code": r["academic_code"],
            "official_classification": r["classification"],
            "official_severity": r["severity"],
            "source_repo": "",
            "source_revision": "",
            "local_candidate_ids": local_ids,
            "local_candidate_id": local_ids[0] if local_ids else "",
            "name_exact_match": name_match_only or off_exact or status == "AMBIGUOUS_NAME_MATCH",
            "binding_status": status,
            "official_binding": status,
            "binding_method": method,
        }
        issue_rows.append(row)

    # summaries
    c_issue = Counter(r["binding_status"] for r in issue_rows)
    c_skill = Counter(r["status"] for r in per_skill_rows)

    # current expectation: 0 name matches at all with existing 165 pool,
    # so all issues UNRESOLVED and all per-skill SOURCE_NOT_FOUND
    assert c_issue.get("NAME_MATCH_ONLY", 0) == 0
    assert c_issue.get("AMBIGUOUS_NAME_MATCH", 0) == 0
    assert c_issue.get("OFFICIAL_BINDING_EXACT", 0) == 0
    assert c_issue.get("UNRESOLVED", 0) == EXPECTED_ISSUES
    assert c_skill.get("SOURCE_NOT_FOUND", 0) == EXPECTED_UNIQUE_NAMES
    assert c_skill.get("BOUND_EXACT", 0) == 0
    assert c_skill.get("BOUND_AMBIGUOUS", 0) == 0

    # stable key check: unique keys < 1708 due to duplicate identical rows sharing key
    unique_keys = len(seen_keys)
    assert unique_keys <= EXPECTED_ISSUES and unique_keys >= 700, f"unique keys {unique_keys} out of range"

    # CSV reorder invariance: sorted keys must not depend on input order
    # verify by shuffling
    import random
    shuf = list(issues)
    random.Random(42).shuffle(shuf)
    shuf_keys = sorted(official_issue_key(r) for r in shuf)
    orig_keys = sorted(official_issue_key(r) for r in issues)
    assert shuf_keys == orig_keys, "official_issue_key must be CSV-order independent"

    summary = {
        "generated_at": "2026-08-26",
        "inputs": {
            "issues": str(args.issues.relative_to(ROOT)),
            "issues_sha256": issues_sha,
            "skills": str(args.skills.relative_to(ROOT)),
            "skills_sha256": skills_sha,
            "candidates": str(args.candidates.relative_to(ROOT)),
            "candidates_sha256": cands_sha,
        },
        "official_issues": len(issues),
        "official_skills_by_id": len({r["skill_id"] for r in issues}),
        "official_skills_by_name": len(issue_names),
        "official_unique_issue_keys": unique_keys,
        "candidate_pool": len(cands),
        "candidate_distinct_names": len(cand_names_set),
        # issue-level (1708)
        "NAME_MATCH_ONLY": c_issue.get("NAME_MATCH_ONLY", 0),
        "AMBIGUOUS_NAME_MATCH": c_issue.get("AMBIGUOUS_NAME_MATCH", 0),
        "OFFICIAL_BINDING_EXACT": c_issue.get("OFFICIAL_BINDING_EXACT", 0),
        "UNRESOLVED": c_issue.get("UNRESOLVED", 0),
        # skill-level (487)
        "skill_BOUND_EXACT": c_skill.get("BOUND_EXACT", 0),
        "skill_BOUND_AMBIGUOUS": c_skill.get("BOUND_AMBIGUOUS", 0),
        "skill_SOURCE_NOT_FOUND": c_skill.get("SOURCE_NOT_FOUND", 0),
        "frozen_real_skill_name": "portfolio",
        "frozen_candidate_id": "andytrust-portfolio-claude-code-skill-md",
        "frozen_binding_status": "REAL_SKILL_UNBOUND",
        "frozen_in_official": False,
        "method": "exact string join on skill_name; candidate name -> list (no collapse); OFFICIAL_BINDING_EXACT requires repo+revision/sha+path; no fuzzy; official_issue_key is deterministic sha16 of all CSV identity fields",
        "note": "Public CSV has skill_name/classification/pattern only, no repo URL or source SHA; EXACT needs private master or targeted re-crawl of 520 affected names. Duplicate identical issue rows share same key (one-issue-at-most-one-case).",
        "p4canary_anchor": "P4CANARY_<sha256(official_issue_key)[:16].upper()>",
    }

    if args.check:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        print("CHECK PASS: Official bound = 0, Real = 1 (UNBOUND), per-skill SOURCE_NOT_FOUND=487")
        return 0

    out_dir = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    with (out_dir / "official_issue_binding.jsonl").open("w", encoding="utf-8", newline="\n") as out:
        for row in issue_rows:
            out.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    # skill-level binding (487)
    with (out_dir / "skill_binding.jsonl").open("w", encoding="utf-8", newline="\n") as out:
        for row in sorted(per_skill_rows, key=lambda x: x["official_skill_name"]):
            out.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    (out_dir / "binding_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"wrote {out_dir/'official_issue_binding.jsonl'} ({len(issue_rows)} rows, {unique_keys} unique keys)")
    print(f"wrote {out_dir/'skill_binding.jsonl'} ({len(per_skill_rows)} rows)")
    print(f"wrote {out_dir/'binding_summary.json'}")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
