#!/usr/bin/env python
"""Recover OFFICIAL_SKILL_BOUND identity for 487 official skills (no execution).

Inputs (read-only, pinned):
  - cache/datasets_v3/raw/skillleakbench_catalog/issues.csv
  - cache/datasets_v3/raw/skillleakbench_catalog/skills_dataset.csv
  - cache/datasets_v3/raw/p4_skill_candidates/candidates.jsonl  (165, may be 0-overlap)
  - [optional] cache/p4_evidence/official_source_evidence.jsonl (future private master)

Output (gitignored, under cache/p4_evidence/):
  - official_skill_sources.jsonl  (487 rows, one per official_skill_name)

Each row:
  official_skill_name
  official_skill_ids: list[str]  (1 or 2 when dual-class)
  classifications: list[str]
  raw_issue_rows: int
  sanitized_issue_keys: list[str]  (unique slb:<sha16> for this skill)
  sanitized_keys_count
  issue_count_from_skills_dataset: int (sum across classifications)
  repo_url, commit_sha, skill_path, source_sha256  (empty until recovered)
  status: SOURCE_NOT_FOUND | CANDIDATE_SOURCE_VERIFIED | BOUND_AMBIGUOUS | BOUND_EXACT
  binding_method, binding_confidence
  candidate_ids: list[str]  (if any candidate name match)

Semantics (review deeb98f):
  - This file is OFFICIAL_SKILL_BOUND (skill -> repo/commit/path), not
    OFFICIAL_ISSUE_BOUND. Issue-level binding requires File:Line/snippet/sink
    per evidence and expansion of 924 sanitized collisions:
      official_evidence_key = sha256(sanitized_issue_key|repo|revision|skill_path|file_path|line_start|line_end)
    Each evidence then gets its own P4CANARY; do not reuse skill_name fallback
    to produce issue EXACT.
  - is_candidate_source_verified requires repo+64hex+path; branch never counts.
    Without official evidence a single verified name is CANDIDATE_SOURCE_VERIFIED, never EXACT.
  - 165 pool currently has 0 overlap with 487 official names — expected
    SOURCE_NOT_FOUND for all 487 until targeted re-crawl / private master.

Usage:
  python scripts/p4_recover_official_skill_sources.py
  python scripts/p4_recover_official_skill_sources.py --check
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ISSUES = ROOT / "cache/datasets_v3/raw/skillleakbench_catalog/issues.csv"
DEFAULT_SKILLS = ROOT / "cache/datasets_v3/raw/skillleakbench_catalog/skills_dataset.csv"
DEFAULT_CANDS = ROOT / "cache/datasets_v3/raw/p4_skill_candidates/candidates.jsonl"
DEFAULT_OFFICIAL = ROOT / "cache/p4_evidence/official_source_evidence.jsonl"
OUT = ROOT / "cache/p4_evidence/official_skill_sources.jsonl"

_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")


def sha16(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:16]


def official_issue_key(row: dict[str, str]) -> str:
    raw = "|".join([row["skill_id"], row["skill_name"], row["pattern_id"],
                     row["academic_code"], row["pattern"], row["classification"], row["severity"]])
    return "slb:" + hashlib.sha256(raw.encode()).hexdigest()[:16]


def is_candidate_source_verified(cand: dict) -> tuple[bool, str]:
    repo = (cand.get("repo_url") or "").strip()
    sha = (cand.get("source_sha256") or "").strip()
    path = (cand.get("local_path") or cand.get("skill_path") or cand.get("skill_subdir") or "").strip()
    reasons: list[str] = []
    if not repo:
        reasons.append("missing repo")
    if not sha or not _HEX64.fullmatch(sha):
        reasons.append("missing/invalid source_sha256 (need 64 hex)")
    if not path:
        reasons.append("missing skill path")
    if reasons:
        return False, "; ".join(reasons)
    return True, "repo+64hex_sha+path"


def load_official_by_skill(p: Path) -> dict[str, dict]:
    if not p.exists():
        return {}
    out: dict[str, dict] = {}
    with p.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            k = obj.get("official_skill_name") or obj.get("skill_name")
            if k:
                out[str(k)] = obj
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Recover OFFICIAL_SKILL_BOUND for 487 official skills")
    ap.add_argument("--issues", type=Path, default=DEFAULT_ISSUES)
    ap.add_argument("--skills", type=Path, default=DEFAULT_SKILLS)
    ap.add_argument("--candidates", type=Path, default=DEFAULT_CANDS)
    ap.add_argument("--official-evidence", type=Path, default=DEFAULT_OFFICIAL)
    ap.add_argument("--out", type=Path, default=OUT)
    ap.add_argument("--check", action="store_true", help="assert only, no write")
    args = ap.parse_args()

    issues = list(csv.DictReader(args.issues.open(encoding="utf-8", newline="")))
    skills = list(csv.DictReader(args.skills.open(encoding="utf-8", newline="")))
    cands: list[dict] = []
    if args.candidates.exists():
        with args.candidates.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    cands.append(json.loads(line))

    assert len(issues) == 1708, f"issues {len(issues)} != 1708"
    assert len(skills) == 520, f"skills {len(skills)} != 520"
    issue_names = {r["skill_name"] for r in issues}
    assert len(issue_names) == 487

    # per-skill aggregation
    by_name_issues: dict[str, list[dict]] = defaultdict(list)
    for r in issues:
        by_name_issues[r["skill_name"]].append(r)
    by_name_skills: dict[str, list[dict]] = defaultdict(list)
    for r in skills:
        by_name_skills[r["skill_name"]].append(r)

    cand_by_name: dict[str, list[dict]] = defaultdict(list)
    for c in cands:
        cand_by_name[c.get("skill_name", "")].append(c)

    official_by_skill = load_official_by_skill(args.official_evidence)

    rows: list[dict] = []
    for name in sorted(issue_names):
        iss = by_name_issues[name]
        sks = by_name_skills[name]
        skill_ids = sorted({r["skill_id"] for r in iss})
        classifications = sorted({r["classification"] for r in iss})
        keys = sorted({official_issue_key(r) for r in iss})
        issue_count = sum(int(r["issue_count"]) for r in sks)

        lst = cand_by_name.get(name, [])
        # skill-level binding (ALLOW skill_name -> repo for this file only)
        off = official_by_skill.get(name)
        if not lst:
            status = "SOURCE_NOT_FOUND"
            method = "no candidate with this skill_name in 165 pool; no official evidence"
            confidence = "unverified"
        elif len(lst) > 1:
            status = "BOUND_AMBIGUOUS"
            method = f"ambiguous: {len(lst)} candidates share skill_name"
            confidence = "ambiguous"
        else:
            cand = lst[0]
            verified, reason = is_candidate_source_verified(cand)
            if not verified:
                status = "SOURCE_NOT_FOUND"
                method = f"name match but candidate not verified: {reason}"
                confidence = "unverified"
            else:
                if not off:
                    status = "CANDIDATE_SOURCE_VERIFIED"
                    method = f"candidate verified ({reason}) but no official skill evidence"
                    confidence = "candidate_only"
                else:
                    # official skill evidence must have repo/path/revision(40/64hex)
                    repo = (off.get("repo_url") or off.get("repo") or "").strip()
                    path = (off.get("skill_path") or off.get("local_path") or "").strip()
                    rev = (off.get("revision") or off.get("commit_sha") or off.get("commit") or "").strip()
                    sha = (off.get("source_sha256") or "").strip()
                    ok = bool(repo and path and (re.fullmatch(r"[0-9a-fA-F]{40}", rev or "") or re.fullmatch(r"[0-9a-fA-F]{64}", rev or "") or (sha and _HEX64.fullmatch(sha))))
                    if not ok:
                        status = "CANDIDATE_SOURCE_VERIFIED"
                        method = "candidate verified but official skill evidence incomplete"
                        confidence = "candidate_only"
                    else:
                        # compare with candidate
                        cand_repo = (cand.get("repo_url") or "").strip()
                        cand_path = (cand.get("skill_subdir") or cand.get("local_path") or "").strip()
                        cand_sha = (cand.get("source_sha256") or "").strip()
                        if off.get("repo_url", off.get("repo","")) and off.get("repo_url", off.get("repo","")).strip() != cand_repo:
                            status = "CANDIDATE_SOURCE_VERIFIED"
                            method = "official repo mismatch"
                            confidence = "mismatch"
                        elif path != cand_path:
                            status = "CANDIDATE_SOURCE_VERIFIED"
                            method = f"official path mismatch official={path!r} cand={cand_path!r}"
                            confidence = "mismatch"
                        else:
                            # allow sha-based EXACT when candidate has no hex revision
                            if _HEX64.fullmatch(sha or "") and cand_sha.lower() == sha.lower():
                                status = "BOUND_EXACT"
                                method = "official repo/path/sha consistent with candidate"
                                confidence = "exact"
                            elif rev and cand.get("revision","").strip().lower() == rev.lower():
                                status = "BOUND_EXACT"
                                method = "official repo/path/revision consistent"
                                confidence = "exact"
                            else:
                                status = "CANDIDATE_SOURCE_VERIFIED"
                                method = "candidate verified but sha/revision mismatch"
                                confidence = "mismatch"

        # repo/commit/path until recovered
        repo_url = (off.get("repo_url") or off.get("repo") or "") if off else ""
        commit_sha = (off.get("revision") or off.get("commit_sha") or off.get("commit") or "") if off else ""
        skill_path = (off.get("skill_path") or off.get("local_path") or "") if off else ""
        source_sha256 = (off.get("source_sha256") or "") if off else ""

        rows.append({
            "official_skill_name": name,
            "official_skill_ids": skill_ids,
            "classifications": classifications,
            "raw_issue_rows": len(iss),
            "sanitized_issue_keys": keys,
            "sanitized_keys_count": len(keys),
            "issue_count_from_skills_dataset": issue_count,
            "repo_url": repo_url,
            "commit_sha": commit_sha,
            "skill_path": skill_path,
            "source_sha256": source_sha256,
            "status": status,
            "binding_method": method,
            "binding_confidence": confidence,
            "candidate_ids": [c["candidate_id"] for c in lst] if lst else [],
        })

    c = Counter(r["status"] for r in rows)
    # Current expectation with 0 overlap: all SOURCE_NOT_FOUND
    # Keep as assertion for now; when recovery begins these will shift
    summary = {
        "generated_at": "2026-08-26",
        "official_skills": 487,
        "issues": 1708,
        "unique_issue_keys": len({official_issue_key(r) for r in issues}),
        "candidate_pool": len(cands),
        "SOURCE_NOT_FOUND": c.get("SOURCE_NOT_FOUND", 0),
        "CANDIDATE_SOURCE_VERIFIED": c.get("CANDIDATE_SOURCE_VERIFIED", 0),
        "BOUND_AMBIGUOUS": c.get("BOUND_AMBIGUOUS", 0),
        "BOUND_EXACT": c.get("BOUND_EXACT", 0),
        "official_bound_skill_count": c.get("BOUND_EXACT", 0),
        "official_issue_bound_DIRECT": 0,
        "note": "OFFICIAL_SKILL_BOUND layer only; OFFICIAL_ISSUE_BOUND requires per-evidence File:Line/sink and expansion of 924 sanitized collisions (evidence key = sha256(sanitized_key|repo|revision|skill_path|file_path|line_start|line_end)). Do not use skill_name fallback for issue EXACT.",
    }

    if args.check:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        print(f"CHECK: 487 skills -> {dict(c)}; unique_keys {summary['unique_issue_keys']}")
        return 0

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8", newline="\n") as out:
        for r in rows:
            out.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")
    # also write summary sidecar
    (args.out.parent / "official_skill_sources_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"wrote {args.out} ({len(rows)} rows)")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
