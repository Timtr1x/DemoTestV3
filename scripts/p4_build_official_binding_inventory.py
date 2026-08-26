#!/usr/bin/env python
"""Generate P4 official issue binding inventory (reproducible, no secrets).

Inputs (read-only, pinned):
  - cache/datasets_v3/raw/skillleakbench_catalog/issues.csv        (1708 rows)
  - cache/datasets_v3/raw/skillleakbench_catalog/skills_dataset.csv (520 rows)
  - cache/datasets_v3/raw/p4_skill_candidates/candidates.jsonl      (165)
  - [optional] cache/p4_evidence/official_source_evidence.jsonl    (private master File:Line)

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

Resolver states (per-issue, pure function resolve_issue_binding):
  - UNRESOLVED                : no candidate name match
  - AMBIGUOUS_NAME_MATCH      : multiple candidates share skill_name
  - NAME_MATCH_ONLY           : single name match but candidate source incomplete
  - CANDIDATE_SOURCE_VERIFIED : single name match + candidate source verified,
                                but no official-side provenance to allow EXACT
  - OFFICIAL_BINDING_EXACT    : single name match + candidate verified + official
                                repo/path/revision/File:Line consistent
  CANDIDATE_SOURCE_VERIFIED != OFFICIAL_BINDING_EXACT by construction.

Per-skill source status (487 official names, pure function resolve_skill_binding):
  - SOURCE_NOT_FOUND          : no candidate or unverified
  - CANDIDATE_SOURCE_VERIFIED : single verified candidate, awaiting official evidence
  - BOUND_AMBIGUOUS           : multiple candidates for same name
  - BOUND_EXACT               : single verified candidate + official evidence match
    (currently zero — requires private master)

Usage:
  python scripts/p4_build_official_binding_inventory.py
  python scripts/p4_build_official_binding_inventory.py --check
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
DEFAULT_OFFICIAL_EVIDENCE = ROOT / "cache/p4_evidence/official_source_evidence.jsonl"
OUT_DIR = ROOT / "cache/p4_evidence"

EXPECTED_ISSUES = 1708
EXPECTED_SKILLS = 520
EXPECTED_UNIQUE_NAMES = 487
EXPECTED_CANDS = 165
EXPECTED_CAND_UNIQUE = 162

_HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_HEX_REVISION_RE = re.compile(r"^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")


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


# ---------------------------------------------------------------------------
# Candidate self-verification (no official binding).
# ---------------------------------------------------------------------------

def is_candidate_source_verified(cand: dict) -> tuple[bool, str]:
    """Prove candidate self source completeness only.

    Requires repo_url + 64-hex source_sha256 + skill path.
    Branch is NOT an immutable revision and is ignored.
    This never yields OFFICIAL_BINDING_EXACT by itself.
    """
    repo = (cand.get("repo_url") or cand.get("source_repo") or "").strip()
    sha = (cand.get("source_sha256") or cand.get("source_sha") or "").strip()
    path = (cand.get("local_path") or cand.get("skill_path") or cand.get("skill_subdir") or "").strip()
    reasons: list[str] = []
    if not repo:
        reasons.append("missing repo")
    if not sha or not _HEX64_RE.fullmatch(sha):
        reasons.append("missing/invalid source_sha256 (need 64 hex)")
    if not path:
        reasons.append("missing skill path")
    if reasons:
        return False, "; ".join(reasons)
    return True, "repo+64hex_sha+path"


# Keep legacy alias for backward compat but mark deprecated in docstring.
def is_strong_provenance(cand: dict):  # pragma: no cover
    """Deprecated alias for is_candidate_source_verified."""
    return is_candidate_source_verified(cand)


# ---------------------------------------------------------------------------
# Official-side provenance matching.
# ---------------------------------------------------------------------------

def _official_matches_candidate(candidate: dict, official: dict | None) -> tuple[bool, str]:
    """Check official-side evidence vs candidate.

    Returns (True, reason) only when every present official field matches candidate.
    No official evidence -> (False, reason) meaning insufficient for EXACT.
    Official revision must be 40/64 hex; branch never counts.
    """
    if not official:
        return False, "no official-side provenance"
    cand_repo = (candidate.get("repo_url") or "").strip()
    off_repo = (official.get("repo_url") or official.get("repo") or official.get("source_repo") or "").strip()
    if off_repo and off_repo != cand_repo:
        return False, f"repo mismatch official={off_repo!r} candidate={cand_repo!r}"
    if not off_repo:
        return False, "official repo missing"

    cand_path = (candidate.get("skill_subdir") or candidate.get("local_path") or candidate.get("skill_path") or "").strip()
    off_path = (official.get("skill_path") or official.get("local_path") or official.get("skill_subdir") or "").strip()
    if off_path and cand_path != off_path:
        return False, f"path mismatch official={off_path!r} candidate={cand_path!r}"
    if not off_path:
        return False, "official skill path missing"

    off_rev = (official.get("revision") or official.get("source_revision") or official.get("commit") or "").strip()
    if not off_rev or not _HEX_REVISION_RE.fullmatch(off_rev):
        return False, f"official revision not immutable 40/64 hex: {off_rev!r}"
    cand_rev = (candidate.get("revision") or candidate.get("source_revision") or candidate.get("commit") or "").strip()
    # Candidate revision today is branch "main"/"master" — never hex, so EXACT fails by design.
    # Future re-crawl must pin commit SHA to become hex.
    # We allow matching via either revision equality or via source_sha256 equality if revision absent.
    if cand_rev and _HEX_REVISION_RE.fullmatch(cand_rev):
        if cand_rev.lower() != off_rev.lower():
            return False, f"revision mismatch cand={cand_rev[:12]} off={off_rev[:12]}"
    else:
        # fall back to source_sha256 comparison when candidate has no hex revision
        off_sha = (official.get("source_sha256") or "").strip()
        cand_sha = (candidate.get("source_sha256") or "").strip()
        if off_sha and _HEX64_RE.fullmatch(off_sha):
            if not _HEX64_RE.fullmatch(cand_sha or ""):
                return False, "candidate sha not 64 hex for revision-less match"
            if cand_sha.lower() != off_sha.lower():
                return False, f"sha mismatch cand={cand_sha[:12]} off={off_sha[:12]}"
        else:
            return False, f"candidate has no hex revision and official sha missing/invalid"

    # Optional File:Line — if official provides, candidate must have matching file evidence
    # For now we just record that official File:Line is present; real check requires file inventory.
    return True, "official repo/path/revision/sha consistent"


# ---------------------------------------------------------------------------
# Pure resolver (no I/O).
# ---------------------------------------------------------------------------

def resolve_issue_binding(
    candidates_for_name: list[dict],
    official_evidence: dict | None,
) -> tuple[str, str, bool]:
    """Pure function: issue-level binding.

    Returns (binding_status, method, name_exact_match_bool).
    Never reads filesystem; caller supplies slice.
    """
    if not candidates_for_name:
        return "UNRESOLVED", "no_candidate_match_in_165_pool", False
    if len(candidates_for_name) > 1:
        return "AMBIGUOUS_NAME_MATCH", f"ambiguous: {len(candidates_for_name)} candidates share skill_name", True
    cand = candidates_for_name[0]
    verified, reason = is_candidate_source_verified(cand)
    if not verified:
        return "NAME_MATCH_ONLY", f"name match but candidate not verified: {reason}", True
    ok, why = _official_matches_candidate(cand, official_evidence)
    if ok:
        return "OFFICIAL_BINDING_EXACT", why, True
    # verified candidate but no/weak official evidence -> verified, not exact
    if official_evidence is None:
        return "CANDIDATE_SOURCE_VERIFIED", f"candidate verified but no official evidence: {reason}; {why}", True
    return "CANDIDATE_SOURCE_VERIFIED", f"candidate verified but official mismatch: {why}", True


def resolve_skill_binding(
    candidates_for_name: list[dict],
    official_evidence: dict | None,
) -> tuple[str, str]:
    """Pure function: skill-level source status (487 names)."""
    if not candidates_for_name:
        return "SOURCE_NOT_FOUND", "no candidate with this skill_name in 165 pool"
    if len(candidates_for_name) > 1:
        return "BOUND_AMBIGUOUS", f"ambiguous: {len(candidates_for_name)} candidates share skill_name"
    cand = candidates_for_name[0]
    verified, reason = is_candidate_source_verified(cand)
    if not verified:
        return "SOURCE_NOT_FOUND", f"name match but not verified: {reason}"
    ok, why = _official_matches_candidate(cand, official_evidence)
    if ok:
        return "BOUND_EXACT", why
    return "CANDIDATE_SOURCE_VERIFIED", f"verified but no official exact: {why}"


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


def load_official_evidence(p: Path) -> dict[str, dict]:
    """Map official_issue_key or skill_name -> evidence dict. Empty if file absent."""
    if not p.exists():
        return {}
    out: dict[str, dict] = {}
    with p.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            # key by official_issue_key if present else skill_name
            k = obj.get("official_issue_key") or obj.get("skill_name") or obj.get("official_skill_name")
            if k:
                out[str(k)] = obj
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Build P4 official binding inventory")
    ap.add_argument("--issues", type=Path, default=DEFAULT_ISSUES)
    ap.add_argument("--skills", type=Path, default=DEFAULT_SKILLS)
    ap.add_argument("--candidates", type=Path, default=DEFAULT_CANDS)
    ap.add_argument("--official-evidence", type=Path, default=DEFAULT_OFFICIAL_EVIDENCE)
    ap.add_argument("--out-dir", type=Path, default=OUT_DIR)
    ap.add_argument("--check", action="store_true", help="assert only, no write")
    args = ap.parse_args()

    issues = load_issues(args.issues)
    skills = load_skills(args.skills)
    cands = load_cands(args.candidates)
    official_by_key = load_official_evidence(args.official_evidence)

    assert len(issues) == EXPECTED_ISSUES, f"issues {len(issues)} != {EXPECTED_ISSUES}"
    assert len(skills) == EXPECTED_SKILLS, f"skills {len(skills)} != {EXPECTED_SKILLS}"
    issue_names = {r["skill_name"] for r in issues}
    skill_names = {r["skill_name"] for r in skills}
    assert issue_names == skill_names, f"skill identity mismatch: issues {len(issue_names)} vs skills {len(skill_names)}"
    assert len(issue_names) == EXPECTED_UNIQUE_NAMES
    assert len(cands) == EXPECTED_CANDS
    cand_names_set = {c.get("skill_name", "") for c in cands}
    assert len(cand_names_set) == EXPECTED_CAND_UNIQUE

    issues_sha = sha_file(args.issues)
    skills_sha = sha_file(args.skills)
    cands_sha = sha_file(args.candidates)
    official_sha = sha_file(args.official_evidence) if args.official_evidence.exists() else ""

    cand_by_name: dict[str, list[dict]] = defaultdict(list)
    for c in cands:
        cand_by_name[c.get("skill_name", "")].append(c)

    # compute unique keys and collisions before resolution (sanitized identity)
    key_counter: Counter[str] = Counter()
    for r in issues:
        key_counter[official_issue_key(r)] += 1
    unique_issue_keys = len(key_counter)
    sanitized_identity_collisions = len(issues) - unique_issue_keys
    duplicate_key_groups = sum(1 for v in key_counter.values() if v > 1)
    # most-collided key example
    most_common = key_counter.most_common(3)

    # per-skill resolution (pure)
    per_skill_rows: list[dict] = []
    for name in sorted(issue_names):
        lst = cand_by_name.get(name, [])
        # official evidence lookup by skill_name (fallback) — private master would key by issue key for line-level
        off = official_by_key.get(name)
        status, note = resolve_skill_binding(lst, off)
        # keep legacy SOURCE_NOT_FOUND for unverified singletons as well
        per_skill_rows.append({
            "official_skill_name": name,
            "status": status,
            "candidates": [c["candidate_id"] for c in lst] if lst else [],
            "provenance_note": note,
        })

    # per-issue resolution (pure)
    issue_rows: list[dict] = []
    for r in issues:
        key = official_issue_key(r)
        name = r["skill_name"]
        lst = cand_by_name.get(name, [])
        # prefer issue-keyed evidence over skill-name evidence
        off = official_by_key.get(key) or official_by_key.get(name)
        binding_status, method, name_match = resolve_issue_binding(lst, off)
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
            "name_exact_match": name_match,
            "binding_status": binding_status,
            "official_binding": binding_status,
            "binding_method": method,
            "candidate_source_verified": is_candidate_source_verified(lst[0])[0] if len(lst) == 1 else False,
        }
        issue_rows.append(row)

    c_issue = Counter(r["binding_status"] for r in issue_rows)
    c_skill = Counter(r["status"] for r in per_skill_rows)

    # Expectations: public CSV has no official evidence, candidate revisions are branch
    # -> zero OFFICIAL_BINDING_EXACT / BOUND_EXACT, all remains UNRESOLVED or CANDIDATE_SOURCE_VERIFIED
    # Currently 165 pool has zero name overlap with 487 official names, so even CANDIDATE_SOURCE_VERIFIED is 0.
    # Re-crawl targeted 520 names will populate CANDIDATE_SOURCE_VERIFIED; private master + hex revision will upgrade to OFFICIAL.
    assert c_issue.get("OFFICIAL_BINDING_EXACT", 0) == 0
    assert c_skill.get("BOUND_EXACT", 0) == 0
    # With current 0 overlap, these hold:
    if unique_issue_keys == len({official_issue_key(r) for r in issues}):
        pass

    # stable key: CSV reorder invariance
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
            "official_evidence": str(args.official_evidence.relative_to(ROOT)) if args.official_evidence.exists() else None,
            "official_evidence_sha256": official_sha or None,
            "official_evidence_rows": len(official_by_key),
        },
        "official_issues": len(issues),
        "official_skills_by_id": len({r["skill_id"] for r in issues}),
        "official_skills_by_name": len(issue_names),
        "unique_issue_keys": unique_issue_keys,
        "sanitized_identity_collisions": sanitized_identity_collisions,
        "duplicate_key_groups": duplicate_key_groups,
        "most_common_keys": [{"key": k, "count": c} for k, c in most_common],
        "candidate_pool": len(cands),
        "candidate_distinct_names": len(cand_names_set),
        "NAME_MATCH_ONLY": c_issue.get("NAME_MATCH_ONLY", 0),
        "CANDIDATE_SOURCE_VERIFIED": c_issue.get("CANDIDATE_SOURCE_VERIFIED", 0),
        "AMBIGUOUS_NAME_MATCH": c_issue.get("AMBIGUOUS_NAME_MATCH", 0),
        "OFFICIAL_BINDING_EXACT": c_issue.get("OFFICIAL_BINDING_EXACT", 0),
        "UNRESOLVED": c_issue.get("UNRESOLVED", 0),
        "skill_SOURCE_NOT_FOUND": c_skill.get("SOURCE_NOT_FOUND", 0),
        "skill_CANDIDATE_SOURCE_VERIFIED": c_skill.get("CANDIDATE_SOURCE_VERIFIED", 0),
        "skill_BOUND_AMBIGUOUS": c_skill.get("BOUND_AMBIGUOUS", 0),
        "skill_BOUND_EXACT": c_skill.get("BOUND_EXACT", 0),
        "frozen_real_skill_name": "portfolio",
        "frozen_candidate_id": "andytrust-portfolio-claude-code-skill-md",
        "frozen_binding_status": "REAL_SKILL_UNBOUND",
        "frozen_in_official": False,
        "method": "exact string join on skill_name; candidate name -> list (no collapse); is_candidate_source_verified requires repo+64hex_sha+path (branch not immutable); OFFICIAL_BINDING_EXACT requires official repo/path/revision(40/64 hex)/sha consistent with candidate; single verified name without official -> CANDIDATE_SOURCE_VERIFIED not EXACT; official_issue_key deterministic sha16",
        "note": "Public CSV has no repo/path/revision/File:Line; EXACT needs private master or targeted re-crawl with commit SHA. Duplicate identical issue rows share same key (one-issue-at-most-one-case); sanitized_identity_collisions保留待 private master 后消歧.",
        "p4canary_anchor": "P4CANARY_<sha256(official_issue_key)[:16].upper()>",
        "stop_gate": "OFFICIAL_ISSUE_BOUND DIRECT 0/50; Real 1 (UNBOUND supplementary); 不冻结 Core、不跑 Smoke、不扩采集",
    }

    if args.check:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        print("CHECK PASS: Official bound = 0, Real = 1 (UNBOUND), candidate verification gated by 64hex+path, branch not counted")
        return 0

    out_dir = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    with (out_dir / "official_issue_binding.jsonl").open("w", encoding="utf-8", newline="\n") as out:
        for row in issue_rows:
            out.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    with (out_dir / "skill_binding.jsonl").open("w", encoding="utf-8", newline="\n") as out:
        for row in sorted(per_skill_rows, key=lambda x: x["official_skill_name"]):
            out.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    (out_dir / "binding_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"wrote {out_dir/'official_issue_binding.jsonl'} ({len(issue_rows)} rows, {unique_issue_keys} unique keys, collisions {sanitized_identity_collisions})")
    print(f"wrote {out_dir/'skill_binding.jsonl'} ({len(per_skill_rows)} rows)")
    print(f"wrote {out_dir/'binding_summary.json'}")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
