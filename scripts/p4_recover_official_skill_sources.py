#!/usr/bin/env python
"""Recover OFFICIAL_SKILL_BOUND identity for 487 official skills (no execution).

Official-first: BOUND_EXACT does NOT require the 165 candidate pool.
Once private master / official metadata provides repo + immutable commit +
skill path, DemoTest can acquire/verify the tree and compute source_sha256
itself. The candidate pool is only a local reuse cache.

Inputs (read-only, pinned):
  - cache/datasets_v3/raw/skillleakbench_catalog/issues.csv
  - cache/datasets_v3/raw/skillleakbench_catalog/skills_dataset.csv
  - cache/datasets_v3/raw/p4_skill_candidates/candidates.jsonl  (165, may be 0-overlap)
  - [optional] cache/p4_evidence/official_source_evidence.jsonl
      One JSON per line, each evidence belongs to a skill. Multiple evidence
      rows for the same skill are aggregated as list[evidence]; conflicting
      repo/path/revision among them -> BOUND_AMBIGUOUS (no last-write-wins).

Output (gitignored, under cache/p4_evidence/):
  - official_skill_sources.jsonl  (487 rows, one per official_skill_name)
  - official_skill_sources_summary.json

Each row contains:
  official_skill_name
  official_skill_key: stable identity "osk:<sha16>" over sorted(skill_ids)|skill_name
  official_skill_ids: list[str] (1 or 2 for dual-class skills)
  classifications, raw_issue_rows, sanitized_issue_keys, ...
  repo_url, commit_sha, skill_path, source_sha256  (from verified official evidence)
  status: SOURCE_NOT_FOUND | CANDIDATE_SOURCE_VERIFIED | OFFICIAL_SOURCE_DECLARED
          | BOUND_AMBIGUOUS | SOURCE_OBJECT_VERIFIED
          OFFICIAL_SOURCE_DECLARED = repo/commit/path declared but tree not yet acquired/verified (never verified)
          SOURCE_OBJECT_VERIFIED = repo@immutable_commit acquired + skill_path exists + source_sha256 recomputed (object verified)
                                    BUT mapping provenance not yet verified as OFFICIAL; use mapping_audit to promote.
  mapping_provenance: {mapping_source_type, mapping_source_uri, mapping_source_revision,
                       mapping_evidence_sha256, mapping_method, mapping_confidence}
                      Required for promotion SOURCE_OBJECT_VERIFIED -> OFFICIAL_SKILL_BOUND.
                      See docs/P4_MAPPING_PROVENANCE.md and cache/p4_evidence/mapping_audit.jsonl.
  binding_method, binding_confidence
  candidate_ids: list[str]
  evidence_count, distinct_evidence_keys

Semantics:
  - Two-tier trust (see review 2026-08-26):
    SOURCE_OBJECT_VERIFIED = DECLARED_MAPPING + SOURCE_VERIFIED (repo/commit/path/hash recomputed).
    OFFICIAL_SKILL_BOUND   = VERIFIED_OFFICIAL_MAPPING + SOURCE_VERIFIED
                           (mapping must come from private master / official metadata / Zenodo / author artifact
                            or independently corroborated official source, recorded in mapping_provenance).
    Resolver without external audit defaults to SOURCE_OBJECT_VERIFIED; promotion to
    OFFICIAL_SKILL_BOUND requires a mapping_provenance record marked VERIFIED_OFFICIAL_MAPPING.
  - OFFICIAL_SKILL_BOUND is still the skill -> repo/commit/path level (not issue-level).
    Issue-level requires File:Line/sink per evidence and expansion of
    924 collisions: evidence_key = sha256(sanitized_key|repo|revision|skill_path|file|ls|le)
    and also requires OFFICIAL_SKILL_BOUND as prerequisite.
  - is_candidate_source_verified requires repo+64hex+path; branch never counts.
    CANDIDATE_SOURCE_VERIFIED never yields BOUND_EXACT/SOURCE_OBJECT_VERIFIED by itself.
  - SOURCE_OBJECT_VERIFIED requires DemoTest to actually acquire repo@immutable_commit and
    recompute source_sha256 over the skill_path subtree. Sidecar repo/commit/path/source_sha
    alone yields OFFICIAL_SOURCE_DECLARED, never verified. Same (repo,commit,path) with
    multiple distinct non-empty source_sha -> BOUND_AMBIGUOUS. Hash drift or missing path
    under the acquired tree -> fail-closed.
  - official evidence aggregation: skill -> list[evidence]; distinct
    (repo,commit,path) keys are deduplicated; conflict -> BOUND_AMBIGUOUS.

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
_HEX_REV = re.compile(r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def official_issue_key(row: dict[str, str]) -> str:
    raw = "|".join([row["skill_id"], row["skill_name"], row["pattern_id"],
                     row["academic_code"], row["pattern"], row["classification"], row["severity"]])
    return "slb:" + sha256_hex(raw)[:16]


def official_skill_key(skill_name: str, skill_ids: list[str]) -> str:
    """Stable identity for a skill source; not just skill_name."""
    raw = "|".join(sorted(skill_ids)) + "|" + skill_name
    return "osk:" + sha256_hex(raw)[:16]


def is_hex_revision(s: str) -> bool:
    return bool(s and _HEX_REV.fullmatch(s.strip()))


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


def normalize_repo(u: str) -> str:
    return (u or "").strip().rstrip("/")


def evidence_tuple(ev: dict) -> tuple[str, str, str, str]:
    """Canonical tuple for deduplication: (repo, commit lower, skill_path, sha lower)."""
    repo = normalize_repo(ev.get("repo_url") or ev.get("repo") or ev.get("source_repo") or "")
    # commit may be under revision / commit_sha / commit
    rev = (ev.get("commit_sha") or ev.get("revision") or ev.get("commit") or ev.get("source_revision") or "").strip()
    path = (ev.get("skill_path") or ev.get("local_path") or ev.get("skill_subdir") or "").strip()
    sha = (ev.get("source_sha256") or ev.get("source_sha") or "").strip()
    return (repo, rev.lower(), path, sha.lower())


def load_official_by_skill_list(p: Path) -> dict[str, list[dict]]:
    """Load skill -> list[evidence]. Never last-write-wins."""
    if not p.exists():
        return {}
    out: dict[str, list[dict]] = defaultdict(list)
    with p.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            k = obj.get("official_skill_name") or obj.get("skill_name") or obj.get("official_skill_key")
            if not k:
                continue
            out[str(k)].append(obj)
    return dict(out)


def compute_tree_sha_for_skill_path(tree_root: Path, skill_path: str) -> tuple[str | None, str]:
    """Hash the subtree at tree_root/skill_path (all files recursively).

    Returns (sha256 hex of sorted relative_path|file_sha, reason).
    Aligned with demotest.datasets.source_lock.hash_raw_snapshot:
      - symlink no-follow (is_symlink() skipped, rglob does not follow dir symlinks)
      - exclude .git / __pycache__ at any depth
      - blob = "\\n".join(f"{rel}|{sha256}") sorted by rel ("/" normalized)
    If skill_path does not exist -> (None, reason).
    """
    if not tree_root.exists():
        return None, f"tree root missing: {tree_root}"
    skill_dir = tree_root / skill_path if skill_path else tree_root
    # symlink no-follow: skill_path itself must not be a symlink
    if skill_dir.is_symlink():
        return None, f"skill_path is a symlink (no-follow): {skill_path!r}"
    if not skill_dir.exists():
        return None, f"skill_path not found under tree: {skill_path!r}"
    if not skill_dir.is_dir():
        # single file case — file symlink already rejected above
        if skill_dir.is_symlink():
            return None, f"skill file is a symlink (no-follow): {skill_path!r}"
        data = skill_dir.read_bytes()
        return hashlib.sha256(data).hexdigest(), "single file"
    # collect files — do not follow symlinks, skip excluded dirs
    exclude = {".git", "__pycache__"}
    files: list[Path] = []
    for p in skill_dir.rglob("*"):
        # no-follow: skip any symlink (file or dir)
        try:
            if p.is_symlink():
                continue
        except OSError:
            continue
        if not p.is_file():
            continue
        try:
            rel_parts = p.relative_to(skill_dir).parts
        except ValueError:
            continue
        if any(part in exclude for part in rel_parts):
            continue
        files.append(p)
    if not files:
        return None, f"skill_path has no files: {skill_path!r}"
    file_hashes: list[tuple[str, str]] = []
    for p in sorted(files, key=lambda x: str(x.relative_to(skill_dir)).replace("\\", "/")):
        rel = str(p.relative_to(skill_dir)).replace("\\", "/")
        h = hashlib.sha256(p.read_bytes()).hexdigest()
        file_hashes.append((rel, h))
    blob = "\n".join(f"{rel}|{h}" for rel, h in file_hashes)
    return hashlib.sha256(blob.encode()).hexdigest(), f"hashed {len(file_hashes)} files"


def resolve_skill_source(
    skill_name: str,
    skill_ids: list[str],
    candidate_list: list[dict],
    evidence_list: list[dict],
    *,
    tree_root_resolver: callable | None = None,
) -> dict:
    """Pure resolver for one skill (no I/O except optional tree_root_resolver).

    Returns dict with keys: status, binding_method, binding_confidence,
    repo_url, commit_sha, skill_path, source_sha256, official_skill_key,
    evidence_count, distinct_keys, candidate_ids
    """
    official_skill_key_val = official_skill_key(skill_name, skill_ids)
    candidate_ids = [c.get("candidate_id", "") for c in candidate_list]

    # candidate verification (cache only)
    verified_candidates: list[dict] = []
    for c in candidate_list:
        ok, _ = is_candidate_source_verified(c)
        if ok:
            verified_candidates.append(c)
    has_verified_candidate = len(verified_candidates) > 0

    # evidence aggregation and conflict detection
    evidence_count = len(evidence_list)
    if evidence_count == 0:
        # no official evidence -> cannot be BOUND_EXACT regardless of candidate
        if not candidate_list:
            return {
                "official_skill_key": official_skill_key_val,
                "status": "SOURCE_NOT_FOUND",
                "binding_method": "no official evidence and no candidate with this skill_name in 165 pool",
                "binding_confidence": "unverified",
                "repo_url": "",
                "commit_sha": "",
                "skill_path": "",
                "source_sha256": "",
                "candidate_ids": candidate_ids,
                "evidence_count": 0,
                "distinct_evidence_keys": 0,
            }
        if len(candidate_list) > 1:
            return {
                "official_skill_key": official_skill_key_val,
                "status": "BOUND_AMBIGUOUS",
                "binding_method": f"ambiguous: {len(candidate_list)} candidates share skill_name; no official evidence to disambiguate",
                "binding_confidence": "ambiguous",
                "repo_url": "",
                "commit_sha": "",
                "skill_path": "",
                "source_sha256": "",
                "candidate_ids": candidate_ids,
                "evidence_count": 0,
                "distinct_evidence_keys": 0,
            }
        # single candidate
        if has_verified_candidate:
            return {
                "official_skill_key": official_skill_key_val,
                "status": "CANDIDATE_SOURCE_VERIFIED",
                "binding_method": "candidate verified (repo+64hex+path) but no official evidence",
                "binding_confidence": "candidate_only",
                "repo_url": "",
                "commit_sha": "",
                "skill_path": "",
                "source_sha256": "",
                "candidate_ids": candidate_ids,
                "evidence_count": 0,
                "distinct_evidence_keys": 0,
            }
        return {
            "official_skill_key": official_skill_key_val,
            "status": "SOURCE_NOT_FOUND",
            "binding_method": "single candidate but not verified and no official evidence",
            "binding_confidence": "unverified",
            "repo_url": "",
            "commit_sha": "",
            "skill_path": "",
            "source_sha256": "",
            "candidate_ids": candidate_ids,
            "evidence_count": 0,
            "distinct_evidence_keys": 0,
        }

    # has official evidence list; deduplicate by evidence_tuple
    # For conflict detection we consider (repo, commit, path) differing as conflict
    tuple_to_count: Counter[tuple] = Counter(evidence_tuple(ev) for ev in evidence_list)
    distinct = len(tuple_to_count)
    # also consider logical identity (repo, commit, path) without sha
    logical_keys = {(t[0], t[1], t[2]) for t in tuple_to_count}
    # Same (repo,commit,path) with multiple distinct non-empty source_sha -> ambiguous
    _sha_by_logical: dict[tuple, set[str]] = {}
    for _ev in evidence_list:
        _rt = evidence_tuple(_ev)
        _lk = (_rt[0], _rt[1], _rt[2])
        # sha may be under source_sha256 or source_sha
        _sha = (_ev.get("source_sha256") or _ev.get("source_sha") or "").strip().lower()
        if _sha and _HEX64.fullmatch(_sha):
            _sha_by_logical.setdefault(_lk, set()).add(_sha)
    for _lk, _shas in _sha_by_logical.items():
        if len(_shas) > 1:
            return {
                "official_skill_key": official_skill_key_val,
                "status": "BOUND_AMBIGUOUS",
                "binding_method": f"same repo/commit/path {_lk} has {len(_shas)} distinct non-empty source_sha values",
                "binding_confidence": "ambiguous",
                "repo_url": "",
                "commit_sha": "",
                "skill_path": "",
                "source_sha256": "",
                "candidate_ids": candidate_ids,
                "evidence_count": evidence_count,
                "distinct_evidence_keys": distinct,
            }

    if len(logical_keys) > 1:
        return {
            "official_skill_key": official_skill_key_val,
            "status": "BOUND_AMBIGUOUS",
            "binding_method": f"conflicting official evidence for same skill: {len(logical_keys)} distinct repo/commit/path tuples",
            "binding_confidence": "ambiguous",
            "repo_url": "",
            "commit_sha": "",
            "skill_path": "",
            "source_sha256": "",
            "candidate_ids": candidate_ids,
            "evidence_count": evidence_count,
            "distinct_evidence_keys": distinct,
        }
    # single logical key — pick representative evidence
    rep_tuple = next(iter(logical_keys))
    repo, commit, skill_path = rep_tuple
    # find representative raw evidence for sha
    rep_ev = None
    for ev in evidence_list:
        if evidence_tuple(ev)[:3] == (repo, commit, skill_path):
            rep_ev = ev
            break
    expected_sha = (rep_ev.get("source_sha256") or rep_ev.get("source_sha") or "").strip() if rep_ev else ""

    # branch-only check
    if not repo or not skill_path:
        return {
            "official_skill_key": official_skill_key_val,
            "status": "SOURCE_NOT_FOUND",
            "binding_method": f"official evidence incomplete: repo={bool(repo)} path={bool(skill_path)}",
            "binding_confidence": "unverified",
            "repo_url": repo,
            "commit_sha": commit,
            "skill_path": skill_path,
            "source_sha256": expected_sha,
            "candidate_ids": candidate_ids,
            "evidence_count": evidence_count,
            "distinct_evidence_keys": distinct,
        }
    if not is_hex_revision(commit):
        return {
            "official_skill_key": official_skill_key_val,
            "status": "SOURCE_NOT_FOUND",
            "binding_method": f"branch-only revision not immutable: {commit!r}",
            "binding_confidence": "unverified",
            "repo_url": repo,
            "commit_sha": commit,
            "skill_path": skill_path,
            "source_sha256": expected_sha,
            "candidate_ids": candidate_ids,
            "evidence_count": evidence_count,
            "distinct_evidence_keys": distinct,
        }

    # verify tree if resolver provided or local tree exists
    computed_sha: str | None = None
    verify_reason = ""
    # try to locate tree for this skill if tree_root_resolver supplied
    tree_root: Path | None = None
    if tree_root_resolver is not None:
        try:
            tree_root = tree_root_resolver(skill_name, official_skill_key_val, repo, commit, skill_path)
        except Exception as e:
            tree_root = None
            verify_reason = f"tree resolver error: {e}"
    else:
        # default locations: cache/p4_official_clones/<sanitized official_skill_key or skill_name>
        # osk:xxx contains ':' which is not a valid Windows path, so use osk_xxx sanitized form as well.
        sanitized_osk = official_skill_key_val.replace(":", "_")
        cand_roots = [
            ROOT / "cache" / "p4_official_clones" / official_skill_key_val,
            ROOT / "cache" / "p4_official_clones" / sanitized_osk,
            ROOT / "cache" / "p4_official_clones" / skill_name.replace("/", "_"),
        ]
        for cr in cand_roots:
            if cr.exists():
                tree_root = cr
                break

    if tree_root is not None and tree_root.exists():
        computed_sha, verify_reason = compute_tree_sha_for_skill_path(tree_root, skill_path)
        if computed_sha is None:
            # path missing under tree -> fail closed
            return {
                "official_skill_key": official_skill_key_val,
                "status": "SOURCE_NOT_FOUND",
                "binding_method": f"official evidence points to missing path: {verify_reason}",
                "binding_confidence": "unverified",
                "repo_url": repo,
                "commit_sha": commit,
                "skill_path": skill_path,
                "source_sha256": expected_sha or "",
                "candidate_ids": candidate_ids,
                "evidence_count": evidence_count,
                "distinct_evidence_keys": distinct,
            }
        # if expected_sha provided, must match computed
        if expected_sha and _HEX64.fullmatch(expected_sha):
            if computed_sha.lower() != expected_sha.lower():
                return {
                    "official_skill_key": official_skill_key_val,
                    "status": "SOURCE_NOT_FOUND",
                    "binding_method": f"hash drift: expected {expected_sha[:12]}.. computed {computed_sha[:12]}..",
                    "binding_confidence": "unverified",
                    "repo_url": repo,
                    "commit_sha": commit,
                    "skill_path": skill_path,
                    "source_sha256": computed_sha,
                    "candidate_ids": candidate_ids,
                    "evidence_count": evidence_count,
                    "distinct_evidence_keys": distinct,
                }
        # tree verified -> source_sha is computed
        final_sha = computed_sha
    else:
        # No local tree acquired -> OFFICIAL_SOURCE_DECLARED, never BOUND_EXACT
        if expected_sha and _HEX64.fullmatch(expected_sha):
            return {
                "official_skill_key": official_skill_key_val,
                "status": "OFFICIAL_SOURCE_DECLARED",
                "binding_method": "official repo/commit/path/source_sha declared but tree not yet acquired/verified (awaits acquire + recompute)",
                "binding_confidence": "declared",
                "repo_url": repo,
                "commit_sha": commit,
                "skill_path": skill_path,
                "source_sha256": expected_sha.lower(),
                "candidate_ids": candidate_ids,
                "evidence_count": evidence_count,
                "distinct_evidence_keys": distinct,
            }
        else:
            if expected_sha:
                return {
                    "official_skill_key": official_skill_key_val,
                    "status": "SOURCE_NOT_FOUND",
                    "binding_method": "official evidence has valid repo/commit/path but source_sha256 invalid and tree not acquired",
                    "binding_confidence": "unverified",
                    "repo_url": repo,
                    "commit_sha": commit,
                    "skill_path": skill_path,
                    "source_sha256": expected_sha,
                    "candidate_ids": candidate_ids,
                    "evidence_count": evidence_count,
                    "distinct_evidence_keys": distinct,
                }
            return {
                "official_skill_key": official_skill_key_val,
                "status": "OFFICIAL_SOURCE_DECLARED",
                "binding_method": "official repo/commit/path declared but no source_sha256 yet and tree not acquired (awaits recompute)",
                "binding_confidence": "declared",
                "repo_url": repo,
                "commit_sha": commit,
                "skill_path": skill_path,
                "source_sha256": "",
                "candidate_ids": candidate_ids,
                "evidence_count": evidence_count,
                "distinct_evidence_keys": distinct,
            }

    # candidate consistency check: do NOT let candidate pollute official; just report mismatch but still allow official to succeed independently
    # If candidate exists and differs, we still return SOURCE_OBJECT_VERIFIED for object (official-first)
    # Promotion to OFFICIAL_SKILL_BOUND requires external mapping_provenance.
    method = f"official repo/commit/path verified (evidence_count={evidence_count}, distinct={distinct})"
    if verify_reason:
        method += f"; {verify_reason}"
    if candidate_list:
        if len(candidate_list) == 1 and has_verified_candidate:
            cand = verified_candidates[0]
            cand_repo = normalize_repo(cand.get("repo_url", ""))
            cand_path = (cand.get("skill_subdir") or cand.get("local_path") or cand.get("skill_path") or "").strip()
            cand_sha = (cand.get("source_sha256") or "").strip().lower()
            if cand_repo.lower() != repo.lower() or cand_path != skill_path or (cand_sha and cand_sha != final_sha.lower()):
                method += f"; candidate cache differs (official-first, not blocking)"
        elif len(candidate_list) > 1:
            method += "; multiple candidates exist, official-first resolution not blocked"

    # Two-tier status: object verified (SOURCE_OBJECT_VERIFIED). Mapping provenance
    # determines promotion to OFFICIAL_SKILL_BOUND; resolver alone stores provenance
    # passthrough if present on the evidence.
    mapping_prov = None
    if rep_ev is not None:
        # passthrough any mapping_provenance already attached to the representative evidence
        mp = rep_ev.get("mapping_provenance") or rep_ev.get("mapping") or None
        if isinstance(mp, dict) and mp:
            mapping_prov = {k: mp.get(k) for k in [
                "mapping_source_type", "mapping_source_uri", "mapping_source_revision",
                "mapping_evidence_sha256", "mapping_method", "mapping_confidence",
                "official_identity_fields", "candidate_identity_fields", "identity_match_basis",
                "audit Verdict".lower(),
            ] if mp.get(k) is not None}
            # keep original keys as-is for audit Verdict etc
            for k in ["audit_verdict", "auditVerdict", "verdict", "risk"]:
                if mp.get(k) is not None and k not in mapping_prov:
                    mapping_prov[k] = mp.get(k)
            # also preserve raw mapping_provenance for transparency
            mapping_prov["_raw"] = mp

    # Determine status: without VERIFIED_OFFICIAL_MAPPING we stay at SOURCE_OBJECT_VERIFIED
    status = "SOURCE_OBJECT_VERIFIED"
    confidence = "source_object_verified"
    # Look up external audit file cache/p4_evidence/mapping_audit.jsonl for upgrade
    # (loaded lazily per-skill via helper below if available)
    audit_verdict = None
    try:
        # rep_ev may carry explicit audit verdict
        if rep_ev is not None:
            audit_verdict = (rep_ev.get("mapping_provenance") or {}).get("audit_verdict") \
                or (rep_ev.get("mapping_provenance") or {}).get("verdict")
        if audit_verdict is None:
            # try external audit registry (module-level cache)
            from pathlib import Path as _P
            _audit_path = ROOT / "cache/p4_evidence/mapping_audit.jsonl"
            if _audit_path.exists():
                # lightweight per-call scan (20 rows) — acceptable
                for _line in _audit_path.read_text(encoding="utf-8").splitlines():
                    if not _line.strip():
                        continue
                    try:
                        _a = json.loads(_line)
                    except Exception:
                        continue
                    if _a.get("official_skill_name") == skill_name and _a.get("repo_url"):
                        # normalize compare
                        if normalize_repo(_a.get("repo_url", "")) == normalize_repo(repo) \
                                and (_a.get("commit_sha") or _a.get("revision") or "").strip().lower() == commit.lower() \
                                and (_a.get("skill_path") or "").strip() == skill_path:
                            audit_verdict = _a.get("audit_verdict") or _a.get("verdict")
                            if audit_verdict:
                                mapping_prov = _a.get("mapping_provenance") or mapping_prov or _a
                            break
    except Exception:
        audit_verdict = None

    if audit_verdict == "VERIFIED_OFFICIAL_MAPPING":
        status = "OFFICIAL_SKILL_BOUND"
        confidence = "official_mapping_verified"
        method += "; mapping_provenance=VERIFIED_OFFICIAL_MAPPING"
    else:
        # explicit that mapping not yet verified
        if audit_verdict in ("COPIED_FIXTURE", "INFERRED_MAPPING", "AMBIGUOUS", "REJECT"):
            method += f"; mapping_audit={audit_verdict} (not OFFICIAL)"
        else:
            method += "; mapping_provenance pending (SOURCE_OBJECT_VERIFIED only)"

    out = {
        "official_skill_key": official_skill_key_val,
        "status": status,
        "binding_method": method,
        "binding_confidence": confidence,
        "repo_url": repo,
        "commit_sha": commit,
        "skill_path": skill_path,
        "source_sha256": final_sha,
        "candidate_ids": candidate_ids,
        "evidence_count": evidence_count,
        "distinct_evidence_keys": distinct,
    }
    if mapping_prov is not None:
        out["mapping_provenance"] = mapping_prov
    if audit_verdict is not None:
        out["audit_verdict"] = audit_verdict
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Recover OFFICIAL_SKILL_BOUND for 487 official skills (official-first)")
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

    by_name_issues: dict[str, list[dict]] = defaultdict(list)
    for r in issues:
        by_name_issues[r["skill_name"]].append(r)
    by_name_skills: dict[str, list[dict]] = defaultdict(list)
    for r in skills:
        by_name_skills[r["skill_name"]].append(r)

    cand_by_name: dict[str, list[dict]] = defaultdict(list)
    for c in cands:
        cand_by_name[c.get("skill_name", "")].append(c)

    official_by_skill_list = load_official_by_skill_list(args.official_evidence)

    rows: list[dict] = []
    for name in sorted(issue_names):
        iss = by_name_issues[name]
        sks = by_name_skills[name]
        skill_ids = sorted({r["skill_id"] for r in iss})
        classifications = sorted({r["classification"] for r in iss})
        keys = sorted({official_issue_key(r) for r in iss})
        issue_count = sum(int(r["issue_count"]) for r in sks)

        lst = cand_by_name.get(name, [])
        ev_list = official_by_skill_list.get(name, [])

        resolved = resolve_skill_source(name, skill_ids, lst, ev_list)

        rows.append({
            "official_skill_name": name,
            "official_skill_key": resolved["official_skill_key"],
            "official_skill_ids": skill_ids,
            "classifications": classifications,
            "raw_issue_rows": len(iss),
            "sanitized_issue_keys": keys,
            "sanitized_keys_count": len(keys),
            "issue_count_from_skills_dataset": issue_count,
            "repo_url": resolved["repo_url"],
            "commit_sha": resolved["commit_sha"],
            "skill_path": resolved["skill_path"],
            "source_sha256": resolved["source_sha256"],
            "status": resolved["status"],
            "binding_method": resolved["binding_method"],
            "binding_confidence": resolved["binding_confidence"],
            "candidate_ids": resolved["candidate_ids"],
            "evidence_count": resolved["evidence_count"],
            "distinct_evidence_keys": resolved["distinct_evidence_keys"],
        })

    c = Counter(r["status"] for r in rows)
    # Two-tier: SOURCE_OBJECT_VERIFIED = object recomputed; OFFICIAL_SKILL_BOUND = verified official mapping
    sov = c.get("SOURCE_OBJECT_VERIFIED", 0)
    osb = c.get("OFFICIAL_SKILL_BOUND", 0)
    summary = {
        "generated_at": "2026-08-26",
        "official_skills": 487,
        "issues": 1708,
        "unique_issue_keys": len({official_issue_key(r) for r in issues}),
        "candidate_pool": len(cands),
        "evidence_skills": len(official_by_skill_list),
        "evidence_rows": sum(len(v) for v in official_by_skill_list.values()),
        "SOURCE_NOT_FOUND": c.get("SOURCE_NOT_FOUND", 0),
        "CANDIDATE_SOURCE_VERIFIED": c.get("CANDIDATE_SOURCE_VERIFIED", 0),
        "OFFICIAL_SOURCE_DECLARED": c.get("OFFICIAL_SOURCE_DECLARED", 0),
        "BOUND_AMBIGUOUS": c.get("BOUND_AMBIGUOUS", 0),
        "BOUND_EXACT": c.get("BOUND_EXACT", 0),
        "SOURCE_OBJECT_VERIFIED": sov,
        "OFFICIAL_SKILL_BOUND": osb,
        "source_object_verified_count": sov + osb,
        "official_bound_skill_count": osb,
        "official_issue_bound_DIRECT": 0,
        "note": "SOURCE_OBJECT_VERIFIED = DemoTest-actual acquire repo@immutable_commit + recomputed skill_path subtree SHA (object verified); OFFICIAL_SKILL_BOUND = SOURCE_VERIFIED + VERIFIED_OFFICIAL_MAPPING (private master/official metadata/Zenodo/author artifact via mapping_provenance); declared without acquisition is OFFICIAL_SOURCE_DECLARED; same (repo,commit,path) multi non-empty sha -> BOUND_AMBIGUOUS; candidate never blocks; symlink no-follow aligned with source_lock.hash_raw_snapshot.",
    }

    if args.check:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        print(f"CHECK: 487 skills -> {dict(c)}; unique_keys {summary['unique_issue_keys']}")
        return 0

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8", newline="\n") as out:
        for r in rows:
            out.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")
    (args.out.parent / "official_skill_sources_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"wrote {args.out} ({len(rows)} rows)")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
