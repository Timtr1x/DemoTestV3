"""P4 candidate intake — real Skill → Candidate Manifest (guide P4 D1/D2).

This layer sits BEFORE snapshot (guide §4-§6):

    real source (local dir / SkillsMP crawl output)
          ↓
    Candidate Intake  (+ static pre-check, no execution)
          ↓
    candidates.jsonl + candidate_meta.json  (under raw/p4_skill_candidates)
          ↓
    materialize  (deterministic subset → skills dir for snapshot)

Security invariants
  * No skill is executed here — only file-level checks (§5).
  * classification_hint / pattern_hints / severity_hint are priority hints only;
    they never become ground truth — BLOCK still requires a real sandbox trace.
  * Dangerous code is NOT a rejection reason — we are benchmarking leaky Skills.
  * No synthetic/template/LLM expansion.
"""
from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from ...paths import DATASE_V3_RAW_DIR
from ..source_lock import now_utc

CANDIDATES_ROOT = DATASE_V3_RAW_DIR / "p4_skill_candidates"
CANDIDATES_JSONL = "candidates.jsonl"
CANDIDATE_META = "candidate_meta.json"
STAGED_SKILLS_DIRNAME = "skills"

# Policy constants
CANDIDATE_POLICY_VERSION = "p4-candidate-v1"
DEFAULT_SELECTION_SEED = 42
# Oversize guard — per-skill total bytes. Skills larger than this are flagged
# REJECT_OVERSIZE (but still recorded, not silently dropped).
OVERSIZE_BYTES = 50 * 1024 * 1024  # 50 MB

CandidateSource = Literal["local_import", "skillsmp", "mixed"]
RejectReason = Literal[
    "ACCEPT",
    "REJECT_EMPTY",
    "REJECT_OVERSIZE",
    "REJECT_SYMLINK_ESCAPE",
    "REJECT_DUPLICATE",
    "REJECT_INCOMPLETE",
]


_EXCLUDE_DIRS = {".git", "__pycache__", "node_modules", ".venv"}


@dataclass(frozen=True)
class SkillCandidate:
    """One real Skill as recorded in the candidate pool."""

    candidate_id: str
    skill_id: str
    skill_name: str
    source_type: str  # local_import | skillsmp
    source_uri: str
    source_revision: str
    source_sha256: str
    acquired_at: str
    acquisition_method: str
    classification_hint: str = ""
    pattern_hints: tuple[str, ...] = ()
    severity_hint: str = ""
    local_path: str = ""  # staged path relative to CANDIDATES_ROOT, POSIX
    file_count: int = 0
    total_bytes: int = 0
    static_candidate: bool = True
    manual_priority: int = 0
    source_real: bool = True
    synthetic: bool = False
    reject_reason: str = "ACCEPT"  # one of RejectReason

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "skill_id": self.skill_id,
            "skill_name": self.skill_name,
            "source_type": self.source_type,
            "source_uri": self.source_uri,
            "source_revision": self.source_revision,
            "source_sha256": self.source_sha256,
            "acquired_at": self.acquired_at,
            "acquisition_method": self.acquisition_method,
            "classification_hint": self.classification_hint,
            "pattern_hints": list(self.pattern_hints),
            "severity_hint": self.severity_hint,
            "local_path": self.local_path,
            "file_count": self.file_count,
            "total_bytes": self.total_bytes,
            "static_candidate": self.static_candidate,
            "manual_priority": self.manual_priority,
            "source_real": self.source_real,
            "synthetic": self.synthetic,
            "reject_reason": self.reject_reason,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SkillCandidate":
        return cls(
            candidate_id=str(d.get("candidate_id") or ""),
            skill_id=str(d.get("skill_id") or ""),
            skill_name=str(d.get("skill_name") or ""),
            source_type=str(d.get("source_type") or ""),
            source_uri=str(d.get("source_uri") or ""),
            source_revision=str(d.get("source_revision") or ""),
            source_sha256=str(d.get("source_sha256") or ""),
            acquired_at=str(d.get("acquired_at") or ""),
            acquisition_method=str(d.get("acquisition_method") or ""),
            classification_hint=str(d.get("classification_hint") or ""),
            pattern_hints=tuple(str(x) for x in (d.get("pattern_hints") or [])),
            severity_hint=str(d.get("severity_hint") or ""),
            local_path=str(d.get("local_path") or ""),
            file_count=int(d.get("file_count") or 0),
            total_bytes=int(d.get("total_bytes") or 0),
            static_candidate=bool(d.get("static_candidate", True)),
            manual_priority=int(d.get("manual_priority") or 0),
            source_real=bool(d.get("source_real", True)),
            synthetic=bool(d.get("synthetic", False)),
            reject_reason=str(d.get("reject_reason") or "ACCEPT"),
        )


@dataclass(frozen=True)
class CandidateSetManifest:
    candidate_set_id: str
    source: str  # skillsmp | local_import | mixed
    source_revision: str
    created_at: str
    selection_seed: int
    selection_policy_version: str
    count: int
    accepted_count: int = 0
    rejected_count: int = 0
    source_real: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_set_id": self.candidate_set_id,
            "source": self.source,
            "source_revision": self.source_revision,
            "created_at": self.created_at,
            "selection_seed": self.selection_seed,
            "selection_policy_version": self.selection_policy_version,
            "count": self.count,
            "accepted_count": self.accepted_count,
            "rejected_count": self.rejected_count,
            "source_real": self.source_real,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "CandidateSetManifest":
        return cls(
            candidate_set_id=str(d.get("candidate_set_id") or ""),
            source=str(d.get("source") or ""),
            source_revision=str(d.get("source_revision") or ""),
            created_at=str(d.get("created_at") or ""),
            selection_seed=int(d.get("selection_seed") or 0),
            selection_policy_version=str(d.get("selection_policy_version") or CANDIDATE_POLICY_VERSION),
            count=int(d.get("count") or 0),
            accepted_count=int(d.get("accepted_count") or 0),
            rejected_count=int(d.get("rejected_count") or 0),
            source_real=bool(d.get("source_real", True)),
        )


# ---------------------------------------------------------------------------
# File-level helpers
# ---------------------------------------------------------------------------

def _hash_skill_dir(skill_dir: Path) -> tuple[str, int, int]:
    """SHA over sorted relpath|file-sha lines + file count + total bytes."""
    files = [
        p for p in sorted(skill_dir.rglob("*"))
        if p.is_file() and not any(part in _EXCLUDE_DIRS for part in p.relative_to(skill_dir).parts)
    ]
    lines: list[str] = []
    total = 0
    for p in files:
        rel = str(p.relative_to(skill_dir)).replace("\\", "/")
        sha = hashlib.sha256(p.read_bytes()).hexdigest()
        lines.append(f"{rel}|{sha}")
        total += p.stat().st_size
    archive_sha = hashlib.sha256("\n".join(lines).encode()).hexdigest() if lines else hashlib.sha256(b"").hexdigest()
    return archive_sha, len(files), total


def _has_symlink_escape(skill_dir: Path) -> bool:
    """True if any symlink points outside skill_dir."""
    for p in skill_dir.rglob("*"):
        if p.is_symlink():
            try:
                target = p.resolve()
                # resolved target must stay within skill_dir
                target.relative_to(skill_dir.resolve())
            except ValueError:
                return True
            except Exception:
                return True
    return False


def _has_skill_entrypoint(skill_dir: Path) -> bool:
    """Presence of SKILL.md or common entrypoint is considered complete."""
    if (skill_dir / "SKILL.md").exists():
        return True
    if (skill_dir / "skill.md").exists():
        return True
    # also accept any .py / .sh / .js entry
    for pat in ("*.py", "*.sh", "*.js", "*.ts"):
        if list(skill_dir.glob(pat)):
            return True
    # check subdir SKILL.md
    for p in skill_dir.rglob("SKILL.md"):
        if p.is_file():
            return True
    return False


def _classify_skill_dir(skill_dir: Path, seen_shas: set[str], sha: str, n_files: int, total_bytes: int) -> str:
    """Return RejectReason for this skill (ACCEPT if no issue)."""
    if _has_symlink_escape(skill_dir):
        return "REJECT_SYMLINK_ESCAPE"
    if n_files == 0:
        return "REJECT_EMPTY"
    if total_bytes > OVERSIZE_BYTES:
        return "REJECT_OVERSIZE"
    if sha in seen_shas:
        return "REJECT_DUPLICATE"
    if not _has_skill_entrypoint(skill_dir):
        return "REJECT_INCOMPLETE"
    return "ACCEPT"


def _skill_dirs(root: Path) -> list[Path]:
    return sorted(d for d in root.iterdir() if d.is_dir() and not d.name.startswith("_") and not d.name.startswith("."))


def _candidate_set_id(candidates: list[SkillCandidate]) -> str:
    blob = "\n".join(f"{c.candidate_id}|{c.source_sha256}" for c in sorted(candidates, key=lambda x: x.candidate_id))
    h = hashlib.sha256(blob.encode()).hexdigest()[:12]
    return f"p4-candidates-{h}"


# ---------------------------------------------------------------------------
# Public intake API
# ---------------------------------------------------------------------------

def import_local_candidates(
    skills_dir: Path | str,
    *,
    dest_root: Path | str | None = None,
    source_revision: str = "",
    created_at: str = "",
    selection_seed: int = DEFAULT_SELECTION_SEED,
) -> CandidateSetManifest:
    """Import real Skills from a local directory into the candidate pool.

    Each immediate sub-directory of *skills_dir* becomes one candidate. Files are
    copied into ``<dest_root>/skills/<skill_id>`` so the pool is self-contained
    and later materialize can run without the original directory.
    """
    src = Path(skills_dir)
    if not src.is_dir():
        raise FileNotFoundError(f"skills dir not found: {src}")
    dest = Path(dest_root) if dest_root else CANDIDATES_ROOT
    staged = dest / STAGED_SKILLS_DIRNAME
    staged.mkdir(parents=True, exist_ok=True)
    # Clean stale jsonl/meta from previous import — intake is idempotent per run
    # but we keep staging additive? For now overwrite jsonl/meta, keep staged skills.
    created_at = created_at or now_utc()
    acquired_at = created_at
    candidates: list[SkillCandidate] = []
    seen_shas: set[str] = set()
    for sd in _skill_dirs(src):
        skill_id = sd.name
        sha, n_files, total = _hash_skill_dir(sd)
        reason = _classify_skill_dir(sd, seen_shas, sha, n_files, total)
        # Copy to staged regardless of reject — audit retains the bytes (except duplicate
        # second copy would collide; we skip duplicate copy but still record it)
        staged_skill = staged / skill_id
        if reason != "REJECT_DUPLICATE":
            if staged_skill.exists():
                shutil.rmtree(staged_skill)
            shutil.copytree(sd, staged_skill)
            seen_shas.add(sha)
        else:
            # still track duplicate sha
            pass
        rel_staged = f"{STAGED_SKILLS_DIRNAME}/{skill_id}" if staged_skill.exists() else ""
        cand = SkillCandidate(
            candidate_id=skill_id,
            skill_id=skill_id,
            skill_name=skill_id,
            source_type="local_import",
            source_uri=str(src.resolve()),
            source_revision=source_revision,
            source_sha256=sha,
            acquired_at=acquired_at,
            acquisition_method="local_import",
            classification_hint="",
            pattern_hints=(),
            severity_hint="",
            local_path=rel_staged,
            file_count=n_files,
            total_bytes=total,
            static_candidate=True,
            manual_priority=0,
            source_real=True,
            synthetic=False,
            reject_reason=reason,
        )
        candidates.append(cand)

    return _write_pool(candidates, dest=dest, source="local_import",
                       source_revision=source_revision, created_at=created_at,
                       selection_seed=selection_seed)


def import_skillsmp_candidates(
    crawl_output_dir: Path | str,
    *,
    dest_root: Path | str | None = None,
    source_revision: str = "",
    created_at: str = "",
    selection_seed: int = DEFAULT_SELECTION_SEED,
) -> CandidateSetManifest:
    """Import from an official SkillsMP crawl output dir.

    Expected layout: each skill is a sub-directory (same as local_import), but
    source_type is ``skillsmp`` and classification_hint may be read from an
    optional ``metadata.json`` inside each skill dir (if present). No network
    call is made here — the caller must have already crawled.
    """
    src = Path(crawl_output_dir)
    if not src.is_dir():
        raise FileNotFoundError(f"crawl output dir not found: {src}")
    dest = Path(dest_root) if dest_root else CANDIDATES_ROOT
    staged = dest / STAGED_SKILLS_DIRNAME
    staged.mkdir(parents=True, exist_ok=True)
    created_at = created_at or now_utc()
    acquired_at = created_at
    candidates: list[SkillCandidate] = []
    seen_shas: set[str] = set()
    for sd in _skill_dirs(src):
        skill_id = sd.name
        sha, n_files, total = _hash_skill_dir(sd)
        reason = _classify_skill_dir(sd, seen_shas, sha, n_files, total)
        # Optional hints
        class_hint = ""
        pattern_hints: tuple[str, ...] = ()
        severity_hint = ""
        meta_path = sd / "metadata.json"
        if meta_path.exists():
            try:
                m = json.loads(meta_path.read_text(encoding="utf-8"))
                class_hint = str(m.get("classification") or m.get("classification_hint") or "")
                ph = m.get("pattern_hints") or m.get("patterns") or []
                if isinstance(ph, list):
                    pattern_hints = tuple(str(x) for x in ph)
                severity_hint = str(m.get("severity") or m.get("severity_hint") or "")
            except Exception:
                pass
        staged_skill = staged / skill_id
        if reason != "REJECT_DUPLICATE":
            if staged_skill.exists():
                shutil.rmtree(staged_skill)
            shutil.copytree(sd, staged_skill)
            seen_shas.add(sha)
        rel_staged = f"{STAGED_SKILLS_DIRNAME}/{skill_id}" if staged_skill.exists() else ""
        cand = SkillCandidate(
            candidate_id=skill_id,
            skill_id=skill_id,
            skill_name=skill_id,
            source_type="skillsmp",
            source_uri=str(src.resolve()),
            source_revision=source_revision,
            source_sha256=sha,
            acquired_at=acquired_at,
            acquisition_method="skillsmp_crawl",
            classification_hint=class_hint,
            pattern_hints=pattern_hints,
            severity_hint=severity_hint,
            local_path=rel_staged,
            file_count=n_files,
            total_bytes=total,
            static_candidate=True,
            manual_priority=0,
            source_real=True,
            synthetic=False,
            reject_reason=reason,
        )
        candidates.append(cand)
    return _write_pool(candidates, dest=dest, source="skillsmp",
                       source_revision=source_revision, created_at=created_at,
                       selection_seed=selection_seed)


def _write_pool(
    candidates: list[SkillCandidate],
    *,
    dest: Path,
    source: str,
    source_revision: str,
    created_at: str,
    selection_seed: int,
) -> CandidateSetManifest:
    dest.mkdir(parents=True, exist_ok=True)
    # Deterministic order
    candidates = sorted(candidates, key=lambda c: c.candidate_id)
    candidate_set_id = _candidate_set_id(candidates) if candidates else "p4-candidates-empty"
    jsonl_path = dest / CANDIDATES_JSONL
    jsonl_path.write_text(
        "".join(json.dumps(c.to_dict(), ensure_ascii=False, sort_keys=True) + "\n" for c in candidates),
        encoding="utf-8",
    )
    accepted = sum(1 for c in candidates if c.reject_reason == "ACCEPT")
    rejected = len(candidates) - accepted
    manifest = CandidateSetManifest(
        candidate_set_id=candidate_set_id,
        source=source,
        source_revision=source_revision,
        created_at=created_at,
        selection_seed=selection_seed,
        selection_policy_version=CANDIDATE_POLICY_VERSION,
        count=len(candidates),
        accepted_count=accepted,
        rejected_count=rejected,
        source_real=True,
    )
    (dest / CANDIDATE_META).write_text(
        json.dumps(manifest.to_dict(), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def load_candidates(root: Path | str | None = None) -> list[SkillCandidate]:
    root = Path(root) if root else CANDIDATES_ROOT
    p = root / CANDIDATES_JSONL
    if not p.exists():
        return []
    out: list[SkillCandidate] = []
    for raw in p.read_text(encoding="utf-8").splitlines():
        if raw.strip():
            out.append(SkillCandidate.from_dict(json.loads(raw)))
    return out


def load_candidate_meta(root: Path | str | None = None) -> CandidateSetManifest:
    root = Path(root) if root else CANDIDATES_ROOT
    p = root / CANDIDATE_META
    if not p.exists():
        raise FileNotFoundError(f"candidate meta not found: {p}")
    return CandidateSetManifest.from_dict(json.loads(p.read_text(encoding="utf-8")))


def verify_candidates(root: Path | str | None = None) -> list[str]:
    """Static pre-check — no execution (guide §5). Returns problem strings."""
    root = Path(root) if root else CANDIDATES_ROOT
    problems: list[str] = []
    cands = load_candidates(root)
    if not cands:
        problems.append("no candidates found (run candidates import-* first)")
        return problems
    try:
        meta = load_candidate_meta(root)
        if meta.count != len(cands):
            problems.append(f"meta count {meta.count} != jsonl count {len(cands)}")
        expected_id = _candidate_set_id(cands)
        if meta.candidate_set_id != expected_id:
            problems.append(f"candidate_set_id drift: meta={meta.candidate_set_id} expected={expected_id}")
    except FileNotFoundError as e:
        problems.append(str(e))
    # Per-candidate checks
    seen_ids: set[str] = set()
    seen_shas: set[str] = set()
    for c in cands:
        if c.candidate_id in seen_ids:
            problems.append(f"duplicate candidate_id: {c.candidate_id}")
        seen_ids.add(c.candidate_id)
        if c.source_sha256 in seen_shas and c.reject_reason != "REJECT_DUPLICATE":
            problems.append(f"duplicate sha without REJECT_DUPLICATE: {c.candidate_id} sha={c.source_sha256[:12]}")
        seen_shas.add(c.source_sha256)
        if c.synthetic:
            problems.append(f"synthetic candidate not allowed: {c.candidate_id}")
        if not c.source_real:
            problems.append(f"source_real must be true: {c.candidate_id}")
        if c.reject_reason not in ("ACCEPT", "REJECT_EMPTY", "REJECT_OVERSIZE", "REJECT_SYMLINK_ESCAPE", "REJECT_DUPLICATE", "REJECT_INCOMPLETE"):
            problems.append(f"unknown reject_reason {c.reject_reason}: {c.candidate_id}")
        # Staged file existence
        if c.reject_reason == "ACCEPT":
            staged = root / c.local_path if c.local_path else None
            if staged is None or not staged.exists():
                problems.append(f"ACCEPT candidate missing staged dir: {c.candidate_id} -> {c.local_path}")
            else:
                sha, n_files, total = _hash_skill_dir(staged)
                if sha != c.source_sha256:
                    problems.append(f"staged sha drift: {c.candidate_id} stored={c.source_sha256[:12]} actual={sha[:12]}")
        # REJECT_* must not be silently dropped — they stay in jsonl for audit
    return problems


def materialize_candidates(
    *,
    pool_root: Path | str | None = None,
    dest_dir: Path | str,
    limit: int | None = None,
    offset: int = 0,
    seed: int = DEFAULT_SELECTION_SEED,
    include_rejected: bool = False,
) -> list[SkillCandidate]:
    """Deterministically select a subset and copy staged skills to *dest_dir*.

    Only ACCEPT candidates are considered by default. Selection is deterministic:
    candidates are ordered by ``sha256(candidate_set_id|seed|candidate_id)`` so
    the same pool+seed always yields the same subset (guide §15).
    """
    pool = Path(pool_root) if pool_root else CANDIDATES_ROOT
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    all_cands = load_candidates(pool)
    if not include_rejected:
        all_cands = [c for c in all_cands if c.reject_reason == "ACCEPT"]
    if not all_cands:
        return []
    meta = None
    try:
        meta = load_candidate_meta(pool)
    except FileNotFoundError:
        pass
    pool_id = meta.candidate_set_id if meta else _candidate_set_id(all_cands)

    def _rank(c: SkillCandidate) -> str:
        return hashlib.sha256(f"{pool_id}|{seed}|{c.candidate_id}".encode()).hexdigest()

    ranked = sorted(all_cands, key=_rank)
    start = max(0, int(offset))
    stop = None if limit is None else start + max(0, int(limit))
    selected = ranked[start:stop]
    for c in selected:
        src = pool / c.local_path if c.local_path else None
        if src is None or not src.exists():
            continue
        dst = dest / c.skill_id
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(src, dst)
    return selected
