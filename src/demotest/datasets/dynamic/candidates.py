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
  * P4 deterministic Core requires explicit execution spec — no auto-guessed
    entry_command. SKILL.md-only Skills are kept as AGENT_REQUIRED for the
    Extended Agent-driven path.
  * Intake must not read host files via symlink traversal — preflight rejects
    any symlink before hashing or copying.
"""
from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from ...paths import DATASE_V3_RAW_DIR
from ..source_lock import now_utc

CANDIDATES_ROOT = DATASE_V3_RAW_DIR / "p4_skill_candidates"
CANDIDATES_JSONL = "candidates.jsonl"
CANDIDATE_META = "candidate_meta.json"
STAGED_SKILLS_DIRNAME = "skills"
RUNTIME_SPECS_DIRNAME = "runtime_specs"
RUNTIME_SPECS_FILE = "runtime_specs.jsonl"
MATERIALIZATION_FILENAME = "_p4_materialization.json"
RUNTIME_SPEC_VERSION = "p4-runtime-v1"

# Policy constants
CANDIDATE_POLICY_VERSION = "p4-candidate-v2"
DEFAULT_SELECTION_SEED = 42
OVERSIZE_BYTES = 50 * 1024 * 1024  # 50 MB

CandidateSource = Literal["local_import", "skillsmp", "mixed"]
RejectReason = Literal[
    "ACCEPT",
    "REJECT_EMPTY",
    "REJECT_OVERSIZE",
    "REJECT_SYMLINK_ESCAPE",
    "REJECT_SYMLINK",
    "REJECT_DUPLICATE",
    "REJECT_INCOMPLETE",
]
RuntimeStatus = Literal[
    "RUNTIME_READY",
    "AGENT_REQUIRED",
    "RUNTIME_UNKNOWN",
    "SOURCE_REJECTED",
    # Sidecar spec exists but was written for a different source_sha256 —
    # never auto-execute: a human must re-confirm the spec (P0).
    "RUNTIME_SPEC_STALE",
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
    # Runtime eligibility (P0-1)
    runtime_status: str = "RUNTIME_UNKNOWN"
    runtime_eligible: bool = False
    entry_command: tuple[str, ...] = ()
    declared_providers: tuple[str, ...] = ()
    execution_spec_source: str = ""
    # Upstream provenance (SkillsMP skills_metadata.json) — informational;
    # source_sha256 over the extracted tree is the immutable content anchor.
    repo_url: str = ""
    branch: str = ""
    skill_subdir: str = ""
    skill_url: str = ""
    updated_at: str = ""

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
            "runtime_status": self.runtime_status,
            "runtime_eligible": self.runtime_eligible,
            "entry_command": list(self.entry_command),
            "declared_providers": list(self.declared_providers),
            "execution_spec_source": self.execution_spec_source,
            "repo_url": self.repo_url,
            "branch": self.branch,
            "skill_subdir": self.skill_subdir,
            "skill_url": self.skill_url,
            "updated_at": self.updated_at,
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
            runtime_status=str(d.get("runtime_status") or "RUNTIME_UNKNOWN"),
            runtime_eligible=bool(d.get("runtime_eligible", False)),
            entry_command=tuple(str(x) for x in (d.get("entry_command") or [])),
            declared_providers=tuple(str(x) for x in (d.get("declared_providers") or [])),
            execution_spec_source=str(d.get("execution_spec_source") or ""),
            repo_url=str(d.get("repo_url") or ""),
            branch=str(d.get("branch") or ""),
            skill_subdir=str(d.get("skill_subdir") or ""),
            skill_url=str(d.get("skill_url") or ""),
            updated_at=str(d.get("updated_at") or ""),
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
    skills_metadata_sha256: str = ""  # sha over upstream skills_metadata.json bytes

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
            "skills_metadata_sha256": self.skills_metadata_sha256,
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
            skills_metadata_sha256=str(d.get("skills_metadata_sha256") or ""),
        )


# ---------------------------------------------------------------------------
# File-level helpers — preflight before any read (P0-2)
# ---------------------------------------------------------------------------

def _scan_skill_dir_nofollow(skill_dir: Path) -> tuple[list[Path], int, bool]:
    """Enumerate regular files without following symlinks.

    Returns (regular_files, total_bytes via lstat, has_symlink).
    """
    regular: list[Path] = []
    total = 0
    has_symlink = False
    for p in skill_dir.rglob("*"):
        # Check symlink first via lstat — do not follow
        try:
            is_link = p.is_symlink()
        except Exception:
            has_symlink = True
            continue
        if is_link:
            has_symlink = True
            continue
        # Exclude dirs
        try:
            rel_parts = p.relative_to(skill_dir).parts
        except ValueError:
            continue
        if any(part in _EXCLUDE_DIRS for part in rel_parts):
            continue
        if p.is_file():
            regular.append(p)
            try:
                total += p.stat().st_size
            except Exception:
                pass
    return sorted(regular, key=lambda x: str(x.relative_to(skill_dir)).replace("\\", "/")), total, has_symlink


def _hash_skill_dir_streaming(skill_dir: Path, regular_files: list[Path]) -> tuple[str, int, int]:
    """SHA over sorted relpath|file-sha (streaming, no read_bytes)."""
    lines: list[str] = []
    total = 0
    for p in regular_files:
        rel = str(p.relative_to(skill_dir)).replace("\\", "/")
        h = hashlib.sha256()
        with p.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        sha = h.hexdigest()
        lines.append(f"{rel}|{sha}")
        total += p.stat().st_size
    archive_sha = hashlib.sha256("\n".join(lines).encode()).hexdigest() if lines else hashlib.sha256(b"").hexdigest()
    return archive_sha, len(regular_files), total


def _has_skill_entrypoint_nofollow(skill_dir: Path, regular_files: list[Path]) -> bool:
    """Presence of SKILL.md or common entrypoint without following symlinks."""
    # Direct checks (regular files only, since symlink already excluded)
    names = {str(p.relative_to(skill_dir)).replace("\\", "/").lower() for p in regular_files}
    if "skill.md" in names:
        return True
    # any .py/.sh/.js/.ts at top-level is not sufficient for completeness anymore,
    # but keep as before for source ACCEPT — runtime eligibility is separate.
    for n in names:
        if n.endswith(".py") or n.endswith(".sh") or n.endswith(".js") or n.endswith(".ts"):
            return True
    # subdir SKILL.md
    for n in names:
        if n.endswith("/skill.md") or n.endswith("\\skill.md"):
            return True
    return False


def _read_execution_spec_inline(skill_dir: Path) -> tuple[tuple[str, ...], tuple[str, ...], str]:
    """Inline spec inside the Skill dir (legacy) — external sidecar is preferred.

    Real SkillsMP Skills will not contain demotest files; prefer the external
    runtime_specs sidecar so source_sha256 stays clean. Inline files are still
    supported for tests / backwards compat but not for clean provenance.
    """
    for fname in ("demotest.skill.json", "runtime_spec.json"):
        meta_path = skill_dir / fname
        if meta_path.exists() and not meta_path.is_symlink():
            try:
                m = json.loads(meta_path.read_text(encoding="utf-8"))
                cmd = tuple(str(x) for x in (m.get("entry_command") or []))
                prov = tuple(str(x) for x in (m.get("declared_providers") or []))
                if cmd:
                    return cmd, prov, fname
                if prov:
                    return (), prov, fname
            except Exception:
                continue
    return (), (), ""


def _load_external_runtime_specs(pool_root: Path) -> dict[str, dict[str, Any]]:
    """Load external sidecar specs from <pool>/runtime_specs/runtime_specs.jsonl."""
    p = pool_root / RUNTIME_SPECS_DIRNAME / RUNTIME_SPECS_FILE
    if not p.exists():
        return {}
    out: dict[str, dict[str, Any]] = {}
    for raw in p.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        try:
            d = json.loads(raw)
            cid = str(d.get("candidate_id") or d.get("skill_id") or "")
            if cid:
                out[cid] = d
        except Exception:
            continue
    return out


def _load_skillsmp_metadata_file(p: Path) -> dict[str, dict[str, Any]]:
    """Parse one skills_metadata.json file into skill_id -> entry dict."""
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}
    entries = data if isinstance(data, list) else (data.get("skills") or data.get("entries") or [])
    out: dict[str, dict[str, Any]] = {}
    for e in entries:
        if isinstance(e, dict):
            sid = str(e.get("skill_id") or e.get("id") or "")
            if sid:
                out[sid] = dict(e)
    return out


def _load_skillsmp_metadata_index(
    crawl_root: Path,
    metadata_path: Path | None = None,
) -> tuple[dict[str, dict[str, Any]], str]:
    """Load official crawler output `skills_metadata.json` if present.

    Official SkillLeakBench layout (phase1_downloads/) keeps skills under
    ``repos/`` while the metadata file lives one level up, so resolution order:
      1. explicit *metadata_path* (preferred, reproducible)
      2. ``<crawl_root>/skills_metadata.json`` (+ aliases)
      3. ``<crawl_root>/../skills_metadata.json`` (official repos/ layout)

    Returns (skill_id -> entry, sha256 of the metadata file bytes or "").
    """
    candidates: list[Path] = []
    if metadata_path is not None:
        candidates.append(Path(metadata_path))
    for fname in ("skills_metadata.json", "skillsmp_metadata.json", "crawl_metadata.json"):
        candidates.append(crawl_root / fname)
        candidates.append(crawl_root.parent / fname)
    seen: set[str] = set()
    for p in candidates:
        key = str(p.resolve()) if p.exists() else str(p)
        if key in seen:
            continue
        seen.add(key)
        if p.exists() and p.is_file() and not p.is_symlink():
            idx = _load_skillsmp_metadata_file(p)
            if idx:
                return idx, hashlib.sha256(p.read_bytes()).hexdigest()
    return {}, ""


def _resolve_execution_spec(
    skill_id: str,
    skill_dir: Path,
    external_specs: dict[str, dict[str, Any]] | None = None,
    source_sha256: str = "",
) -> tuple[tuple[str, ...], tuple[str, ...], str, bool]:
    """Prefer external sidecar; fallback to inline — never guess entry.

    Returns (entry_command, declared_providers, spec_source, stale).
    A sidecar spec is bound to the source_sha256 it was reviewed against:
    if the skill bytes changed (re-crawl, upstream update), the old spec no
    longer matches and the skill degrades to RUNTIME_SPEC_STALE instead of
    silently executing the stale command.
    """
    if external_specs is not None and skill_id in external_specs:
        d = external_specs[skill_id]
        spec_sha = str(d.get("source_sha256") or "")
        if not spec_sha or not source_sha256 or spec_sha != source_sha256:
            return (), (), f"{RUNTIME_SPECS_DIRNAME}/{RUNTIME_SPECS_FILE}", True
        cmd = tuple(str(x) for x in (d.get("entry_command") or []))
        prov = tuple(str(x) for x in (d.get("declared_providers") or []))
        if cmd or prov:
            return cmd, prov, f"{RUNTIME_SPECS_DIRNAME}/{RUNTIME_SPECS_FILE}", False
    cmd, prov, src = _read_execution_spec_inline(skill_dir)
    return cmd, prov, src, False


def _classify_skill_dir_nofollow(
    skill_dir: Path,
    regular_files: list[Path],
    total_bytes: int,
    has_symlink: bool,
    seen_shas: set[str],
    sha: str,
) -> str:
    """Return RejectReason (ACCEPT if no issue). Symlink/oversize checked first."""
    if has_symlink:
        return "REJECT_SYMLINK_ESCAPE"
    n_files = len(regular_files)
    if n_files == 0:
        return "REJECT_EMPTY"
    if total_bytes > OVERSIZE_BYTES:
        return "REJECT_OVERSIZE"
    if sha in seen_shas:
        return "REJECT_DUPLICATE"
    if not _has_skill_entrypoint_nofollow(skill_dir, regular_files):
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
    src = Path(skills_dir)
    if not src.is_dir():
        raise FileNotFoundError(f"skills dir not found: {src}")
    dest = Path(dest_root) if dest_root else CANDIDATES_ROOT
    staged = dest / STAGED_SKILLS_DIRNAME
    staged.mkdir(parents=True, exist_ok=True)
    created_at = created_at or now_utc()
    acquired_at = created_at
    external_specs = _load_external_runtime_specs(dest)
    candidates: list[SkillCandidate] = []
    seen_shas: set[str] = set()
    for sd in _skill_dirs(src):
        skill_id = sd.name
        regular, total_lstat, has_symlink = _scan_skill_dir_nofollow(sd)
        if has_symlink:
            reason = "REJECT_SYMLINK_ESCAPE"
            sha = hashlib.sha256(f"rejected:{reason}:{skill_id}".encode()).hexdigest()
            n_files = len(regular)
            total = total_lstat
            entry_cmd: tuple[str, ...] = ()
            prov: tuple[str, ...] = ()
            spec_src = ""
            spec_stale = False
        elif total_lstat > OVERSIZE_BYTES:
            reason = "REJECT_OVERSIZE"
            sha = hashlib.sha256(f"rejected:{reason}:{skill_id}:{total_lstat}".encode()).hexdigest()
            n_files = len(regular)
            total = total_lstat
            entry_cmd = ()
            prov = ()
            spec_src = ""
            spec_stale = False
        else:
            sha, n_files, total = _hash_skill_dir_streaming(sd, regular)
            reason = _classify_skill_dir_nofollow(sd, regular, total, has_symlink, seen_shas, sha)
            entry_cmd, prov, spec_src, spec_stale = _resolve_execution_spec(sd.name, sd, external_specs, sha)
        # Derive runtime eligibility
        if reason != "ACCEPT":
            runtime_status: str = "SOURCE_REJECTED"
            runtime_eligible = False
        elif spec_stale:
            runtime_status = "RUNTIME_SPEC_STALE"
            runtime_eligible = False
        elif entry_cmd:
            runtime_status = "RUNTIME_READY"
            runtime_eligible = True
        else:
            runtime_status = "AGENT_REQUIRED"
            runtime_eligible = False

        # Copy to staged only for non-link / non-oversize (P0-2)
        should_copy = reason not in ("REJECT_SYMLINK_ESCAPE", "REJECT_SYMLINK", "REJECT_OVERSIZE")
        if reason != "REJECT_DUPLICATE" and should_copy:
            staged_skill = staged / skill_id
            if staged_skill.exists():
                shutil.rmtree(staged_skill)
            # copytree must not follow symlinks — we already rejected any symlink,
            # so safe to copy regular files.
            shutil.copytree(sd, staged_skill, symlinks=False)
            if reason == "ACCEPT":
                seen_shas.add(sha)
            elif reason not in ("REJECT_SYMLINK_ESCAPE", "REJECT_SYMLINK", "REJECT_OVERSIZE"):
                seen_shas.add(sha)
        else:
            if reason == "ACCEPT":
                seen_shas.add(sha)
        rel_staged = f"{STAGED_SKILLS_DIRNAME}/{skill_id}" if (staged / skill_id).exists() else ""
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
            runtime_status=runtime_status,
            runtime_eligible=runtime_eligible,
            entry_command=entry_cmd,
            declared_providers=prov,
            execution_spec_source=spec_src,
        )
        candidates.append(cand)

    return _write_pool(candidates, dest=dest, source="local_import",
                       source_revision=source_revision, created_at=created_at,
                       selection_seed=selection_seed)


def import_skillsmp_candidates(
    crawl_output_dir: Path | str,
    *,
    metadata_path: Path | str | None = None,
    dest_root: Path | str | None = None,
    source_revision: str = "",
    created_at: str = "",
    selection_seed: int = DEFAULT_SELECTION_SEED,
) -> CandidateSetManifest:
    src = Path(crawl_output_dir)
    if not src.is_dir():
        raise FileNotFoundError(f"crawl output dir not found: {src}")
    dest = Path(dest_root) if dest_root else CANDIDATES_ROOT
    staged = dest / STAGED_SKILLS_DIRNAME
    staged.mkdir(parents=True, exist_ok=True)
    created_at = created_at or now_utc()
    acquired_at = created_at
    # Upstream SkillsMP metadata — official phase1_downloads layout keeps
    # skills under repos/ with skills_metadata.json one level up; an explicit
    # --metadata path is the most reproducible and is preferred.
    upstream_index, skills_metadata_sha = _load_skillsmp_metadata_index(
        src, Path(metadata_path) if metadata_path else None)
    external_specs = _load_external_runtime_specs(dest)
    candidates: list[SkillCandidate] = []
    seen_shas: set[str] = set()
    for sd in _skill_dirs(src):
        skill_id = sd.name
        regular, total_lstat, has_symlink = _scan_skill_dir_nofollow(sd)
        if has_symlink:
            reason = "REJECT_SYMLINK_ESCAPE"
            sha = hashlib.sha256(f"rejected:{reason}:{skill_id}".encode()).hexdigest()
            n_files = len(regular)
            total = total_lstat
            entry_cmd: tuple[str, ...] = ()
            prov: tuple[str, ...] = ()
            spec_src = ""
            spec_stale = False
        elif total_lstat > OVERSIZE_BYTES:
            reason = "REJECT_OVERSIZE"
            sha = hashlib.sha256(f"rejected:{reason}:{skill_id}:{total_lstat}".encode()).hexdigest()
            n_files = len(regular)
            total = total_lstat
            entry_cmd = ()
            prov = ()
            spec_src = ""
            spec_stale = False
        else:
            sha, n_files, total = _hash_skill_dir_streaming(sd, regular)
            reason = _classify_skill_dir_nofollow(sd, regular, total, has_symlink, seen_shas, sha)
            entry_cmd, prov, spec_src, spec_stale = _resolve_execution_spec(sd.name, sd, external_specs, sha)
        # Hints from optional metadata.json (if not symlink)
        class_hint = ""
        pattern_hints: tuple[str, ...] = ()
        severity_hint = ""
        meta_path = sd / "metadata.json"
        if meta_path.exists() and not meta_path.is_symlink() and reason not in ("REJECT_SYMLINK_ESCAPE", "REJECT_SYMLINK", "REJECT_OVERSIZE"):
            try:
                m = json.loads(meta_path.read_text(encoding="utf-8"))
                class_hint = str(m.get("classification") or m.get("classification_hint") or "")
                ph = m.get("pattern_hints") or m.get("patterns") or []
                if isinstance(ph, list):
                    pattern_hints = tuple(str(x) for x in ph)
                severity_hint = str(m.get("severity") or m.get("severity_hint") or "")
            except Exception:
                pass
        # Enrich with upstream SkillsMP provenance if available
        upstream = upstream_index.get(skill_id) or {}
        if upstream:
            # Prefer upstream skill_url/repo_url over local src path for source_uri
            src_uri = str(upstream.get("skill_url") or upstream.get("repo_url") or src.resolve())
        else:
            src_uri = str(src.resolve())
        if reason != "ACCEPT":
            runtime_status = "SOURCE_REJECTED"
            runtime_eligible = False
        elif spec_stale:
            runtime_status = "RUNTIME_SPEC_STALE"
            runtime_eligible = False
        elif entry_cmd:
            runtime_status = "RUNTIME_READY"
            runtime_eligible = True
        else:
            runtime_status = "AGENT_REQUIRED"
            runtime_eligible = False
        should_copy = reason not in ("REJECT_SYMLINK_ESCAPE", "REJECT_SYMLINK", "REJECT_OVERSIZE")
        if reason != "REJECT_DUPLICATE" and should_copy:
            staged_skill = staged / skill_id
            if staged_skill.exists():
                shutil.rmtree(staged_skill)
            shutil.copytree(sd, staged_skill, symlinks=False)
            if reason == "ACCEPT":
                seen_shas.add(sha)
            elif reason not in ("REJECT_SYMLINK_ESCAPE", "REJECT_SYMLINK", "REJECT_OVERSIZE"):
                seen_shas.add(sha)
        else:
            if reason == "ACCEPT":
                seen_shas.add(sha)
        rel_staged = f"{STAGED_SKILLS_DIRNAME}/{skill_id}" if (staged / skill_id).exists() else ""
        cand = SkillCandidate(
            candidate_id=skill_id,
            skill_id=skill_id,
            skill_name=str(upstream.get("skill_name") or skill_id) if upstream else skill_id,
            source_type="skillsmp",
            source_uri=src_uri,
            source_revision=str(upstream.get("branch") or upstream.get("revision") or source_revision) if upstream else source_revision,
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
            runtime_status=runtime_status,
            runtime_eligible=runtime_eligible,
            entry_command=entry_cmd,
            declared_providers=prov,
            execution_spec_source=spec_src,
            repo_url=str(upstream.get("repo_url") or "") if upstream else "",
            branch=str(upstream.get("branch") or "") if upstream else "",
            skill_subdir=str(upstream.get("skill_subdir") or "") if upstream else "",
            skill_url=str(upstream.get("skill_url") or "") if upstream else "",
            updated_at=str(upstream.get("updated_at") or "") if upstream else "",
        )
        candidates.append(cand)
    return _write_pool(candidates, dest=dest, source="skillsmp",
                       source_revision=source_revision, created_at=created_at,
                       selection_seed=selection_seed,
                       skills_metadata_sha256=skills_metadata_sha)


def _write_pool(
    candidates: list[SkillCandidate],
    *,
    dest: Path,
    source: str,
    source_revision: str,
    created_at: str,
    selection_seed: int,
    skills_metadata_sha256: str = "",
) -> CandidateSetManifest:
    dest.mkdir(parents=True, exist_ok=True)
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
        skills_metadata_sha256=skills_metadata_sha256,
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
        if meta.selection_policy_version != CANDIDATE_POLICY_VERSION:
            problems.append(f"policy version drift: meta={meta.selection_policy_version} != {CANDIDATE_POLICY_VERSION}")
    except FileNotFoundError as e:
        problems.append(str(e))
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
        if c.reject_reason not in ("ACCEPT", "REJECT_EMPTY", "REJECT_OVERSIZE", "REJECT_SYMLINK_ESCAPE", "REJECT_SYMLINK", "REJECT_DUPLICATE", "REJECT_INCOMPLETE"):
            problems.append(f"unknown reject_reason {c.reject_reason}: {c.candidate_id}")
        if c.runtime_status not in ("RUNTIME_READY", "AGENT_REQUIRED", "RUNTIME_UNKNOWN", "SOURCE_REJECTED", "RUNTIME_SPEC_STALE"):
            problems.append(f"unknown runtime_status {c.runtime_status}: {c.candidate_id}")
        if c.reject_reason == "ACCEPT" and c.runtime_status == "SOURCE_REJECTED":
            problems.append(f"ACCEPT with SOURCE_REJECTED: {c.candidate_id}")
        if c.reject_reason != "ACCEPT" and c.runtime_eligible:
            problems.append(f"REJECT with runtime_eligible: {c.candidate_id}")
        if c.runtime_eligible and not c.entry_command:
            problems.append(f"runtime_eligible without entry_command: {c.candidate_id}")
        if c.runtime_status == "RUNTIME_SPEC_STALE" and (c.runtime_eligible or c.entry_command):
            problems.append(f"RUNTIME_SPEC_STALE must not stay executable: {c.candidate_id}")
        # ACCEPT must have runtime_status coherent
        if c.reject_reason == "ACCEPT" and c.runtime_status not in ("RUNTIME_READY", "AGENT_REQUIRED", "RUNTIME_UNKNOWN", "RUNTIME_SPEC_STALE"):
            problems.append(f"ACCEPT with unexpected runtime_status: {c.candidate_id}")
        if c.reject_reason == "ACCEPT":
            staged = root / c.local_path if c.local_path else None
            if staged is None or not staged.exists():
                # AGENT_REQUIRED may still be staged (it is ACCEPT source) — so must exist
                problems.append(f"ACCEPT candidate missing staged dir: {c.candidate_id} -> {c.local_path}")
            else:
                regular, _, has_sym = _scan_skill_dir_nofollow(staged)
                if has_sym:
                    problems.append(f"staged dir contains symlink: {c.candidate_id}")
                else:
                    sha, _, _ = _hash_skill_dir_streaming(staged, regular)
                    if sha != c.source_sha256:
                        problems.append(f"staged sha drift: {c.candidate_id} stored={c.source_sha256[:12]} actual={sha[:12]}")
        else:
            # REJECT_SYMLINK/OVERSIZE must NOT be staged (P0-2)
            if c.reject_reason in ("REJECT_SYMLINK_ESCAPE", "REJECT_SYMLINK", "REJECT_OVERSIZE"):
                staged = root / c.local_path if c.local_path else None
                if c.local_path and staged is not None and staged.exists():
                    problems.append(f"{c.reject_reason} must not be staged: {c.candidate_id}")
    return problems


def materialize_candidates(
    *,
    pool_root: Path | str | None = None,
    dest_dir: Path | str,
    limit: int | None = None,
    offset: int = 0,
    seed: int = DEFAULT_SELECTION_SEED,
    include_rejected: bool = False,
    require_runtime_ready: bool = False,
    clean_dest: bool = False,
) -> list[SkillCandidate]:
    """Deterministically select a subset and copy staged skills to *dest_dir*.

    Only ACCEPT candidates are considered by default. Selection is deterministic:
    candidates are ordered by ``sha256(candidate_set_id|seed|candidate_id)`` so
    the same pool+seed always yields the same subset (guide §15).

    P4 deterministic Core should set ``require_runtime_ready=True`` so only
    ``RUNTIME_READY`` Skills enter the snapshot (SKILL.md-only -> AGENT_REQUIRED
    is kept in the pool but excluded from deterministic execution).
    """
    pool = Path(pool_root) if pool_root else CANDIDATES_ROOT
    dest = Path(dest_dir)
    # Dest hygiene (P1): refuse non-empty dest unless explicitly cleaned
    if dest.exists() and any(dest.iterdir()):
        if not clean_dest:
            raise RuntimeError(f"dest dir not empty: {dest} (use --clean-dest to overwrite)")
        # clean
        for child in list(dest.iterdir()):
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
    else:
        dest.mkdir(parents=True, exist_ok=True)
    all_cands = load_candidates(pool)
    if not include_rejected:
        all_cands = [c for c in all_cands if c.reject_reason == "ACCEPT"]
        if require_runtime_ready:
            all_cands = [c for c in all_cands if c.runtime_eligible and c.runtime_status == "RUNTIME_READY"]
    if not all_cands:
        # Still write empty materialization manifest for provenance
        _write_materialization_manifest(dest, pool, seed, [])
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
        shutil.copytree(src, dst, symlinks=False)
    _write_materialization_manifest(dest, pool, seed, selected)
    return selected


def _write_materialization_manifest(dest: Path, pool: Path, seed: int, selected: list[SkillCandidate]) -> Path:
    try:
        meta = load_candidate_meta(pool)
        candidate_set_id = meta.candidate_set_id
        policy = meta.selection_policy_version
    except Exception:
        candidate_set_id = _candidate_set_id(load_candidates(pool))
        policy = CANDIDATE_POLICY_VERSION
    sel_blob = "\n".join(f"{c.candidate_id}|{c.source_sha256}" for c in sorted(selected, key=lambda x: x.candidate_id))
    selection_sha256 = hashlib.sha256(sel_blob.encode()).hexdigest() if sel_blob else hashlib.sha256(b"").hexdigest()
    doc = {
        "candidate_set_id": candidate_set_id,
        "candidate_policy_version": policy,
        "seed": seed,
        "selected_count": len(selected),
        "selection_sha256": selection_sha256,
        # Whole sidecar file identity (vs the per-selection projection hashed
        # by the snapshot as selected_runtime_specs_sha256).
        "runtime_specs_file_sha256": runtime_specs_sha256(pool),
        "skills": [
            {
                "candidate_id": c.candidate_id,
                "skill_id": c.skill_id,
                "source_type": c.source_type,
                "source_uri": c.source_uri,
                "source_revision": c.source_revision,
                "source_sha256": c.source_sha256,
                "runtime_spec": {
                    "entry_command": list(c.entry_command),
                    "declared_providers": list(c.declared_providers),
                    "execution_spec_source": c.execution_spec_source,
                    "runtime_status": c.runtime_status,
                    "runtime_eligible": c.runtime_eligible,
                },
            }
            for c in sorted(selected, key=lambda x: x.candidate_id)
        ],
    }
    p = dest / MATERIALIZATION_FILENAME
    p.write_text(json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return p


def _runtime_specs_path(pool_root: Path) -> Path:
    return pool_root / RUNTIME_SPECS_DIRNAME / RUNTIME_SPECS_FILE


def load_runtime_specs(pool_root: Path | str | None = None) -> dict[str, dict[str, Any]]:
    pool = Path(pool_root) if pool_root else CANDIDATES_ROOT
    return _load_external_runtime_specs(pool)


def upsert_runtime_spec(
    *,
    pool_root: Path | str | None = None,
    candidate_id: str,
    entry_command: tuple[str, ...],
    declared_providers: tuple[str, ...] = (),
) -> None:
    """Create or update an external runtime spec (sidecar) for *candidate_id*.

    Never writes into the staged Skill dir — source_sha256 stays clean.
    The spec is bound to the candidate's *current* source_sha256: re-crawling
    the skill under the same candidate_id with different bytes invalidates the
    old spec at resolve time (RUNTIME_SPEC_STALE) until a human re-confirms
    via another upsert.
    """
    pool = Path(pool_root) if pool_root else CANDIDATES_ROOT
    cands = {c.candidate_id: c for c in load_candidates(pool)}
    if candidate_id not in cands:
        raise ValueError(f"candidate not found: {candidate_id}")
    cand = cands[candidate_id]
    specs_dir = pool / RUNTIME_SPECS_DIRNAME
    specs_dir.mkdir(parents=True, exist_ok=True)
    specs = _load_external_runtime_specs(pool)
    specs[candidate_id] = {
        "candidate_id": candidate_id,
        "source_sha256": cand.source_sha256,
        "entry_command": list(entry_command),
        "declared_providers": list(declared_providers),
        "spec_version": RUNTIME_SPEC_VERSION,
    }
    out = _runtime_specs_path(pool)
    lines = [json.dumps(specs[k], ensure_ascii=False, sort_keys=True) for k in sorted(specs)]
    out.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    # Re-derive runtime eligibility for this candidate without re-importing all
    # (next verify/materialize will see the updated spec via _resolve).
    # Also eagerly refresh the single candidate row in candidates.jsonl so
    # verify reflects the new runtime_status without requiring a full re-import.
    new_status = "RUNTIME_READY" if entry_command else "AGENT_REQUIRED"
    if cand.reject_reason != "ACCEPT":
        new_status = "SOURCE_REJECTED"
    updated = SkillCandidate(
        candidate_id=cand.candidate_id, skill_id=cand.skill_id, skill_name=cand.skill_name,
        source_type=cand.source_type, source_uri=cand.source_uri, source_revision=cand.source_revision,
        source_sha256=cand.source_sha256, acquired_at=cand.acquired_at, acquisition_method=cand.acquisition_method,
        classification_hint=cand.classification_hint, pattern_hints=cand.pattern_hints, severity_hint=cand.severity_hint,
        local_path=cand.local_path, file_count=cand.file_count, total_bytes=cand.total_bytes,
        static_candidate=cand.static_candidate, manual_priority=cand.manual_priority, source_real=cand.source_real,
        synthetic=cand.synthetic, reject_reason=cand.reject_reason,
        runtime_status=new_status, runtime_eligible=(new_status == "RUNTIME_READY"),
        entry_command=tuple(entry_command), declared_providers=tuple(declared_providers),
        execution_spec_source=f"{RUNTIME_SPECS_DIRNAME}/{RUNTIME_SPECS_FILE}",
        repo_url=cand.repo_url, branch=cand.branch, skill_subdir=cand.skill_subdir,
        skill_url=cand.skill_url, updated_at=cand.updated_at,
    )
    all_cands = load_candidates(pool)
    for i, c in enumerate(all_cands):
        if c.candidate_id == candidate_id:
            all_cands[i] = updated
            break
    (pool / CANDIDATES_JSONL).write_text(
        "".join(json.dumps(c.to_dict(), ensure_ascii=False, sort_keys=True) + "\n" for c in sorted(all_cands, key=lambda x: x.candidate_id)),
        encoding="utf-8",
    )


def runtime_specs_sha256(pool_root: Path | str | None = None) -> str:
    p = _runtime_specs_path(Path(pool_root) if pool_root else CANDIDATES_ROOT)
    if not p.exists():
        return hashlib.sha256(b"").hexdigest()
    return hashlib.sha256(p.read_bytes()).hexdigest()
