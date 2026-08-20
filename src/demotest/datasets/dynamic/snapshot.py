"""Skill snapshot freezing (guide §21).

"we crawled it today" is never reproducibility. Before any dynamic collection,
the exact skill files are copied into
``cache/datasets_v3/raw/skill_snapshots/<snapshot_id>/`` and a manifest records
per-skill SHA-256 + archive SHA-256 + the pinned pipeline revision.

snapshot_id is derived from the archive hash — re-freezing the same content
yields the same id (deterministic), so snapshot identity is content-defined.

P0-4: when snapshotting a materialized dir (created by
candidates.materialize_candidates), the provenance in
``_p4_materialization.json`` is carried into ``snapshot.json`` as
``candidate_provenance`` (candidate_set_id, materialization_sha256,
policy version, selected skills' source_uri/revision/sha). This restores
the chain: Candidate → Materialization → Snapshot → Trace.
"""
from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ...paths import DATASE_V3_RAW_DIR

SNAPSHOTS_ROOT = DATASE_V3_RAW_DIR / "skill_snapshots"

_EXCLUDE_DIRS = {".git", "__pycache__", "node_modules", ".venv"}
_MATERIALIZATION_FILENAME = "_p4_materialization.json"


@dataclass(frozen=True)
class SkillEntry:
    skill_id: str
    sha256: str
    n_files: int
    declared_providers: tuple[str, ...] = ()
    entry_command: tuple[str, ...] = ()
    # Provenance carried from materialization (P0-4)
    source_uri: str = ""
    source_revision: str = ""
    source_sha256: str = ""
    candidate_id: str = ""


@dataclass(frozen=True)
class SnapshotManifest:
    snapshot_id: str
    pipeline_revision: str
    created_at: str
    skills: tuple[SkillEntry, ...] = field(default_factory=tuple)
    archive_sha256: str = ""
    candidate_provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "snapshot_id": self.snapshot_id,
            "pipeline_revision": self.pipeline_revision,
            "created_at": self.created_at,
            "archive_sha256": self.archive_sha256,
            "skills": [
                {
                    "skill_id": s.skill_id,
                    "sha256": s.sha256,
                    "n_files": s.n_files,
                    "declared_providers": list(s.declared_providers),
                    "entry_command": list(s.entry_command),
                    "source_uri": s.source_uri,
                    "source_revision": s.source_revision,
                    "source_sha256": s.source_sha256,
                    "candidate_id": s.candidate_id,
                }
                for s in self.skills
            ],
        }
        if self.candidate_provenance:
            d["candidate_provenance"] = dict(self.candidate_provenance)
        return d


def _hash_tree(root: Path) -> tuple[str, int]:
    # Fail-closed on any symlink: never follow a link into host files, not
    # even to hash it. Callers must preflight with _tree_has_symlink first;
    # this is the second line of defense.
    # Sort by POSIX relative path (case-sensitive) — must match the candidate
    # intake hash byte-for-byte so declared source_sha256 == tree sha on every
    # platform (WindowsPath ordering is case-insensitive and diverges).
    scanned: list[Path] = []
    for p in root.rglob("*"):
        if p.is_symlink():
            raise RuntimeError(f"snapshot refused: symlink in skill tree: {p.relative_to(root)}")
        scanned.append(p)
    files = sorted(
        (
            p for p in scanned
            if p.is_file() and not any(part in _EXCLUDE_DIRS for part in p.relative_to(root).parts)
            if p.name != _MATERIALIZATION_FILENAME
        ),
        key=lambda p: str(p.relative_to(root)).replace("\\", "/"),
    )
    lines = []
    for p in files:
        rel = str(p.relative_to(root)).replace("\\", "/")
        # Streaming hash to avoid large read_bytes
        h = hashlib.sha256()
        with p.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        lines.append(f"{rel}|{h.hexdigest()}")
    return hashlib.sha256("\n".join(lines).encode()).hexdigest(), len(files)


def _skill_dirs(skills_root: Path) -> list[Path]:
    return sorted(d for d in skills_root.iterdir() if d.is_dir() and not d.name.startswith("_"))


def _skill_meta(skill_dir: Path) -> dict[str, Any]:
    for fname in ("demotest.skill.json", "runtime_spec.json"):
        p = skill_dir / fname
        if p.exists():
            try:
                return json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                continue
    return {}


def _materialization_provenance(
    skills_root: Path,
) -> tuple[dict[str, Any] | None, dict[str, dict[str, Any]]]:
    """Load provenance from _p4_materialization.json.

    Missing file -> (None, {}) selects the legacy/test-only path. A manifest
    that EXISTS but is unreadable or structurally invalid raises — falling
    back to legacy would let a corrupted manifest silently re-enable the
    Skill's own inline execution spec (fail-open).
    """
    p = skills_root / _MATERIALIZATION_FILENAME
    if not p.exists():
        return None, {}
    if p.is_symlink():
        raise RuntimeError("snapshot refused: materialization manifest is a symlink")
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        raise RuntimeError(
            f"snapshot refused: {_MATERIALIZATION_FILENAME} exists but is not valid JSON ({e})"
        ) from e
    if not isinstance(doc, dict):
        raise RuntimeError(f"snapshot refused: {_MATERIALIZATION_FILENAME} must be a JSON object")
    raw_skills = doc.get("skills")
    if not isinstance(raw_skills, list):
        raise RuntimeError(f"snapshot refused: {_MATERIALIZATION_FILENAME} 'skills' must be a list")
    candidate_set_id = str(doc.get("candidate_set_id") or "")
    if not candidate_set_id:
        raise RuntimeError(f"snapshot refused: {_MATERIALIZATION_FILENAME} has empty candidate_set_id")
    per_skill: dict[str, dict[str, Any]] = {}
    for s in raw_skills:
        if not isinstance(s, dict):
            raise RuntimeError(f"snapshot refused: {_MATERIALIZATION_FILENAME} skill entries must be objects")
        sid = str(s.get("skill_id") or s.get("candidate_id") or "")
        if not sid:
            raise RuntimeError(f"snapshot refused: {_MATERIALIZATION_FILENAME} skill entry without skill_id")
        if sid in per_skill:
            raise RuntimeError(f"snapshot refused: {_MATERIALIZATION_FILENAME} duplicate skill_id {sid}")
        per_skill[sid] = dict(s)
    raw = p.read_bytes()
    selected_specs_sha256 = ""
    # Hash of the *selected* runtime-spec projection (the specs for exactly the
    # skills in this materialization) — distinct from the whole sidecar file
    # hash recorded as runtime_specs_file_sha256 in the materialization doc.
    try:
        rs_blob = json.dumps([s.get("runtime_spec") for s in sorted(raw_skills, key=lambda x: str(x.get("skill_id") or ""))], sort_keys=True)
        selected_specs_sha256 = hashlib.sha256(rs_blob.encode()).hexdigest()
    except Exception:
        selected_specs_sha256 = ""
    meta = {
        "candidate_set_id": candidate_set_id,
        "candidate_policy_version": str(doc.get("candidate_policy_version") or ""),
        "seed": doc.get("seed"),
        "selection_sha256": str(doc.get("selection_sha256") or ""),
        "materialization_sha256": hashlib.sha256(raw).hexdigest(),
        "selected_runtime_specs_sha256": selected_specs_sha256,
        "runtime_specs_file_sha256": str(doc.get("runtime_specs_file_sha256") or ""),
    }
    return meta, per_skill


def _tree_has_symlink(root: Path) -> bool:
    for p in root.rglob("*"):
        try:
            if p.is_symlink():
                return True
        except Exception:
            return True
    return False


def _validate_materialized_root(
    skills_root: Path,
    mat_per_skill: dict[str, dict[str, Any]],
    hashed: dict[str, tuple[str, int]],
) -> list[str]:
    """Materialized Snapshot Validation Gate (fail-closed).

    When ``_p4_materialization.json`` exists, the snapshot must reproduce
    exactly what the human-reviewed materialization declared:
      1. actual skill dir set == materialization skills set (no extra skill
         can be smuggled in between materialize and snapshot)
      2. every skill tree is symlink-free
      3. current tree SHA == declared source_sha256 (no byte drift)
      4. candidate_id / source_sha256 non-empty
      5. runtime spec comes from the materialization manifest only — the
         Skill's own inline metadata is ignored entirely
      6. anything declared RUNTIME_READY must have a non-empty entry_command
    """
    problems: list[str] = []
    declared = set(mat_per_skill)
    actual = {sd.name for sd in _skill_dirs(skills_root)}
    extra = sorted(actual - declared)
    missing = sorted(declared - actual)
    if extra:
        problems.append(f"skill dirs not in materialization manifest: {', '.join(extra[:8])}")
    if missing:
        problems.append(f"materialized skills missing from dir: {', '.join(missing[:8])}")
    for sid in sorted(actual & declared):
        per = mat_per_skill[sid]
        sd = skills_root / sid
        if _tree_has_symlink(sd):
            problems.append(f"{sid}: symlink present in materialized skill")
            continue
        sha, _n = hashed.get(sid, ("", 0))
        src_sha = str(per.get("source_sha256") or "")
        if not str(per.get("candidate_id") or ""):
            problems.append(f"{sid}: empty candidate_id in materialization manifest")
        if not src_sha:
            problems.append(f"{sid}: empty source_sha256 in materialization manifest")
        elif sha != src_sha:
            problems.append(
                f"{sid}: byte drift after materialization — tree sha {sha[:12]} != declared source_sha256 {src_sha[:12]}")
        rt = per.get("runtime_spec") or {}
        if str(rt.get("runtime_status") or "") == "RUNTIME_READY" and not (rt.get("entry_command") or []):
            problems.append(f"{sid}: RUNTIME_READY without entry_command in materialization manifest")
    return problems


def freeze_skill_snapshot(
    skills_root: Path | str,
    *,
    pipeline_revision: str,
    out_root: Path | str | None = None,
    created_at: str = "",
) -> SnapshotManifest:
    """Copy skills into the frozen snapshot store + write snapshot.json."""
    skills_root = Path(skills_root)
    out_root = Path(out_root) if out_root else SNAPSHOTS_ROOT
    if not skills_root.is_dir():
        raise FileNotFoundError(f"skills root not found: {skills_root}")

    mat_meta, mat_per_skill = _materialization_provenance(skills_root)
    materialized = mat_meta is not None

    # No-follow preflight BEFORE any hashing: a symlink (including a symlinked
    # top-level skill dir) must be rejected before a single target byte is
    # read. _hash_tree re-checks internally as a second line of defense.
    hashed: dict[str, tuple[str, int]] = {}
    for sd in _skill_dirs(skills_root):
        if sd.is_symlink() or _tree_has_symlink(sd):
            raise RuntimeError(
                f"snapshot refused: symlink present in skill dir {sd.name} (no-follow preflight)")
        hashed[sd.name] = _hash_tree(sd)

    if materialized:
        problems = _validate_materialized_root(skills_root, mat_per_skill, hashed)
        if problems:
            raise RuntimeError(
                "snapshot refused: materialized root failed validation gate — "
                + "; ".join(problems[:10])
                + (f" (+{len(problems)-10} more)" if len(problems) > 10 else "")
            )

    entries: list[SkillEntry] = []
    for sd in _skill_dirs(skills_root):
        sha, n = hashed[sd.name]
        if materialized:
            # Human-reviewed materialization manifest is the ONLY execution
            # authority — never let a Skill's own inline metadata override it.
            per = mat_per_skill.get(sd.name) or {}
            rt = (per.get("runtime_spec") or {}) if per else {}
            entries.append(SkillEntry(
                skill_id=sd.name,
                sha256=sha,
                n_files=n,
                declared_providers=tuple(rt.get("declared_providers") or ()),
                entry_command=tuple(rt.get("entry_command") or ()),
                source_uri=str(per.get("source_uri") or ""),
                source_revision=str(per.get("source_revision") or ""),
                source_sha256=str(per.get("source_sha256") or ""),
                candidate_id=str(per.get("candidate_id") or ""),
            ))
        else:
            # Legacy/test-only path (no materialization manifest): inline
            # metadata may describe the entry — never used for real Core data.
            meta = _skill_meta(sd)
            entries.append(SkillEntry(
                skill_id=sd.name,
                sha256=sha,
                n_files=n,
                declared_providers=tuple(meta.get("declared_providers") or ()),
                entry_command=tuple(meta.get("entry_command") or ()),
            ))
    archive_blob = "\n".join(f"{e.skill_id}|{e.sha256}" for e in entries)
    archive_sha = hashlib.sha256(archive_blob.encode()).hexdigest()
    snapshot_id = f"snap-{archive_sha[:12]}"

    manifest = SnapshotManifest(
        snapshot_id=snapshot_id,
        pipeline_revision=pipeline_revision,
        created_at=created_at,
        skills=tuple(entries),
        archive_sha256=archive_sha,
        candidate_provenance=mat_meta,
    )

    # Freeze means freeze: snapshot_id is content-defined over skill bytes, but
    # the same bytes under a different runtime spec / provenance / pipeline must
    # NOT silently overwrite the existing snapshot artifact.
    snap_dir = out_root / snapshot_id
    existing_json = snap_dir / "snapshot.json"
    if existing_json.exists():
        try:
            existing = load_snapshot(snapshot_id, root=out_root)
        except Exception as e:
            raise RuntimeError(
                f"snapshot {snapshot_id} exists but is unreadable ({e}); "
                "refusing to overwrite a frozen snapshot"
            ) from e
        if _snapshot_identity(existing) == _snapshot_identity(manifest):
            return existing  # idempotent re-freeze
        raise RuntimeError(
            f"snapshot {snapshot_id} already exists with different provenance/runtime/pipeline identity; "
            "refusing to overwrite a frozen snapshot — materialize a new candidate set instead"
        )

    skills_dst = snap_dir / "skills"
    skills_dst.mkdir(parents=True, exist_ok=True)
    for e in entries:
        shutil.copytree(skills_root / e.skill_id, skills_dst / e.skill_id)

    (snap_dir / "snapshot.json").write_text(
        json.dumps(manifest.to_dict(), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def _snapshot_identity(m: SnapshotManifest) -> dict[str, Any]:
    """Identity for the overwrite gate — everything except created_at."""
    d = m.to_dict()
    d.pop("created_at", None)
    return d


def load_snapshot(snapshot_id: str, *, root: Path | str | None = None) -> SnapshotManifest:
    root = Path(root) if root else SNAPSHOTS_ROOT
    p = root / snapshot_id / "snapshot.json"
    if not p.exists():
        raise FileNotFoundError(f"snapshot not found: {p}")
    d = json.loads(p.read_text(encoding="utf-8"))
    return SnapshotManifest(
        snapshot_id=str(d.get("snapshot_id") or ""),
        pipeline_revision=str(d.get("pipeline_revision") or ""),
        created_at=str(d.get("created_at") or ""),
        archive_sha256=str(d.get("archive_sha256") or ""),
        candidate_provenance=dict(d.get("candidate_provenance") or {}),
        skills=tuple(
            SkillEntry(
                skill_id=str(s.get("skill_id") or ""),
                sha256=str(s.get("sha256") or ""),
                n_files=int(s.get("n_files") or 0),
                declared_providers=tuple(s.get("declared_providers") or ()),
                entry_command=tuple(s.get("entry_command") or ()),
                source_uri=str(s.get("source_uri") or ""),
                source_revision=str(s.get("source_revision") or ""),
                source_sha256=str(s.get("source_sha256") or ""),
                candidate_id=str(s.get("candidate_id") or ""),
            )
            for s in (d.get("skills") or [])
        ),
    )


def verify_snapshot(snapshot_id: str, *, root: Path | str | None = None) -> list[str]:
    """Re-hash the frozen skills; return a list of problems (empty == OK)."""
    root = Path(root) if root else SNAPSHOTS_ROOT
    problems: list[str] = []
    try:
        manifest = load_snapshot(snapshot_id, root=root)
    except Exception as e:
        return [f"snapshot unreadable: {e}"]
    entries: list[SkillEntry] = []
    for e in manifest.skills:
        sd = root / snapshot_id / "skills" / e.skill_id
        if not sd.is_dir():
            problems.append(f"missing skill dir: {e.skill_id}")
            continue
        try:
            sha, n = _hash_tree(sd)
        except RuntimeError as exc:
            problems.append(f"skill {e.skill_id}: {exc}")
            continue
        if sha != e.sha256:
            problems.append(f"skill {e.skill_id} sha256 drift: stored={e.sha256} actual={sha}")
        entries.append(e)
    archive_blob = "\n".join(f"{e.skill_id}|{e.sha256}" for e in entries)
    if hashlib.sha256(archive_blob.encode()).hexdigest() != manifest.archive_sha256:
        problems.append("archive_sha256 mismatch")
    if f"snap-{manifest.archive_sha256[:12]}" != manifest.snapshot_id:
        problems.append("snapshot_id does not match archive hash")
    return problems
