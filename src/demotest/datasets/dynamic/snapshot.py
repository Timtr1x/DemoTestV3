"""Skill snapshot freezing (guide §21).

"we crawled it today" is never reproducibility. Before any dynamic collection,
the exact skill files are copied into
``cache/datasets_v3/raw/skill_snapshots/<snapshot_id>/`` and a manifest records
per-skill SHA-256 + archive SHA-256 + the pinned pipeline revision.

snapshot_id is derived from the archive hash — re-freezing the same content
yields the same id (deterministic), so snapshot identity is content-defined.
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


@dataclass(frozen=True)
class SkillEntry:
    skill_id: str
    sha256: str
    n_files: int
    declared_providers: tuple[str, ...] = ()
    entry_command: tuple[str, ...] = ()


@dataclass(frozen=True)
class SnapshotManifest:
    snapshot_id: str
    pipeline_revision: str
    created_at: str
    skills: tuple[SkillEntry, ...] = field(default_factory=tuple)
    archive_sha256: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
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
                }
                for s in self.skills
            ],
        }


def _hash_tree(root: Path) -> tuple[str, int]:
    """SHA-256 over sorted relpath|file-sha lines (same convention as locks)."""
    files = [
        p for p in sorted(root.rglob("*"))
        if p.is_file() and not any(part in _EXCLUDE_DIRS for part in p.relative_to(root).parts)
    ]
    lines = []
    for p in files:
        rel = str(p.relative_to(root)).replace("\\", "/")
        lines.append(f"{rel}|{hashlib.sha256(p.read_bytes()).hexdigest()}")
    return hashlib.sha256("\n".join(lines).encode()).hexdigest(), len(files)


def _skill_dirs(skills_root: Path) -> list[Path]:
    return sorted(d for d in skills_root.iterdir() if d.is_dir() and not d.name.startswith("_"))


def _skill_meta(skill_dir: Path) -> dict[str, Any]:
    """Optional per-skill demotest.skill.json: declared providers + entry command."""
    meta_path = skill_dir / "demotest.skill.json"
    if not meta_path.exists():
        return {}
    try:
        return json.loads(meta_path.read_text(encoding="utf-8"))
    except Exception:
        return {}


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

    entries: list[SkillEntry] = []
    for sd in _skill_dirs(skills_root):
        sha, n = _hash_tree(sd)
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

    snap_dir = out_root / snapshot_id
    skills_dst = snap_dir / "skills"
    if skills_dst.exists():
        shutil.rmtree(skills_dst)
    skills_dst.mkdir(parents=True, exist_ok=True)
    for e in entries:
        shutil.copytree(skills_root / e.skill_id, skills_dst / e.skill_id)

    manifest = SnapshotManifest(
        snapshot_id=snapshot_id,
        pipeline_revision=pipeline_revision,
        created_at=created_at,
        skills=tuple(entries),
        archive_sha256=archive_sha,
    )
    (snap_dir / "snapshot.json").write_text(
        json.dumps(manifest.to_dict(), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


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
        skills=tuple(
            SkillEntry(
                skill_id=str(s.get("skill_id") or ""),
                sha256=str(s.get("sha256") or ""),
                n_files=int(s.get("n_files") or 0),
                declared_providers=tuple(s.get("declared_providers") or ()),
                entry_command=tuple(s.get("entry_command") or ()),
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
        sha, n = _hash_tree(sd)
        if sha != e.sha256:
            problems.append(f"skill {e.skill_id} sha256 drift: stored={e.sha256} actual={sha}")
        entries.append(e)
    archive_blob = "\n".join(f"{e.skill_id}|{e.sha256}" for e in entries)
    if hashlib.sha256(archive_blob.encode()).hexdigest() != manifest.archive_sha256:
        problems.append("archive_sha256 mismatch")
    if f"snap-{manifest.archive_sha256[:12]}" != manifest.snapshot_id:
        problems.append("snapshot_id does not match archive hash")
    return problems
