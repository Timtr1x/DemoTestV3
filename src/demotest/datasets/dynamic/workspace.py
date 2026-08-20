"""Execution workspace — frozen snapshot stays immutable (guide P4 P0-1).

The pinned SkillLeakBench entrypoint writes ``/skills/.env``, ``/skills/config.yaml``
and ``/mock_creds/.env`` at startup. Mounting the frozen snapshot as ``:ro`` with
``--read-only`` therefore breaks the real collect path. The fix is to copy the
frozen skill into a per-execution working directory and mount that copy as
``:rw`` while the frozen source is never touched.
"""
from __future__ import annotations

import hashlib
import shutil
from pathlib import Path


def prepare_execution_copy(
    frozen_skill_dir: Path | str,
    execution_id: str,
    *,
    work_root: Path | str | None = None,
) -> Path:
    """Create a writable execution copy of a frozen skill.

    Returns the path to the copy (always a directory). The frozen source at
    ``frozen_skill_dir`` is never modified.
    """
    frozen = Path(frozen_skill_dir)
    if not frozen.is_dir():
        raise FileNotFoundError(f"frozen skill not found: {frozen}")

    if work_root is None:
        import tempfile

        base = Path(tempfile.mkdtemp(prefix=f"dynexec-{execution_id}-"))
    else:
        base = Path(work_root) / execution_id
        if base.exists():
            shutil.rmtree(base)
        base.mkdir(parents=True, exist_ok=True)

    dest = base / "skill"
    shutil.copytree(frozen, dest)
    return dest


def workspace_provenance(
    frozen_skill_dir: Path | str,
    execution_copy: Path | str,
) -> dict[str, str]:
    """Provenance snippet for the execution workspace."""
    frozen = Path(frozen_skill_dir)

    def _hash_tree(root: Path) -> str:
        files = sorted(p for p in root.rglob("*") if p.is_file())
        lines = []
        for p in files:
            rel = str(p.relative_to(root)).replace("\\", "/")
            lines.append(f"{rel}|{hashlib.sha256(p.read_bytes()).hexdigest()}")
        return hashlib.sha256("\n".join(lines).encode()).hexdigest()

    return {
        "source_skill_sha256": _hash_tree(frozen) if frozen.is_dir() else "",
        "execution_copy": str(Path(execution_copy).resolve()),
        "source_snapshot_immutable": "true",
    }
