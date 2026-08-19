"""Source Lock — pin an external dataset to an immutable revision (guide §2, §5).

A *Source Lock* is the single artifact that makes a frozen benchmark
reproducible: it records where the data came from, which exact revision was
fetched, and the SHA-256 of the raw snapshot we actually read from. Two runs
that agree on the lock read byte-identical data.

Pipeline (guide §2):  official source -> resolve revision -> pin SHA ->
download raw snapshot -> raw hash -> write source lock -> adapter reads lock ->
normalized SecurityCase.

This module is deliberately free of network/IO side effects beyond reading the
local filesystem: ``acquire`` (CLI) downloads and then calls
``write_source_lock``; ``load_source_lock`` reads it back.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from ..core.exceptions import DatasetSourceDirtyError, DatasetSourceError
from ..paths import DATASETS_V3_METADATA_DIR


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _short(text: str, n: int = 12) -> str:
    return _sha256_text(text)[:n]


@dataclass(frozen=True)
class FileHash:
    """One file in a raw snapshot."""

    relative_path: str
    sha256: str
    size: int

    def as_line(self) -> str:
        return f"{self.relative_path}\t{self.sha256}\t{self.size}"


def hash_raw_snapshot(
    root: Path,
    *,
    relative_globs: Sequence[str] | None = None,
    exclude_dirs: Sequence[str] = (".git", "__pycache__"),
) -> tuple[list[FileHash], str]:
    """Hash every file under ``root`` (or only those matching ``relative_globs``).

    Returns ``(file_hashes, snapshot_sha256)``. The snapshot hash is itself a
    SHA-256 over the sorted ``relative_path + sha256`` list (guide §7): a change
    to any file's content, an added file, or a removed file all change it.

    ``root`` is the raw mirror directory (e.g. cache/datasets_v3/raw/llmail).
    For AgentDojo's git clone we exclude ``.git`` and by default hash only the
    adapter-relevant globs from the dataset config (guide §28).
    """
    root = Path(root)
    if not root.exists():
        raise DatasetSourceError(f"raw snapshot missing: {root}")

    if relative_globs:
        candidates: list[Path] = []
        for pat in relative_globs:
            # support both dir/** (recursive) and plain globs
            if pat.endswith("/**") or pat.endswith("/**/*"):
                base = pat.rstrip("/*")
                candidates.extend((root / base).rglob("*"))
            elif pat.endswith("/**"):
                base = pat[:-3]
                candidates.extend((root / base).rglob("*"))
            else:
                candidates.extend((root / pat).parent.glob(Path(pat).name))
                # also try a top-level glob for simple names
                candidates.extend(root.glob(pat))
    else:
        candidates = list(root.rglob("*"))

    seen: set[Path] = set()
    files: list[Path] = []
    excl = set(exclude_dirs)
    for p in candidates:
        if p in seen:
            continue
        seen.add(p)
        if not p.is_file():
            continue
        # skip anything under an excluded dir
        try:
            rel_parts = p.relative_to(root).parts
        except ValueError:
            continue
        if any(part in excl for part in rel_parts):
            continue
        files.append(p)

    file_hashes: list[FileHash] = []
    for p in sorted(files, key=lambda x: str(x.relative_to(root)).replace("\\", "/")):
        rel = str(p.relative_to(root)).replace("\\", "/")
        file_hashes.append(
            FileHash(relative_path=rel, sha256=_sha256_bytes(p.read_bytes()), size=p.stat().st_size)
        )

    blob = "\n".join(f"{h.relative_path}|{h.sha256}" for h in file_hashes)
    snapshot_sha = _sha256_text(blob)
    return file_hashes, snapshot_sha


@dataclass(frozen=True)
class DatasetSourceLock:
    """A pinned external dataset (guide §5, §27).

    ``raw_sha256`` is the snapshot hash over the files the adapter actually
    reads; for HF datasets that is the whole mirror, for a git clone it is the
    adapter-relevant globs (guide §28) plus the commit SHA.
    """

    dataset_id: str
    source_type: str  # huggingface_dataset | github
    source_uri: str  # repo_id or owner/repo
    revision: str  # full commit SHA (never a branch/tag)
    license: str | None = None
    raw_sha256: str = ""
    # extra provenance (benchmark_version for agentdojo)
    extra: dict[str, Any] = field(default_factory=dict)
    adapter_name: str = ""
    adapter_version: str = ""
    acquired_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "DatasetSourceLock":
        return cls(
            dataset_id=str(d.get("dataset_id") or ""),
            source_type=str(d.get("source_type") or ""),
            source_uri=str(d.get("source_uri") or ""),
            revision=str(d.get("revision") or ""),
            license=d.get("license"),
            raw_sha256=str(d.get("raw_sha256") or ""),
            extra=dict(d.get("extra") or {}),
            adapter_name=str(d.get("adapter_name") or ""),
            adapter_version=str(d.get("adapter_version") or ""),
            acquired_at=str(d.get("acquired_at") or ""),
        )

    @property
    def lock_path(self) -> Path:
        return DATASETS_V3_METADATA_DIR / f"{self.dataset_id}.lock.json"


def write_source_lock(lock: DatasetSourceLock, path: Path | None = None) -> Path:
    p = path or lock.lock_path
    p.parent.mkdir(parents=True, exist_ok=True)
    # canonical, sorted-key JSON for reproducibility
    blob = json.dumps(lock.to_dict(), sort_keys=True, ensure_ascii=False, indent=2)
    p.write_text(blob + "\n", encoding="utf-8")
    return p


def load_source_lock(dataset_id: str, path: Path | None = None) -> DatasetSourceLock:
    p = path or (DATASETS_V3_METADATA_DIR / f"{dataset_id}.lock.json")
    if not p.exists():
        raise DatasetSourceError(f"source lock not found: {p} (run 'dataset acquire --dataset {dataset_id}')")
    return DatasetSourceLock.from_dict(json.loads(p.read_text(encoding="utf-8")))


# --------------------------------------------------------------------------
# Clean-tree checks (guide §29)
# --------------------------------------------------------------------------
def git_is_clean(repo: Path) -> bool:
    """``git status --porcelain`` is empty for the clone at ``repo``."""
    try:
        out = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        raise DatasetSourceError(f"git not available / timed out checking {repo}: {e}") from e
    return out.returncode == 0 and out.stdout.strip() == ""


def git_head_sha(repo: Path) -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        raise DatasetSourceError(f"git not available / timed out at {repo}: {e}") from e
    if out.returncode != 0:
        raise DatasetSourceError(f"git rev-parse HEAD failed in {repo}: {out.stderr.strip()}")
    return out.stdout.strip()


def assert_git_clean_at_revision(repo: Path, expected_revision: str) -> None:
    """Fail verify-source if the clone is dirty or not at the pinned SHA."""
    head = git_head_sha(repo)
    if head != expected_revision:
        raise DatasetSourceDirtyError(
            f"agentdojo clone HEAD={head} != pinned revision={expected_revision}"
        )
    if not git_is_clean(repo):
        raise DatasetSourceDirtyError(
            f"agentdojo working tree at {repo} is not clean — local edits are not "
            "allowed as official benchmark data (guide §29)"
        )


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# A lock is "consistent" with the raw tree if recomputing the hash matches.
def verify_lock_against_raw(
    lock: DatasetSourceLock, raw_dir: Path, *, relative_globs: Sequence[str] | None = None
) -> None:
    _, snap = hash_raw_snapshot(raw_dir, relative_globs=relative_globs)
    if lock.raw_sha256 and snap != lock.raw_sha256:
        raise DatasetSourceError(
            f"raw snapshot hash mismatch for {lock.dataset_id}: "
            f"lock={lock.raw_sha256[:12]} actual={snap[:12]}"
        )
