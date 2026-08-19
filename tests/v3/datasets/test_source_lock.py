"""Source Lock + raw snapshot hash tests (guide §5-§11, §28-§29)."""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parents[3] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from demotest.datasets.source_lock import (  # noqa: E402
    DatasetSourceLock,
    FileHash,
    hash_raw_snapshot,
    load_source_lock,
    write_source_lock,
    assert_git_clean_at_revision,
    git_head_sha,
)


def test_hash_raw_snapshot_detects_content_change(tmp_path: Path):
    (tmp_path / "a.json").write_text("{}", encoding="utf-8")
    (tmp_path / "b.json").write_text("hello", encoding="utf-8")
    files, snap1 = hash_raw_snapshot(tmp_path)
    assert len(files) == 2
    assert all(isinstance(f, FileHash) for f in files)
    # change a file -> snapshot hash changes
    (tmp_path / "a.json").write_text('{"x":1}', encoding="utf-8")
    _, snap2 = hash_raw_snapshot(tmp_path)
    assert snap1 != snap2


def test_hash_raw_snapshot_detects_added_removed_file(tmp_path: Path):
    (tmp_path / "a.json").write_text("x", encoding="utf-8")
    _, snap1 = hash_raw_snapshot(tmp_path)
    (tmp_path / "b.json").write_text("y", encoding="utf-8")
    _, snap2 = hash_raw_snapshot(tmp_path)
    (tmp_path / "b.json").unlink()
    _, snap3 = hash_raw_snapshot(tmp_path)
    assert snap1 != snap2  # added
    assert snap1 == snap3  # removed -> back to original


def test_hash_raw_snapshot_excludes_git_dir(tmp_path: Path):
    (tmp_path / "data.json").write_text("x", encoding="utf-8")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("junk", encoding="utf-8")
    files, _ = hash_raw_snapshot(tmp_path)
    assert [f.relative_path for f in files] == ["data.json"]


def test_hash_raw_snapshot_relative_globs(tmp_path: Path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("x=1", encoding="utf-8")
    (tmp_path / "README.md").write_text("hi", encoding="utf-8")
    files, _ = hash_raw_snapshot(tmp_path, relative_globs=["src/**"])
    assert [f.relative_path for f in files] == ["src/a.py"]


def test_source_lock_roundtrip(tmp_path: Path):
    lock = DatasetSourceLock(
        dataset_id="x",
        source_type="huggingface_dataset",
        source_uri="org/x",
        revision="abc123",
        raw_sha256="deadbeef",
        adapter_name="x",
        adapter_version="1.0.0",
        acquired_at="2026-01-01T00:00:00Z",
    )
    p = write_source_lock(lock, tmp_path / "x.lock.json")
    assert p.exists()
    loaded = DatasetSourceLock.from_dict(__import__("json").loads(p.read_text(encoding="utf-8")))
    assert loaded == lock
    # canonical sorted-key JSON
    txt = p.read_text(encoding="utf-8")
    assert txt.index("dataset_id") < txt.index("revision")


def test_load_source_lock_missing(tmp_path: Path):
    with pytest.raises(Exception):
        load_source_lock("nope", tmp_path / "nope.lock.json")


def test_assert_git_clean_at_revision(tmp_path: Path):
    # init a tiny git repo, commit, then verify clean-at-revision
    import subprocess

    subprocess.run(["git", "init", "-q"], cwd=str(tmp_path), check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=str(tmp_path), check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=str(tmp_path), check=True)
    (tmp_path / "f").write_text("1", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=str(tmp_path), check=True)
    subprocess.run(["git", "commit", "-qm", "c"], cwd=str(tmp_path), check=True)
    head = git_head_sha(tmp_path)
    assert_git_clean_at_revision(tmp_path, head)  # clean -> ok
    # dirty it
    (tmp_path / "f").write_text("2", encoding="utf-8")
    with pytest.raises(Exception):
        assert_git_clean_at_revision(tmp_path, head)
