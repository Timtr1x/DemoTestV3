"""SkillLeakBench catalog adapter — source catalog only (guide §35).

This dataset is a *source catalog* (MIT, 520 skills / 1708 issues). It is NOT
converted to SecurityCase. It provides taxonomy, candidate priority, and
provenance for the offline credential trace builder. ``iter_cases`` yields
nothing; ``validate_raw`` confirms the 520/1708 invariant.
"""
from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Iterator

from ...config import DatasetSourceConfig, get_dataset
from ...core.models import SecurityCase
from ..base import DatasetAdapter, ValidationReport
from ..registry import register_adapter
from ..source_lock import load_source_lock
from ...core.exceptions import DatasetSourceError


@register_adapter
class SkillLeakbenchAdapter(DatasetAdapter):
    dataset_id = "skillleakbench"
    adapter_version = "1.0.0"

    def __init__(
        self,
        *,
        raw_dir: Path | str | None = None,
        source_config: DatasetSourceConfig | None = None,
    ) -> None:
        if source_config is None:
            source_config = get_dataset(self.dataset_id)
        self.source_config = source_config
        self.raw_dir = Path(raw_dir) if raw_dir else source_config.raw_path

    def _lock_revision(self) -> str:
        if self.source_config.revision:
            return self.source_config.revision
        try:
            return load_source_lock(self.dataset_id).revision
        except DatasetSourceError:
            return self.source_config.revision

    def iter_cases(self) -> Iterator[SecurityCase]:
        # Catalog does not produce SecurityCase — see credential_traces.
        if False:
            yield  # pragma: no cover
        return
        yield  # type: ignore[misc]

    def validate_raw(self) -> ValidationReport:
        rep = ValidationReport(ok=True)
        skills = self.raw_dir / "skills_dataset.csv"
        issues = self.raw_dir / "issues.csv"
        rep.add("skills_present", skills.exists(), str(skills))
        rep.add("issues_present", issues.exists(), str(issues))
        if skills.exists():
            try:
                n = sum(1 for _ in open(skills, encoding="utf-8")) - 1
                rep.add("skills_520", n == 520, f"n={n}")
            except Exception as e:
                rep.add("skills_520", False, str(e))
        if issues.exists():
            try:
                n = sum(1 for _ in open(issues, encoding="utf-8")) - 1
                rep.add("issues_1708", n == 1708, f"n={n}")
            except Exception as e:
                rep.add("issues_1708", False, str(e))
        return rep

    def source_metadata(self) -> dict[str, Any]:
        return {
            "dataset_id": self.dataset_id,
            "adapter_version": self.adapter_version,
            "source_type": self.source_config.source_type,
            "source_uri": self.source_config.source_uri,
            "revision": self._lock_revision(),
            "quality_tier": "A",
        }


@register_adapter
class SkillleakbenchPipelineAdapter(DatasetAdapter):
    """Pipeline repo (Docker sandbox). Also catalog-only."""

    dataset_id = "skillleakbench_pipeline"
    adapter_version = "1.0.0"

    def __init__(
        self,
        *,
        raw_dir: Path | str | None = None,
        source_config: DatasetSourceConfig | None = None,
    ) -> None:
        if source_config is None:
            source_config = get_dataset(self.dataset_id)
        self.source_config = source_config
        self.raw_dir = Path(raw_dir) if raw_dir else source_config.raw_path

    def iter_cases(self) -> Iterator[SecurityCase]:
        if False:
            yield  # pragma: no cover
        return
        yield  # type: ignore[misc]

    def validate_raw(self) -> ValidationReport:
        rep = ValidationReport(ok=True)
        rep.add("clone_present", self.raw_dir.exists(), str(self.raw_dir))
        for rel in ("code", "data", "config.yaml"):
            rep.add(f"{rel}_present", (self.raw_dir / rel).exists(), str(self.raw_dir / rel))
        return rep

    def source_metadata(self) -> dict[str, Any]:
        rev = self.source_config.revision
        try:
            rev = load_source_lock(self.dataset_id).revision or rev
        except DatasetSourceError:
            pass
        return {
            "dataset_id": self.dataset_id,
            "adapter_version": self.adapter_version,
            "source_type": self.source_config.source_type,
            "source_uri": self.source_config.source_uri,
            "revision": rev,
        }
