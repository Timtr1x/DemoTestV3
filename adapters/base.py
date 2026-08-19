"""DatasetAdapter abstract base + helpers."""
from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Sequence

from core.schema import Sample
from paths import DATASETS_DIR


class DatasetAdapter(ABC):
    source_name: str = "unknown"
    adapter_version: str = "1.0"

    def cache_dir(self) -> Path:
        d = DATASETS_DIR / self.source_name
        d.mkdir(parents=True, exist_ok=True)
        return d

    @abstractmethod
    def fetch(self, **kwargs: Any) -> list[Sample]:
        """Load/transform raw data into canonical samples."""

    def provenance(self) -> dict[str, str]:
        return {
            "source_dataset": self.source_name,
            "adapter_version": f"{self.__class__.__module__.split('.')[-1]}.py@{self.adapter_version}",
            "dataset_version": self.dataset_version(),
        }

    def dataset_version(self) -> str:
        return f"cache:{self.source_name}"


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def write_jsonl(path: Path, rows: Sequence[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
