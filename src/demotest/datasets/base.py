"""DatasetAdapter abstract base (plan §18)."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterator

from ..core.models import SecurityCase


class DatasetAdapter(ABC):
    """Convert one source dataset into ``SecurityCase`` objects.

    Responsibilities (exhaustive):
      * read raw data (cache / fixtures)
      * map each row to a ``SecurityCase`` (channel / operation / content)
      * yield provenance (dataset_version, adapter_version, ...)

    MUST NOT: send requests, judge outcomes, compute metrics, render requests.
    """

    dataset_id: str = "unknown"
    adapter_version: str = "1.0"

    @abstractmethod
    def iter_cases(self) -> Iterator[SecurityCase]:
        """Yield SecurityCase objects (deterministic order where possible)."""
        raise NotImplementedError

    def cases(self) -> list[SecurityCase]:
        return list(self.iter_cases())

    def provenance(self) -> dict[str, str]:
        return {
            "dataset_id": self.dataset_id,
            "adapter_version": f"{self.__class__.__module__.split('.')[-1]}@{self.adapter_version}",
        }
