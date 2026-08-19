"""DatasetAdapter abstract base (plan §18, guide §8)."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Iterator, Any

from ..core.models import SecurityCase


@dataclass
class ValidationReport:
    """Outcome of ``DatasetAdapter.validate_raw`` (guide §34)."""

    ok: bool
    checks: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def add(self, name: str, ok: bool, detail: str = "") -> None:
        self.checks.append({"name": name, "ok": ok, "detail": detail})
        if not ok:
            self.errors.append(f"{name}: {detail}")
            self.ok = False


class DatasetAdapter(ABC):
    """Convert one source dataset into ``SecurityCase`` objects.

    Responsibilities (exhaustive, guide §8):
      * read raw data (cache / fixtures) — READ ONLY; never modify the raw mirror
      * map each row to a ``SecurityCase`` (channel / operation / content)
      * attach uniform source provenance (metadata.source block)
      * yield ``source_metadata`` + ``validate_raw`` for verify-source / verify

    MUST NOT (guide §52, §53): send requests, judge outcomes, compute metrics,
    render requests, call an LLM, read LineMod results, or rewrite payloads.
    """

    dataset_id: str = "unknown"
    adapter_version: str = "1.0.0"

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

    def source_metadata(self) -> dict[str, Any]:
        """Info about the source this adapter reads (for stats / reports)."""
        return {"dataset_id": self.dataset_id, "adapter_version": self.adapter_version}

    def validate_raw(self) -> ValidationReport:
        """Check the raw mirror is present and structurally sane (guide §34)."""
        rep = ValidationReport(ok=True)
        rep.add("iter_cases", True, "default pass")
        return rep
