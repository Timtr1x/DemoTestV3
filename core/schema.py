"""Canonical Sample / ResultRecord / Manifest structures."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable


VALID_LABELS = frozenset({"attack", "benign", "boundary"})
VALID_EXPECTED = frozenset({"blocked", "passed", "payload_too_large"})
VALID_OUTCOMES = frozenset(
    {
        "blocked",
        "passed",
        "passed_upstream_cooldown",
        "rate_limited",
        "error",
        "payload_too_large",
    }
)


@dataclass(frozen=True)
class Sample:
    sample_id: str
    project: str
    source_dataset: str
    subset: str
    category: str
    label: str  # attack | benign | boundary
    prompt_text: str
    expected: str  # blocked | passed | payload_too_large
    generator_meta: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.label not in VALID_LABELS:
            raise ValueError(f"invalid label {self.label!r} for {self.sample_id}")
        if self.expected not in VALID_EXPECTED:
            raise ValueError(f"invalid expected {self.expected!r} for {self.sample_id}")
        if not self.sample_id:
            raise ValueError("sample_id required")
        if not self.prompt_text and self.expected != "payload_too_large":
            # allow empty only for special cases; still require str
            if self.prompt_text is None:
                raise ValueError(f"prompt_text required for {self.sample_id}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "sample_id": self.sample_id,
            "project": self.project,
            "source_dataset": self.source_dataset,
            "subset": self.subset,
            "category": self.category,
            "label": self.label,
            "prompt_text": self.prompt_text,
            "expected": self.expected,
            "generator_meta": dict(self.generator_meta or {}),
        }

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Sample":
        return Sample(
            sample_id=str(d["sample_id"]),
            project=str(d.get("project", "")),
            source_dataset=str(d.get("source_dataset", "")),
            subset=str(d.get("subset", "")),
            category=str(d.get("category", "")),
            label=str(d["label"]),
            prompt_text=str(d.get("prompt_text", "")),
            expected=str(d["expected"]),
            generator_meta=dict(d.get("generator_meta") or {}),
        )


@dataclass
class ResultRecord:
    sample_id: str
    manifest_name: str
    run_version: str
    http_status: int
    outcome: str
    security_flag: str
    latency_ms: int
    attempts: int
    ts: str
    response: str = ""  # model/body snippet for canary-echo checks (E4)

    def __post_init__(self) -> None:
        if self.outcome not in VALID_OUTCOMES:
            # allow unknown but warn via ValueError for strictness in tests
            raise ValueError(f"invalid outcome {self.outcome!r}")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "ResultRecord":
        return ResultRecord(
            sample_id=str(d["sample_id"]),
            manifest_name=str(d.get("manifest_name", "")),
            run_version=str(d.get("run_version", "")),
            http_status=int(d.get("http_status") or d.get("status") or 0),
            outcome=str(d["outcome"]),
            security_flag=str(d.get("security_flag", "")),
            latency_ms=int(d.get("latency_ms") or 0),
            attempts=int(d.get("attempts") or 1),
            ts=str(d.get("ts") or ""),
            response=str(d.get("response") or ""),
        )

    def to_jsonl_line(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)


@dataclass
class Manifest:
    name: str
    created_at: str
    seed: int
    source_dataset: str
    dataset_version: str
    adapter_version: str
    template_version: str
    strata_counts: dict[str, int]
    samples: list[Sample]
    # optional legacy bridge metadata
    extra: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.dataset_version:
            raise ValueError("dataset_version is required for provenance")
        if not self.adapter_version:
            raise ValueError("adapter_version is required for provenance")
        if not self.template_version:
            raise ValueError("template_version is required for provenance")

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "created_at": self.created_at,
            "seed": self.seed,
            "source_dataset": self.source_dataset,
            "dataset_version": self.dataset_version,
            "adapter_version": self.adapter_version,
            "template_version": self.template_version,
            "strata_counts": dict(self.strata_counts or {}),
            "samples": [s.to_dict() for s in self.samples],
            "n": len(self.samples),
            "extra": dict(self.extra or {}),
        }

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Manifest":
        samples_raw = d.get("samples") or []
        samples = [Sample.from_dict(s) for s in samples_raw]
        return Manifest(
            name=str(d["name"]),
            created_at=str(d.get("created_at") or ""),
            seed=int(d.get("seed") or 42),
            source_dataset=str(d.get("source_dataset") or ""),
            dataset_version=str(d.get("dataset_version") or "unknown"),
            adapter_version=str(d.get("adapter_version") or "unknown"),
            template_version=str(d.get("template_version") or "none"),
            strata_counts=dict(d.get("strata_counts") or {}),
            samples=samples,
            extra=dict(d.get("extra") or {}),
        )

    @staticmethod
    def now_iso() -> str:
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def samples_by_id(samples: Iterable[Sample]) -> dict[str, Sample]:
    return {s.sample_id: s for s in samples}
