"""Dynamic trace schemas — execution records + canonical hashing (guide P4).

A DynamicExecutionRecord is an OBSERVATION of one sandboxed skill execution:
what went in (fake canary credentials only), what came out (artifacts), and how
it ended (outcome). It never contains labels — labels are derived later by the
parser, and only SUCCESS_* outcomes may enter the dataset (guide §18/§19).

trace_hash covers the FULL canonical event (guide §8) — not just an ID — so any
change to payload/destination/marker/image/pipeline is detectable.
trace_snapshot_sha256 is separately the SHA-256 over the traces.jsonl bytes.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Literal

ExecutionOutcome = Literal[
    "SUCCESS_REACHED_SECRET_PATH",
    "SUCCESS_NO_SECRET_FLOW",
    "FAILED_SETUP",
    "FAILED_DEPENDENCY",
    "TIMEOUT",
    "SANDBOX_ERROR",
]
#: Only these outcomes may produce dataset traces (guide §19). Crashes,
#: timeouts and missing-dependency runs are UNRESOLVED — never benign controls.
DATASET_ELIGIBLE_OUTCOMES: tuple[str, ...] = (
    "SUCCESS_REACHED_SECRET_PATH",
    "SUCCESS_NO_SECRET_FLOW",
)

ExecutionCondition = Literal["benign", "adversarial", "deterministic"]
ExecutionMode = Literal["deterministic", "agent_driven"]

#: Deterministic fake canary shape — the ONLY credential value form the dynamic
#: collector may inject (security boundary, guide §13). No uuid/random/faker.
CANARY_RE = re.compile(r"^TEST_SECRET_[0-9A-F]{16}$")

COLLECTOR_VERSION = "dynamic-collector-v2"


class DynamicSpecError(ValueError):
    """Raised when collector inputs violate the fake-credential boundary."""


def assert_fake_canary(name: str, value: str) -> None:
    """Hard boundary: injected credential VALUES must be TEST_SECRET canaries."""
    if not CANARY_RE.match(str(value or "")):
        raise DynamicSpecError(
            f"credential {name!r} value is not a deterministic TEST_SECRET canary; "
            "refusing to inject non-fake credentials into the sandbox"
        )


def canonical_trace_hash(
    *,
    skill_snapshot_sha256: str,
    execution_condition: str,
    credential_marker: str,
    sink: str,
    canonical_payload: str,
    destination: str,
    sandbox_image_digest: str,
    pipeline_revision: str,
) -> str:
    """SHA-256 over the full canonical trace event (guide §8).

    Any change to payload, destination, marker, sink, image digest or pipeline
    revision changes the hash — an ID-only hash would miss payload drift.
    """
    blob = json.dumps(
        {
            "skill_snapshot_sha256": skill_snapshot_sha256,
            "execution_condition": execution_condition,
            "credential_marker": credential_marker,
            "sink": sink,
            "canonical_payload": canonical_payload,
            "destination": destination,
            "sandbox_image_digest": sandbox_image_digest,
            "pipeline_revision": pipeline_revision,
        },
        sort_keys=True,
        ensure_ascii=False,
    )
    return "sha256:" + hashlib.sha256(blob.encode("utf-8")).hexdigest()


def trace_snapshot_sha256(file_bytes: bytes) -> str:
    """SHA-256 over the raw traces.jsonl bytes (distinct from trace_hash, §8)."""
    return hashlib.sha256(file_bytes).hexdigest()


@dataclass(frozen=True)
class DynamicExecutionRecord:
    """One sandboxed skill execution — observed facts only, no inference."""

    execution_id: str
    skill_id: str
    skill_snapshot_sha256: str
    condition: ExecutionCondition
    execution_mode: ExecutionMode
    sandbox_provider: str  # "SkillLeakBench"
    pipeline_revision: str  # pinned git sha of the SkillLeakBench checkout
    sandbox_image_digest: str  # sha256:... of the docker image actually used
    outcome: ExecutionOutcome
    exit_code: int | None = None
    timeout: bool = False
    wall_clock_ms: int = 0
    stdout_artifact: str = ""  # path to captured stdout.log
    network_artifact: str = ""  # path to captured network payload log
    network_events: tuple[dict[str, Any], ...] = ()  # normalized captured events
    stdout_text: str = ""  # full captured stdout (raw evidence, untruncated)
    credential_names: tuple[str, ...] = ()  # env var NAMES injected (values never stored here)
    declared_providers: tuple[str, ...] = ()  # hosts the skill legitimately calls
    collector_version: str = COLLECTOR_VERSION
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "skill_id": self.skill_id,
            "skill_snapshot_sha256": self.skill_snapshot_sha256,
            "condition": self.condition,
            "execution_mode": self.execution_mode,
            "sandbox_provider": self.sandbox_provider,
            "pipeline_revision": self.pipeline_revision,
            "sandbox_image_digest": self.sandbox_image_digest,
            "outcome": self.outcome,
            "exit_code": self.exit_code,
            "timeout": self.timeout,
            "wall_clock_ms": self.wall_clock_ms,
            "stdout_artifact": self.stdout_artifact,
            "network_artifact": self.network_artifact,
            "network_events": [dict(e) for e in self.network_events],
            "credential_names": list(self.credential_names),
            "declared_providers": list(self.declared_providers),
            "collector_version": self.collector_version,
            "metadata": dict(self.metadata or {}),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "DynamicExecutionRecord":
        """Load a frozen execution row for batch resume.

        ``stdout_text`` is intentionally not serialized in executions.jsonl;
        existing rows are loaded only for identity/resume and are never
        re-parsed into traces.
        """
        return cls(
            execution_id=str(d.get("execution_id") or ""),
            skill_id=str(d.get("skill_id") or ""),
            skill_snapshot_sha256=str(d.get("skill_snapshot_sha256") or ""),
            condition=str(d.get("condition") or "deterministic"),  # type: ignore[arg-type]
            execution_mode=str(d.get("execution_mode") or "deterministic"),  # type: ignore[arg-type]
            sandbox_provider=str(d.get("sandbox_provider") or "SkillLeakBench"),
            pipeline_revision=str(d.get("pipeline_revision") or ""),
            sandbox_image_digest=str(d.get("sandbox_image_digest") or ""),
            outcome=str(d.get("outcome") or "SANDBOX_ERROR"),  # type: ignore[arg-type]
            exit_code=d.get("exit_code"),
            timeout=bool(d.get("timeout", False)),
            wall_clock_ms=int(d.get("wall_clock_ms") or 0),
            stdout_artifact=str(d.get("stdout_artifact") or ""),
            network_artifact=str(d.get("network_artifact") or ""),
            network_events=tuple(dict(e) for e in (d.get("network_events") or [])),
            stdout_text="",
            credential_names=tuple(str(x) for x in (d.get("credential_names") or [])),
            declared_providers=tuple(str(x) for x in (d.get("declared_providers") or [])),
            collector_version=str(d.get("collector_version") or COLLECTOR_VERSION),
            metadata=dict(d.get("metadata") or {}),
        )
