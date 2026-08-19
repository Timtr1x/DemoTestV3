"""CredentialTrace — raw observation before gateway projection (guide §21).

A CredentialTrace is NOT a SecurityCase. It records a real (or offline-
deterministically-synthesized but lineage-faithful) observation: a secret
injected as a fake canary appears in a concrete sink (stdout / network
payload). The adapter then *projects* each trace deterministically into one
SecurityCase (guide §22).

The trace file is immutable: once written, a changed sandbox bumps trace-v1 ->
trace-v2 (guide §24).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


TraceSink = Literal["stdout", "network", "filesystem", "config_file", "env_file"]
TraceChannel = Literal["TOOL_RESULT", "TOOL_CALL"]


@dataclass(frozen=True)
class CredentialTrace:
    trace_id: str
    # catalog lineage
    skill_id: str  # e.g. "277_creative-writer"
    skill_name: str
    issue_id: str  # e.g. "MAL-007" / "VUL-003" (the pattern_id for this issue)
    academic_code: str  # e.g. "MAL-B" / "VUL-C"
    pattern: str  # e.g. "Information Exposure"
    classification: str  # vulnerable | malicious
    severity: str

    # trace identity
    sink: TraceSink
    # gateway projection target (TOOL_RESULT for stdout, TOOL_CALL for network)
    gateway_channel: TraceChannel
    # gateway visibility (guide §16)
    gateway_visibility: Literal["DIRECT", "PROJECTED"] = "DIRECT"
    # flow class (guide §17)
    flow_class: str = ""  # STDOUT_EXPOSURE / NETWORK_EXFIL / ...
    # the fake canary placed in this trace (TEST_SECRET_*)
    credential_marker: str = ""
    # the raw payload that carried the canary (verbatim or structured body)
    payload: str = ""
    # for TOOL_CALL: the network destination / tool envelope
    destination: str = ""
    tool_name: str = ""
    tool_arguments: dict[str, Any] = field(default_factory=dict)

    # quality
    dynamic_confirmed: bool = False
    # lineage: which source revision + sandbox built this
    source_revision: str = ""
    sandbox_version: str = ""
    trace_hash: str = ""

    # extra structured context preserved for reporting
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "skill_id": self.skill_id,
            "skill_name": self.skill_name,
            "issue_id": self.issue_id,
            "academic_code": self.academic_code,
            "pattern": self.pattern,
            "classification": self.classification,
            "severity": self.severity,
            "sink": self.sink,
            "gateway_channel": self.gateway_channel,
            "gateway_visibility": self.gateway_visibility,
            "flow_class": self.flow_class,
            "credential_marker": self.credential_marker,
            "payload": self.payload,
            "destination": self.destination,
            "tool_name": self.tool_name,
            "tool_arguments": dict(self.tool_arguments or {}),
            "dynamic_confirmed": self.dynamic_confirmed,
            "source_revision": self.source_revision,
            "sandbox_version": self.sandbox_version,
            "trace_hash": self.trace_hash,
            "metadata": dict(self.metadata or {}),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "CredentialTrace":
        return cls(
            trace_id=str(d.get("trace_id") or ""),
            skill_id=str(d.get("skill_id") or ""),
            skill_name=str(d.get("skill_name") or ""),
            issue_id=str(d.get("issue_id") or ""),
            academic_code=str(d.get("academic_code") or ""),
            pattern=str(d.get("pattern") or ""),
            classification=str(d.get("classification") or ""),
            severity=str(d.get("severity") or ""),
            sink=str(d.get("sink") or "stdout"),  # type: ignore[assignment]
            gateway_channel=str(d.get("gateway_channel") or "TOOL_RESULT"),  # type: ignore[assignment]
            gateway_visibility=str(d.get("gateway_visibility") or "DIRECT"),  # type: ignore[assignment]
            flow_class=str(d.get("flow_class") or ""),
            credential_marker=str(d.get("credential_marker") or ""),
            payload=str(d.get("payload") or ""),
            destination=str(d.get("destination") or ""),
            tool_name=str(d.get("tool_name") or ""),
            tool_arguments=dict(d.get("tool_arguments") or {}),
            dynamic_confirmed=bool(d.get("dynamic_confirmed", False)),
            source_revision=str(d.get("source_revision") or ""),
            sandbox_version=str(d.get("sandbox_version") or ""),
            trace_hash=str(d.get("trace_hash") or ""),
            metadata=dict(d.get("metadata") or {}),
        )
