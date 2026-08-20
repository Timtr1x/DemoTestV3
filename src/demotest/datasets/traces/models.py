"""CredentialTrace — raw observation before gateway projection (guide §21).

Evidence types:
  CATALOG_DERIVED — offline synthesis from the SkillLeakBench catalog taxonomy
                    (Extended / synthetic, quality C, dynamic_confirmed=False)
  DYNAMIC_TRACE   — real sandbox execution with forged third-party canary
                    (P4 Core, quality A/B, dynamic_confirmed=True)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


TraceSink = Literal["stdout", "network", "filesystem", "config_file", "env_file"]
TraceChannel = Literal["TOOL_RESULT", "TOOL_CALL"]
EvidenceType = Literal["CATALOG_DERIVED", "DYNAMIC_TRACE"]


@dataclass(frozen=True)
class CredentialTrace:
    trace_id: str
    skill_id: str
    skill_name: str
    issue_id: str
    academic_code: str
    pattern: str
    classification: str
    severity: str

    sink: TraceSink
    gateway_channel: TraceChannel
    gateway_visibility: Literal["DIRECT", "PROJECTED"] = "DIRECT"
    flow_class: str = ""
    credential_marker: str = ""
    payload: str = ""
    destination: str = ""
    tool_name: str = ""
    tool_arguments: dict[str, Any] = field(default_factory=dict)

    dynamic_confirmed: bool = False
    evidence_type: EvidenceType = "CATALOG_DERIVED"  # type: ignore[assignment]
    source_revision: str = ""
    sandbox_version: str = ""
    trace_hash: str = ""

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
            "evidence_type": self.evidence_type,
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
            evidence_type=str(d.get("evidence_type") or "CATALOG_DERIVED"),  # type: ignore[assignment]
            source_revision=str(d.get("source_revision") or ""),
            sandbox_version=str(d.get("sandbox_version") or ""),
            trace_hash=str(d.get("trace_hash") or ""),
            metadata=dict(d.get("metadata") or {}),
        )
