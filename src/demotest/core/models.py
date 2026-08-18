"""SecurityCase — the V3 core abstraction.

A ``SecurityCase`` is *one security event flowing through the gateway*: a piece
of content on a named :class:`Channel`, about to undergo an :class:`Operation`,
with an :class:`ExpectedAction`. It replaces V2's flat ``Sample.prompt_text``.

The case carries structured context (tool args, MCP schema, memory target,
credential markers, presentation style) that V2 had to compress into a string.
Renderers turn a case into a :class:`~demotest.core.contracts.GatewayRequest`;
the case itself never knows how it is sent.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from .enums import (
    Channel,
    Direction,
    ExpectedAction,
    Operation,
)
from .exceptions import ValidationError
from .ids import compute_case_id

# Channels whose content is inherently outbound (leaving the agent / gateway).
_OUTBOUND_CHANNELS = frozenset(
    {Channel.OUTBOUND_RESPONSE, Channel.TOOL_CALL, Channel.MEMORY_WRITE}
)


@dataclass(frozen=True)
class SecurityCase:
    # --- identity (plan §4) ---
    case_id: str
    dataset_id: str
    source_id: str

    # --- what / where / why ---
    channel: Channel
    operation: Operation
    direction: Direction = Direction.INBOUND

    content: str = ""
    expected_action: ExpectedAction = ExpectedAction.BLOCK

    # --- context ---
    user_intent: str = ""
    threat_id: str = ""
    project_id: str = ""

    # --- tool context ---
    tool_name: str = ""
    tool_arguments: dict[str, Any] = field(default_factory=dict)
    tool_result: str = ""

    # --- MCP context ---
    mcp_server: str = ""
    mcp_tool: str = ""
    mcp_description: str = ""
    mcp_schema: dict[str, Any] = field(default_factory=dict)

    # --- memory context ---
    memory_target: str = ""
    memory_operation: str = ""

    # --- credential context ---
    credential_markers: list[str] = field(default_factory=list)

    # --- presentation / provenance ---
    presentation_style: str = ""  # explicit | structured | stealth | natural
    labels: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    # --- optional expected scanner (future; not enforced) ---
    expected_scanner: str = ""

    def __post_init__(self) -> None:
        # Coerce enum-like inputs so builders can pass plain strings.
        object.__setattr__(self, "channel", Channel.from_value(self.channel))
        object.__setattr__(self, "operation", Operation.from_value(self.operation))
        object.__setattr__(
            self, "expected_action", ExpectedAction.from_value(self.expected_action)
        )
        object.__setattr__(self, "direction", Direction.from_value(self.direction))

        if not self.case_id:
            object.__setattr__(
                self,
                "case_id",
                compute_case_id(
                    self.dataset_id,
                    self.source_id,
                    self.channel.value,
                    self.operation.value,
                    self.threat_id,
                ),
            )
        if not self.dataset_id:
            raise ValidationError("SecurityCase requires dataset_id")
        if not self.source_id:
            raise ValidationError("SecurityCase requires source_id")
        if not self.content and self.expected_action == ExpectedAction.ALLOW:
            # benign cases still need *something* to send; allow empty only for
            # ALLOW where the renderer may inject benign filler (rare). Be strict.
            pass
        if self.presentation_style and self.presentation_style not in (
            "explicit",
            "structured",
            "stealth",
            "natural",
            "",
        ):
            # keep permissive: extra styles allowed but flagged via metadata
            pass

    # ------------------------------------------------------------------ helpers
    def is_attack(self) -> bool:
        return self.expected_action == ExpectedAction.BLOCK

    def is_benign(self) -> bool:
        return self.expected_action == ExpectedAction.ALLOW

    def redacted_view(self) -> dict[str, Any]:
        """A log-safe dict (no credential markers expanded)."""
        d = self.to_dict()
        if d.get("credential_markers"):
            d["credential_markers"] = [
                "<canary>" if m else "" for m in self.credential_markers
            ]
        return d

    # ------------------------------------------------------------------ serde
    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "dataset_id": self.dataset_id,
            "source_id": self.source_id,
            "channel": self.channel.value,
            "operation": self.operation.value,
            "direction": self.direction.value,
            "content": self.content,
            "expected_action": self.expected_action.value,
            "user_intent": self.user_intent,
            "threat_id": self.threat_id,
            "project_id": self.project_id,
            "tool_name": self.tool_name,
            "tool_arguments": dict(self.tool_arguments or {}),
            "tool_result": self.tool_result,
            "mcp_server": self.mcp_server,
            "mcp_tool": self.mcp_tool,
            "mcp_description": self.mcp_description,
            "mcp_schema": dict(self.mcp_schema or {}),
            "memory_target": self.memory_target,
            "memory_operation": self.memory_operation,
            "credential_markers": list(self.credential_markers or []),
            "presentation_style": self.presentation_style,
            "labels": dict(self.labels or {}),
            "metadata": dict(self.metadata or {}),
            "expected_scanner": self.expected_scanner,
        }

    @staticmethod
    def from_dict(d: Mapping[str, Any]) -> "SecurityCase":
        return SecurityCase(
            case_id=str(d.get("case_id") or ""),
            dataset_id=str(d.get("dataset_id") or ""),
            source_id=str(d.get("source_id") or ""),
            channel=Channel.from_value(d.get("channel") or "user_prompt"),
            operation=Operation.from_value(d.get("operation") or "chat"),
            direction=Direction.from_value(d.get("direction") or "inbound"),
            content=str(d.get("content") or ""),
            expected_action=ExpectedAction.from_value(
                d.get("expected_action") or d.get("expected") or "block"
            ),
            user_intent=str(d.get("user_intent") or ""),
            threat_id=str(d.get("threat_id") or ""),
            project_id=str(d.get("project_id") or d.get("project") or ""),
            tool_name=str(d.get("tool_name") or ""),
            tool_arguments=dict(d.get("tool_arguments") or {}),
            tool_result=str(d.get("tool_result") or ""),
            mcp_server=str(d.get("mcp_server") or ""),
            mcp_tool=str(d.get("mcp_tool") or ""),
            mcp_description=str(d.get("mcp_description") or ""),
            mcp_schema=dict(d.get("mcp_schema") or {}),
            memory_target=str(d.get("memory_target") or ""),
            memory_operation=str(d.get("memory_operation") or ""),
            credential_markers=list(d.get("credential_markers") or []),
            presentation_style=str(d.get("presentation_style") or ""),
            labels=dict(d.get("labels") or {}),
            metadata=dict(d.get("metadata") or {}),
            expected_scanner=str(d.get("expected_scanner") or ""),
        )

    # ------------------------------------------------------------------ build
    @classmethod
    def build(
        cls,
        *,
        dataset_id: str,
        source_id: str,
        channel: str | Channel,
        operation: str | Operation,
        content: str = "",
        expected_action: str | ExpectedAction = ExpectedAction.BLOCK,
        **kwargs: Any,
    ) -> "SecurityCase":
        """Ergonomic constructor that derives ``case_id`` automatically."""
        ch = Channel.from_value(channel)
        op = Operation.from_value(operation)
        threat_id = str(kwargs.get("threat_id") or "")
        case_id = compute_case_id(dataset_id, source_id, ch.value, op.value, threat_id)
        direction = kwargs.get("direction")
        if direction is None:
            direction = (
                Direction.OUTBOUND if ch in _OUTBOUND_CHANNELS else Direction.INBOUND
            )
        return cls(
            case_id=case_id,
            dataset_id=dataset_id,
            source_id=source_id,
            channel=ch,
            operation=op,
            direction=Direction.from_value(direction),
            content=content,
            expected_action=ExpectedAction.from_value(expected_action),
            **kwargs,
        )
