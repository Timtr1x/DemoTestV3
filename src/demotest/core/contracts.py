"""Transport + observation + verdict contracts.

These decouple *what the gateway returned* (``GatewayObservation``) from
*whether that is correct for this case* (``Evaluation``) and from *how we store
it* (``CaseResult``). The HTTP parser (targets) builds an Observation; the Oracle
builds an Evaluation; the runner stamps a CaseResult.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping

from .enums import ExpectedAction, Outcome
from .ids import request_hash


class Verdict(str, Enum):
    """Confusion-matrix verdict for a judged case."""

    TP = "TP"  # expected block, actually blocked
    FN = "FN"  # expected block, actually allowed
    FP = "FP"  # expected allow, actually blocked
    TN = "TN"  # expected allow, actually allowed
    UNJUDGED = "UNJUDGED"  # rate_limited / error / cooldown — not counted in TPR/FPR


@dataclass(frozen=True)
class GatewayRequest:
    """The transport-level request a TargetAdapter sends.

    Renderers produce this; targets consume it. ``json_body`` ordering is the
    source of truth for byte-stable request hashing (regression).
    """

    target: str
    url: str
    method: str = "POST"
    headers: dict[str, str] = field(default_factory=dict)
    json_body: dict[str, Any] = field(default_factory=dict)
    model: str = ""
    timeout: float = 60.0
    # The rendered user-visible text (the single user message content). Kept for
    # logging/hashing without re-deriving from json_body.
    rendered_text: str = ""

    def request_hash(self) -> str:
        return request_hash(
            method=self.method,
            url=self.url,
            headers=self.headers,
            json_body=self.json_body,
        )

    def body_bytes(self) -> bytes:
        return json.dumps(self.json_body, ensure_ascii=False).encode("utf-8")


@dataclass
class GatewayObservation:
    """What the gateway actually returned, parsed into a normalized shape.

    Built by the target's HTTP parser. Separates transport (status/latency) from
    security signal (scanner/policy/score) so the Oracle can reason cleanly.
    """

    http_status: int = 0
    raw_body: str = ""
    gateway_action: str = ""  # raw gateway decision: blocked | allowed | ""
    security_blocked: bool = False
    scanner: str = ""
    policy: str = ""
    score: float | None = None
    security_flag: str = ""  # combined scanner/rule identifier (V2-compatible)
    latency_ms: int = 0
    attempts: int = 1
    rate_limited: bool = False
    upstream_cooldown: bool = False
    payload_too_large: bool = False
    error_type: str = ""
    response_text: str = ""  # returned content (for canary-echo checks)
    note: str = ""

    @property
    def outcome(self) -> Outcome:
        if self.security_blocked:
            return Outcome.BLOCKED
        if self.payload_too_large:
            return Outcome.PAYLOAD_TOO_LARGE
        if self.upstream_cooldown:
            return Outcome.UPSTREAM_COOLDOWN
        if self.rate_limited:
            return Outcome.RATE_LIMITED
        if self.error_type:
            return Outcome.ERROR
        return Outcome.PASSED

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["outcome"] = self.outcome.value
        return d


@dataclass(frozen=True)
class Evaluation:
    """Oracle verdict for one (case, observation) pair."""

    verdict: Verdict
    expected: ExpectedAction
    actual_outcome: Outcome
    detail: str = ""

    @property
    def judged(self) -> bool:
        return self.verdict != Verdict.UNJUDGED


@dataclass
class CaseResult:
    """The append-only record written to the result store (plan §23)."""

    case_id: str
    run_id: str
    project: str
    channel: str
    expected: str
    target: str
    request_hash: str
    http_status: int
    outcome: str
    scanner: str = ""
    policy: str = ""
    score: float | None = None
    security_flag: str = ""
    attempt: int = 1
    latency_ms: int = 0
    timestamp: str = ""
    renderer_name: str = ""
    renderer_version: str = ""
    verdict: str = ""
    # response_text stored only when a canary oracle needs it; redacted by
    # ResultStore.append before hitting disk (plan §24, §43).
    response_text: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # never persist None score as null silently — keep absent? keep null for json fidelity
        return d

    def to_jsonl(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @staticmethod
    def from_dict(d: Mapping[str, Any]) -> "CaseResult":
        return CaseResult(
            case_id=str(d.get("case_id") or ""),
            run_id=str(d.get("run_id") or ""),
            project=str(d.get("project") or ""),
            channel=str(d.get("channel") or ""),
            expected=str(d.get("expected") or ""),
            target=str(d.get("target") or ""),
            request_hash=str(d.get("request_hash") or ""),
            http_status=int(d.get("http_status") or 0),
            outcome=str(d.get("outcome") or "error"),
            scanner=str(d.get("scanner") or ""),
            policy=str(d.get("policy") or ""),
            score=d.get("score"),
            security_flag=str(d.get("security_flag") or ""),
            attempt=int(d.get("attempt") or 1),
            latency_ms=int(d.get("latency_ms") or 0),
            timestamp=str(d.get("timestamp") or ""),
            renderer_name=str(d.get("renderer_name") or ""),
            renderer_version=str(d.get("renderer_version") or ""),
            verdict=str(d.get("verdict") or ""),
            response_text=str(d.get("response_text") or ""),
            metadata=dict(d.get("metadata") or {}),
        )
