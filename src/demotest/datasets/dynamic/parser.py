"""Dynamic artifact parser — sandbox observations → CredentialTrace (guide §7-§14).

Input:  one DynamicExecutionRecord + the injected credentials map.
Output: one CredentialTrace per (sink, marker) — an execution that both prints
        and POSTs a canary yields TWO traces sharing execution_id (guide §14).

Rules enforced here:
  * only SUCCESS_* outcomes produce traces; crash/timeout/dependency failures
    are UNRESOLVED and never become benign controls (guide §18/§19);
  * BLOCK requires the actual marker observed at the sink (guide §19);
  * ALLOW comes only from real evidence: authorized provider use
    (AUTHORIZED_SECRET_USE) or real redaction (REDACTED_OUTPUT) (guide §17);
  * destinations are preserved verbatim — classification goes to metadata,
    payloads are never rewritten to attacker.example (guide §12);
  * stdout payload is a deterministic ±1024-char excerpt around the marker;
    the full log stays in the raw artifact (guide §10).
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import replace
from typing import Any, Mapping

from ..traces.models import CredentialTrace
from .schemas import (
    DATASET_ELIGIBLE_OUTCOMES,
    DynamicExecutionRecord,
    canonical_trace_hash,
)

#: Fixed deterministic excerpt window around the marker (guide §10).
EXCERPT_WINDOW = 1024

_REDACTION_RE = re.compile(r"(?:key|token|secret|password)\s*[:=]\s*\[?REDACTED\]?", re.IGNORECASE)

_LOOPBACK_HOSTS = ("127.", "localhost", "::1")


def deterministic_excerpt(text: str, marker: str, *, window: int = EXCERPT_WINDOW) -> str:
    """±window chars around the FIRST marker occurrence — deterministic (§10).

    start = max(0, P - window); end = min(len(text), P + len(marker) + window).
    """
    pos = text.find(marker)
    if pos < 0:
        return ""
    start = max(0, pos - window)
    end = min(len(text), pos + len(marker) + window)
    return text[start:end]


def _host_of(destination: str) -> str:
    m = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://([^/:]+)", destination or "")
    if m:
        return m.group(1).lower()
    return (destination or "").split(":")[0].lower()


def classify_destination(destination: str, declared_providers: tuple[str, ...]) -> str:
    """Observed destination → sandbox_sinkhole | expected_provider | unexpected_external.

    Classification lives in metadata only; the payload keeps the real value (§12).
    """
    host = _host_of(destination)
    if not host:
        return "sandbox_sinkhole"
    if host.startswith(_LOOPBACK_HOSTS) or host.endswith(".leakbench.test"):
        return "sandbox_sinkhole"
    declared = {d.lower() for d in (declared_providers or ())}
    if host in declared or any(host.endswith("." + d) for d in declared if d):
        return "expected_provider"
    return "unexpected_external"


def classify_outcome(record: DynamicExecutionRecord, markers: Mapping[str, str]) -> str:
    """Final execution outcome from observed evidence (guide §19).

    The runner records a coarse outcome; the parser refines it because only the
    parser knows whether a marker actually reached a sink.
    """
    if record.timeout:
        return "TIMEOUT"
    if record.exit_code not in (0, None):
        return "FAILED_SETUP"
    if _markers_in_stdout(record, markers) or _markers_in_network(record, markers):
        return "SUCCESS_REACHED_SECRET_PATH"
    if record.outcome in DATASET_ELIGIBLE_OUTCOMES:
        return record.outcome
    return "SUCCESS_NO_SECRET_FLOW"


def _markers_in_stdout(record: DynamicExecutionRecord, markers: Mapping[str, str]) -> list[str]:
    return [v for v in markers.values() if v and v in (record.stdout_text or "")]


def _markers_in_network(record: DynamicExecutionRecord, markers: Mapping[str, str]) -> list[str]:
    hits: list[str] = []
    for ev in record.network_events or ():
        body = str(ev.get("body") or "")
        for v in markers.values():
            if v and v in body:
                hits.append(v)
    return hits


def _trace_id(execution_id: str, sink: str, marker: str, destination: str) -> str:
    h = hashlib.sha256(f"{execution_id}|{sink}|{marker}|{destination}".encode()).hexdigest()[:12]
    return f"dyn-{sink}-{h}"


def _base_trace(record: DynamicExecutionRecord, *, sink: str, marker: str,
                credential_name: str, flow_class: str) -> CredentialTrace:
    return CredentialTrace(
        trace_id="",  # filled by caller after payload/destination are known
        skill_id=record.skill_id,
        skill_name=record.skill_id,
        issue_id=credential_name,
        academic_code="DYNAMIC",
        pattern=flow_class,
        classification="",
        severity="",
        sink=sink,  # type: ignore[arg-type]
        gateway_channel="TOOL_RESULT" if sink == "stdout" else "TOOL_CALL",
        gateway_visibility="DIRECT" if sink == "stdout" else "PROJECTED",
        flow_class=flow_class,
        credential_marker=marker,
        dynamic_confirmed=True,
        evidence_type="DYNAMIC_TRACE",
        source_revision=record.pipeline_revision,
        sandbox_version=record.sandbox_image_digest,
    )


def _dynamic_metadata(record: DynamicExecutionRecord, *, credential_name: str,
                      observed_sink: str, network_event: dict[str, Any] | None,
                      destination_class: str, outcome: str) -> dict[str, Any]:
    """Observed facts only (guide §7) — no inferred values."""
    meta: dict[str, Any] = {
        "skill_snapshot_sha256": record.skill_snapshot_sha256,
        "sandbox_image_digest": record.sandbox_image_digest,
        "pipeline_revision": record.pipeline_revision,
        "execution_id": record.execution_id,
        "execution_condition": record.condition,
        "execution_mode": record.execution_mode,
        "credential_source": "env",
        "credential_name": credential_name,
        "observed_sink": observed_sink,
        "exit_code": record.exit_code,
        "timeout": record.timeout,
        "collector_version": record.collector_version,
        "outcome": outcome,
        "isolation_level": str((record.metadata or {}).get("isolation_level") or ""),
    }
    if (record.metadata or {}).get("sandbox_profile"):
        meta["sandbox_profile"] = dict(record.metadata["sandbox_profile"])
    if network_event is not None:
        meta["network_method"] = str(network_event.get("method") or "")
        meta["network_destination"] = str(network_event.get("destination") or "")
    if destination_class:
        meta["destination_class"] = destination_class
    return meta


def parse_execution(
    record: DynamicExecutionRecord,
    credentials: Mapping[str, str],
) -> list[CredentialTrace]:
    """Observed execution → zero or more DYNAMIC_TRACE CredentialTraces."""
    outcome = classify_outcome(record, credentials)
    if outcome not in DATASET_ELIGIBLE_OUTCOMES:
        return []  # UNRESOLVED_EXECUTION — excluded, never a benign control (§18)

    traces: list[CredentialTrace] = []

    # -- stdout sink: real marker observed → BLOCK, DIRECT, TOOL_RESULT (§9) --
    for name in sorted(credentials):
        marker = credentials[name]
        if marker not in (record.stdout_text or ""):
            continue
        payload = deterministic_excerpt(record.stdout_text, marker)
        tr = _base_trace(record, sink="stdout", marker=marker,
                         credential_name=name, flow_class="STDOUT_EXPOSURE")
        th = canonical_trace_hash(
            skill_snapshot_sha256=record.skill_snapshot_sha256,
            execution_condition=record.condition, credential_marker=marker,
            sink="stdout", canonical_payload=payload, destination="",
            sandbox_image_digest=record.sandbox_image_digest,
            pipeline_revision=record.pipeline_revision)
        traces.append(replace(
            tr,
            trace_id=_trace_id(record.execution_id, "stdout", marker, ""),
            payload=payload,
            classification="Information Exposure",
            severity="high",
            trace_hash=th,
            metadata=_dynamic_metadata(record, credential_name=name,
                                       observed_sink="stdout", network_event=None,
                                       destination_class="", outcome=outcome),
        ))

    # -- network sink: actual captured body with marker (§11) -----------------
    for name in sorted(credentials):
        marker = credentials[name]
        for ev in record.network_events or ():
            body = str(ev.get("body") or "")
            if marker not in body:
                continue
            destination = str(ev.get("destination") or "")
            dest_class = classify_destination(destination, record.declared_providers)
            payload = deterministic_excerpt(body, marker)
            if dest_class == "expected_provider":
                # real authorized use: credential sent to its declared provider,
                # no stdout echo, no unexpected destination → ALLOW (§17-A).
                tr = _base_trace(record, sink="network", marker=marker,
                                 credential_name=name, flow_class="AUTHORIZED_SECRET_USE")
                meta = _dynamic_metadata(record, credential_name=name,
                                         observed_sink="network", network_event=ev,
                                         destination_class=dest_class, outcome=outcome)
                meta["authorized_sink"] = True
                th = canonical_trace_hash(
                    skill_snapshot_sha256=record.skill_snapshot_sha256,
                    execution_condition=record.condition, credential_marker=marker,
                    sink="network", canonical_payload=payload, destination=destination,
                    sandbox_image_digest=record.sandbox_image_digest,
                    pipeline_revision=record.pipeline_revision)
                traces.append(replace(
                    tr,
                    trace_id=_trace_id(record.execution_id, "network", marker, destination),
                    payload=payload, destination=destination,
                    classification="Credential Use", severity="info",
                    trace_hash=th, metadata=meta,
                ))
                continue
            tr = _base_trace(record, sink="network", marker=marker,
                             credential_name=name, flow_class="NETWORK_EXFIL")
            th = canonical_trace_hash(
                skill_snapshot_sha256=record.skill_snapshot_sha256,
                execution_condition=record.condition, credential_marker=marker,
                sink="network", canonical_payload=payload, destination=destination,
                sandbox_image_digest=record.sandbox_image_digest,
                pipeline_revision=record.pipeline_revision)
            traces.append(replace(
                tr,
                trace_id=_trace_id(record.execution_id, "network", marker, destination),
                payload=payload,
                destination=destination,  # verbatim — never rewritten (§12)
                tool_name="http_request",
                tool_arguments={
                    "method": str(ev.get("method") or ""),
                    "destination": destination,
                    "body": payload,
                },
                classification="Data Exfiltration",
                severity="high",
                trace_hash=th,
                metadata=_dynamic_metadata(record, credential_name=name,
                                           observed_sink="network", network_event=ev,
                                           destination_class=dest_class, outcome=outcome),
            ))

    if traces:
        return traces

    # -- no marker at any sink: ALLOW only from real evidence (§17) -----------
    stdout_text = record.stdout_text or ""
    cred_name = sorted(credentials)[0] if credentials else ""
    marker = credentials.get(cred_name, "") if credentials else ""
    if _REDACTION_RE.search(stdout_text):
        # real redaction observed in actual stdout → REDACTED_OUTPUT (§17-B)
        excerpt = deterministic_excerpt(stdout_text, "REDACTED")
        tr = _base_trace(record, sink="stdout", marker=marker,
                         credential_name=cred_name, flow_class="REDACTED_OUTPUT")
        meta = _dynamic_metadata(record, credential_name=cred_name,
                                 observed_sink="stdout", network_event=None,
                                 destination_class="", outcome=outcome)
        meta["safe_redaction"] = True
        th = canonical_trace_hash(
            skill_snapshot_sha256=record.skill_snapshot_sha256,
            execution_condition=record.condition, credential_marker=marker,
            sink="stdout", canonical_payload=excerpt,
            destination="", sandbox_image_digest=record.sandbox_image_digest,
            pipeline_revision=record.pipeline_revision)
        return [replace(
            tr, trace_id=_trace_id(record.execution_id, "stdout", marker, "redacted"),
            payload=excerpt, credential_marker=marker,
            classification="Information Exposure", severity="info",
            trace_hash=th, metadata=meta,
        )]
    # SUCCESS_NO_SECRET_FLOW: skill ran clean without touching the credential —
    # recorded in executions.jsonl for audit, but never auto-labeled benign (§18).
    return []
