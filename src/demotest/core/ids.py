"""Deterministic, content-addressed identifiers.

Design rules (refactor plan §20, §22, external review F9):
  * ``case_id`` is a stable hash of the *case identity* only — never of the
    renderer / target / model version. Same case → same id forever, so results
    stay comparable across renderer revisions. It is also content-independent
    by design: the same ``source_id`` with rewritten content keeps the id.
  * ``case_fingerprint`` hashes the *actual payload* (content + context). It is
    the resume guard: a clear outcome is reused only when ``case_id`` AND
    ``case_fingerprint`` both match, so a dataset that silently rewrites a row
    under an unchanged ``source_id`` cannot hide behind a stale result.
  * ``run_id`` aggregates run-time provenance (target, config, renderer, manifest).
  * Renderer / target / model versions live in run metadata, not in the id.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Mapping


def _stable_sha(text: str, n: int = 16) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:n]


def compute_case_id(
    dataset_id: str,
    source_id: str,
    channel: str,
    operation: str,
    threat_id: str = "",
) -> str:
    """Stable case id from case identity fields only.

    ``source_id`` is the original dataset row id (e.g. a V2 ``sample_id``), so
    distinct rows never collide even within one dataset.
    """
    raw = "|".join(
        [
            str(dataset_id or ""),
            str(source_id or ""),
            str(channel or ""),
            str(operation or ""),
            str(threat_id or ""),
        ]
    )
    return f"case-{_stable_sha(raw)}"


def compute_case_fingerprint(payload: Mapping[str, Any]) -> str:
    """Content-addressed fingerprint of a SecurityCase's mutable payload.

    Complements ``case_id`` (which is identity-only and content-independent by
    design, plan §20): ``case_fingerprint`` hashes the *actual case content* so
    resume can detect that a dataset re-issued a row under the same ``source_id``
    with different content (external review F9). Without this, a stale clear
    outcome would silently mask the new, never-tested payload.

    The identity fields that ``case_id`` already covers (``dataset_id``,
    ``source_id``, ``channel``, ``operation``, ``threat_id``) are excluded so a
    pure identity re-derivation does not churn the fingerprint; everything that
    is actual case *data* (content, tool args, mcp schema, memory target,
    credential markers, expected action, authorization context, leakage
    expectation, presentation style, labels, metadata) is included.
    """
    excluded = {
        "case_id",
        "dataset_id",
        "source_id",
        "channel",
        "operation",
        "threat_id",
        "project_id",
    }
    canonical = {k: v for k, v in dict(payload).items() if k not in excluded}
    blob = json.dumps(canonical, sort_keys=True, ensure_ascii=False, default=str)
    return f"fp-{_stable_sha(blob)}"


def compute_run_id(
    target: str,
    target_config_hash: str,
    renderer_version: str,
    manifest_hash_value: str,
    *,
    ts: str | None = None,
) -> str:
    """Stable run id aggregating run-time provenance (plan §22)."""
    stamp = ts or datetime.now(timezone.utc).strftime("%Y%m%d")
    short = _stable_sha(
        "|".join(
            [target, target_config_hash, renderer_version, manifest_hash_value]
        ),
        n=6,
    )
    return f"{stamp}-{target}-r{short}"


def config_hash(config: Mapping[str, Any]) -> str:
    """Stable hash of a config mapping (canonical JSON, sorted keys)."""
    blob = json.dumps(config, sort_keys=True, ensure_ascii=False, default=str)
    return _stable_sha(blob)


def manifest_hash(samples_blob: str) -> str:
    """Stable hash of a serialized manifest (the samples payload)."""
    return _stable_sha(samples_blob, n=12)


def request_hash(
    *,
    method: str,
    url: str,
    headers: Mapping[str, str] | None,
    json_body: Any,
) -> str:
    """Byte-stable hash of a transport request (for regression / dedup).

    Authorization header value is excluded so key rotation does not change the
    hash — only the presence of the header matters.
    """
    safe_headers: dict[str, str] = {}
    for k, v in (headers or {}).items():
        lk = str(k).lower()
        if lk == "authorization":
            safe_headers[lk] = "<redacted-present>" if v else "<absent>"
        else:
            safe_headers[lk] = str(v)
    body = json.dumps(json_body, sort_keys=True, ensure_ascii=False, default=str)
    raw = "\n".join([method.upper(), url, json.dumps(safe_headers, sort_keys=True), body])
    return _stable_sha(raw, n=12)
