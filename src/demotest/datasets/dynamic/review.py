"""P4 human review layer — CredentialTrace → ReviewedCredentialTrace (guide P4 D3).

The parser output ``traces.jsonl`` is never edited by hand. Review is an
append-only verdict per trace:

    traces.jsonl  →  review-export  →  human edits review.jsonl  →  review-apply
                  →  review-status   →  freeze-reviewed (DEV gate)

Review status
  ACCEPTED     — trace is real source_real + dynamic_execution_real + marker
                 observed at declared sink, guitar projection/expected_action valid.
  REJECTED     — trace is invalid / parser error / duplicate / not a security
                 boundary the gateway can express.
  NEEDS_REVIEW — default for new traces.

BLOCK traces require: which forged credential, where it was observed (stdout
vs network), which artifact segment contains it, and that the gateway
visibility is projectable. ALLOW traces require real evidence:
AUTHORIZED_SECRET_USE (declared provider) or REDACTED_OUTPUT (real redaction).
UNRESOLVED executions never become traces and therefore never enter review.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from ...paths import DATASE_V3_RAW_DIR
from ..traces.models import CredentialTrace

REVIEW_VERSION = "p4-review-v1"
ReviewStatus = Literal["ACCEPTED", "REJECTED", "NEEDS_REVIEW"]
REVIEW_STATUSES = ("ACCEPTED", "REJECTED", "NEEDS_REVIEW")

# Default review dir is alongside dynamic traces
REVIEW_DIRNAME = "reviews"
REVIEW_EXPORT = "review.jsonl"
REVIEW_VERDICTS = "review_verdicts.jsonl"


@dataclass(frozen=True)
class TraceReview:
    trace_id: str
    review_status: ReviewStatus = "NEEDS_REVIEW"
    source_real: bool = True
    dynamic_execution_real: bool = True
    fake_credential_confirmed: bool = True
    marker_observed: bool = True
    sink_confirmed: bool = True
    gateway_projection_valid: bool = True
    expected_action_valid: bool = True
    duplicate: bool = False
    parser_error: bool = False
    review_reason: str = ""
    reviewer: str = ""
    reviewed_at: str = ""
    review_schema_version: str = REVIEW_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "review_status": self.review_status,
            "source_real": self.source_real,
            "dynamic_execution_real": self.dynamic_execution_real,
            "fake_credential_confirmed": self.fake_credential_confirmed,
            "marker_observed": self.marker_observed,
            "sink_confirmed": self.sink_confirmed,
            "gateway_projection_valid": self.gateway_projection_valid,
            "expected_action_valid": self.expected_action_valid,
            "duplicate": self.duplicate,
            "parser_error": self.parser_error,
            "review_reason": self.review_reason,
            "reviewer": self.reviewer,
            "reviewed_at": self.reviewed_at,
            "review_schema_version": self.review_schema_version,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "TraceReview":
        return cls(
            trace_id=str(d.get("trace_id") or ""),
            review_status=str(d.get("review_status") or "NEEDS_REVIEW"),  # type: ignore[arg-type]
            source_real=bool(d.get("source_real", True)),
            dynamic_execution_real=bool(d.get("dynamic_execution_real", True)),
            fake_credential_confirmed=bool(d.get("fake_credential_confirmed", True)),
            marker_observed=bool(d.get("marker_observed", True)),
            sink_confirmed=bool(d.get("sink_confirmed", True)),
            gateway_projection_valid=bool(d.get("gateway_projection_valid", True)),
            expected_action_valid=bool(d.get("expected_action_valid", True)),
            duplicate=bool(d.get("duplicate", False)),
            parser_error=bool(d.get("parser_error", False)),
            review_reason=str(d.get("review_reason") or ""),
            reviewer=str(d.get("reviewer") or ""),
            reviewed_at=str(d.get("reviewed_at") or ""),
            review_schema_version=str(d.get("review_schema_version") or REVIEW_VERSION),
        )


def _review_path(raw_dir: Path, name: str = REVIEW_EXPORT) -> Path:
    return raw_dir / REVIEW_DIRNAME / name


# ---------------------------------------------------------------------------
# Export / apply
# ---------------------------------------------------------------------------

def export_reviews(
    traces: list[CredentialTrace],
    *,
    raw_dir: Path | str,
    existing_reviews: dict[str, TraceReview] | None = None,
) -> Path:
    """Write ``review.jsonl`` — one row per trace, preserving prior verdicts.

    New traces default to NEEDS_REVIEW; existing rows keep their verdict so
    incremental batches can be exported without losing prior human work.
    """
    raw_dir = Path(raw_dir)
    out_dir = raw_dir / REVIEW_DIRNAME
    out_dir.mkdir(parents=True, exist_ok=True)
    prior = existing_reviews or {}
    # Merge existing file if present and no explicit prior passed
    prior_path = _review_path(raw_dir, REVIEW_EXPORT)
    if not prior and prior_path.exists():
        prior = {r.trace_id: r for r in load_reviews(raw_dir)}
    rows: list[TraceReview] = []
    for tr in sorted(traces, key=lambda t: t.trace_id):
        if tr.trace_id in prior:
            rows.append(prior[tr.trace_id])
        else:
            rows.append(TraceReview(trace_id=tr.trace_id))
    # Deterministic export
    rows.sort(key=lambda r: r.trace_id)
    prior_path.write_text(
        "".join(json.dumps(r.to_dict(), ensure_ascii=False, sort_keys=True) + "\n" for r in rows),
        encoding="utf-8",
    )
    return prior_path


def load_reviews(raw_dir: Path | str, name: str = REVIEW_EXPORT) -> list[TraceReview]:
    p = _review_path(Path(raw_dir), name)
    if not p.exists():
        return []
    out: list[TraceReview] = []
    for raw in p.read_text(encoding="utf-8").splitlines():
        if raw.strip():
            out.append(TraceReview.from_dict(json.loads(raw)))
    return out


def load_reviews_from_file(path: Path | str) -> list[TraceReview]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"review file not found: {p}")
    out: list[TraceReview] = []
    for raw in p.read_text(encoding="utf-8").splitlines():
        if raw.strip():
            out.append(TraceReview.from_dict(json.loads(raw)))
    return out


def validate_review(review: TraceReview, trace: CredentialTrace | None = None) -> list[str]:
    """Return problem strings for one review row."""
    problems: list[str] = []
    if review.review_status not in REVIEW_STATUSES:
        problems.append(f"{review.trace_id}: invalid review_status {review.review_status!r}")
    if review.review_schema_version != REVIEW_VERSION:
        problems.append(f"{review.trace_id}: wrong schema {review.review_schema_version!r} != {REVIEW_VERSION}")
    if review.review_status == "ACCEPTED":
        # ACCEPTED must affirm all gates
        for field_name in ("source_real", "dynamic_execution_real", "fake_credential_confirmed",
                           "marker_observed", "sink_confirmed", "gateway_projection_valid",
                           "expected_action_valid"):
            if not getattr(review, field_name):
                problems.append(f"{review.trace_id}: ACCEPTED but {field_name} is false")
        if review.duplicate:
            problems.append(f"{review.trace_id}: ACCEPTED but duplicate=true")
        if review.parser_error:
            problems.append(f"{review.trace_id}: ACCEPTED but parser_error=true")
    if trace is not None:
        meta = trace.metadata or {}
        is_allow = bool(meta.get("authorized_sink") or meta.get("safe_redaction"))
        if review.review_status == "ACCEPTED" and trace.evidence_type != "DYNAMIC_TRACE":
            problems.append(f"{review.trace_id}: ACCEPTED but evidence_type={trace.evidence_type}")
        if review.review_status == "ACCEPTED" and not trace.dynamic_confirmed:
            problems.append(f"{review.trace_id}: ACCEPTED but dynamic_confirmed is false")
        if review.review_status == "ACCEPTED" and not trace.trace_hash:
            problems.append(f"{review.trace_id}: ACCEPTED but missing trace_hash")
    return problems


def apply_reviews(
    traces: list[CredentialTrace],
    reviews: list[TraceReview],
) -> tuple[list[CredentialTrace], list[str]]:
    """Filter traces to accepted ones; return (accepted_traces, problems).

    Problems include duplicate trace_ids across reviews and validation failures.
    NEEDS_REVIEW rows are excluded (neither accepted nor rejected — still pending).
    """
    by_id = {t.trace_id: t for t in traces}
    seen: set[str] = set()
    problems: list[str] = []
    accepted: list[CredentialTrace] = []
    for r in reviews:
        if r.trace_id in seen:
            problems.append(f"duplicate review for trace_id {r.trace_id}")
            continue
        seen.add(r.trace_id)
        tr = by_id.get(r.trace_id)
        if tr is None:
            problems.append(f"review for unknown trace_id {r.trace_id}")
            continue
        probs = validate_review(r, tr)
        if probs:
            problems.extend(probs)
        if r.review_status == "ACCEPTED":
            # Only count as accepted if it has no validation problems
            if not [p for p in probs if r.trace_id in p]:
                accepted.append(tr)
        elif r.review_status == "REJECTED":
            pass  # excluded, not a problem by itself
        elif r.review_status == "NEEDS_REVIEW":
            pass
    # Traces with no review row at all are implicitly NEEDS_REVIEW — excluded, not an error
    return sorted(accepted, key=lambda t: t.trace_id), problems


def review_status_summary(
    traces: list[CredentialTrace],
    reviews: list[TraceReview],
) -> dict[str, Any]:
    """Counts for review-status reporting."""
    by_id = {t.trace_id: t for t in traces}
    counts = {"ACCEPTED": 0, "REJECTED": 0, "NEEDS_REVIEW": 0, "UNREVIEWED": 0}
    review_map = {r.trace_id: r for r in reviews}
    for tid in by_id:
        r = review_map.get(tid)
        if r is None:
            counts["UNREVIEWED"] += 1
        else:
            counts[r.review_status] = counts.get(r.review_status, 0) + 1
    total = len(traces)
    return {
        "total_traces": total,
        "by_status": counts,
        "accepted": counts["ACCEPTED"],
        "rejected": counts["REJECTED"],
        "pending": counts["NEEDS_REVIEW"] + counts["UNREVIEWED"],
        "review_version": REVIEW_VERSION,
    }


def freeze_reviewed_traces(
    accepted: list[CredentialTrace],
    *,
    raw_dir: Path | str,
    reviews: list[TraceReview],
) -> dict[str, Any]:
    """Write the reviewed-traces artifact for freeze-reviewed.

    Produces ``<raw_dir>/reviews/reviewed_traces.jsonl`` (accepted traces only,
    deterministic order) plus ``reviews/review_meta.json`` with provenance.
    """
    raw_dir = Path(raw_dir)
    out_dir = raw_dir / REVIEW_DIRNAME
    out_dir.mkdir(parents=True, exist_ok=True)
    accepted = sorted(accepted, key=lambda t: t.trace_id)
    out_path = out_dir / "reviewed_traces.jsonl"
    out_path.write_text(
        "".join(json.dumps(t.to_dict(), ensure_ascii=False, sort_keys=True) + "\n" for t in accepted),
        encoding="utf-8",
    )
    blob = out_path.read_bytes()
    sha = hashlib.sha256(blob).hexdigest()
    meta = {
        "review_schema_version": REVIEW_VERSION,
        "n_accepted": len(accepted),
        "n_reviews": len(reviews),
        "sha256": sha,
        "trace_file": str(out_path),
    }
    (out_dir / "review_meta.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return meta
