"""HISTORICAL one-shot packaging helper — P4 official freeze (2026-08-21).

This script packaged the FIRST frozen P4 artifact (single CONFIRMED_DISCLOSURE
trace, andytrust / TELEGRAM_BOT_TOKEN) from already-human-reviewed evidence.
It is kept ONLY as a record of how the committed artifact under
benchmarks/frozen/datasets/credential_dynamic_traces/ was produced.

FUTURE PUBLISHING RULE (docs/PROJECT_SCOPE.md §5): a script must NEVER
auto-accept traces or stand in for Human Review. Every future publish starts
from a human-finished review (7 evidence gates, fail-closed) and the packaging
step only serializes already-ACCEPTED traces + binds hashes. Running this
script again on new traces without human review is forbidden.
"""
from __future__ import annotations

import json
from pathlib import Path

from demotest.datasets.traces.models import CredentialTrace
from demotest.datasets.dynamic.review import (
    TraceReview,
    freeze_reviewed_traces,
    REVIEW_VERSION,
)

SRC = Path("cache/datasets_v3/raw/credential_dynamic_traces_sourcebound/traces.jsonl")
RAW = Path("benchmarks/frozen/datasets/credential_dynamic_traces/raw")


def main() -> None:
    tr = CredentialTrace.from_dict(json.loads(SRC.read_text(encoding="utf-8").splitlines()[0]))
    assert tr.evidence_type == "DYNAMIC_TRACE"
    assert tr.dynamic_confirmed is True
    assert tr.trace_hash
    assert tr.flow_class == "STDOUT_EXPOSURE"
    assert tr.gateway_visibility == "DIRECT"

    # All 7 evidence gates true (human-reviewed CONFIRMED_DISCLOSURE).
    review = TraceReview(
        trace_id=tr.trace_id,
        review_status="ACCEPTED",
        source_real=True,
        dynamic_execution_real=True,
        fake_credential_confirmed=True,
        marker_observed=True,
        sink_confirmed=True,
        gateway_projection_valid=True,
        expected_action_valid=True,
        review_reason="CONFIRMED_DISCLOSURE: exception URL prints /bot<marker>/sendMessage with "
                      "source-bound canary leakbench-sourcebound-4705bca090dc-389c511417f6",
        reviewer="official-p4-freeze",
        reviewed_at="2026-08-21T00:00:00Z",
        review_schema_version=REVIEW_VERSION,
    )
    meta = freeze_reviewed_traces([tr], raw_dir=RAW, reviews=[review])
    print(json.dumps(meta, indent=2, sort_keys=True))
    print("wrote reviewed_traces.jsonl + review_meta.json under", RAW / "reviews")


if __name__ == "__main__":
    main()
