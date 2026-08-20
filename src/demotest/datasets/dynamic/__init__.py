"""Dynamic sandbox trace collection for P4 Core (guide P4 dynamic).

Boundary:
  sandbox.py   — Docker invocation via the PINNED SkillLeakBench pipeline only
  parser.py    — sandbox artifacts → CredentialTrace (DYNAMIC_TRACE)
  collector    — orchestration → raw traces.jsonl + trace_meta.json + lock
  snapshot.py  — frozen skill snapshots (per-skill SHA, archive SHA)
  schemas.py   — DynamicExecutionRecord + canonical full-event trace_hash
"""
from .schemas import (
    COLLECTOR_VERSION,
    DATASET_ELIGIBLE_OUTCOMES,
    DynamicExecutionRecord,
    DynamicSpecError,
    assert_fake_canary,
    canonical_trace_hash,
    trace_snapshot_sha256,
)

__all__ = [
    "COLLECTOR_VERSION",
    "DATASET_ELIGIBLE_OUTCOMES",
    "DynamicExecutionRecord",
    "DynamicSpecError",
    "assert_fake_canary",
    "canonical_trace_hash",
    "trace_snapshot_sha256",
]
