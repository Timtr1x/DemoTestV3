"""Append-only JSONL result store (plan §23, §48).

V3 writes results under ``cache/results_v3`` (separate from V2's
``cache/results``) so the two never collide and regression comparisons stay
clean. The store is append-only with fsync; resume skips cases that already
have a clear (judged) outcome.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Iterable, Sequence

from ..core.contracts import CaseResult
from ..core.enums import CLEAR_OUTCOMES, Outcome
from ..core.ids import manifest_hash
from ..core.redactor import SecretRedactor


def load_results(path: Path) -> list[dict[str, Any]]:
    """Load all jsonl rows from a result file (skipping malformed lines)."""
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def latest_outcomes(rows: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """case_id -> latest record (by file order / ts)."""
    out: dict[str, dict[str, Any]] = {}
    for r in rows:
        cid = r.get("case_id")
        if not cid:
            continue
        out[cid] = r
    return out


def clear_outcome_index(rows: Iterable[dict[str, Any]]) -> dict[str, str]:
    """case_id -> latest clear outcome (for resume skip)."""
    latest = latest_outcomes(rows)
    clear: dict[str, str] = {}
    for cid, rec in latest.items():
        oc = rec.get("outcome") or ""
        if oc in {o.value for o in CLEAR_OUTCOMES}:
            clear[cid] = oc
    return clear


class ResultStore:
    """Append-only jsonl store with fsync + resume support.

    All persisted rows are passed through ``SecretRedactor`` before writing so
    canary markers (TEST_SECRET_*, CNY-*, bearer tokens, etc.) never land on
    disk in plaintext (plan §24, §43).
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ write
    def append(self, result: CaseResult) -> None:
        data = result.to_dict()
        markers = (data.get("metadata") or {}).get("credential_markers") or []
        data = SecretRedactor(extra_markers=markers).redact_dict(data)
        line = json.dumps(data, ensure_ascii=False) + "\n"
        with self.path.open("a", encoding="utf-8") as f:
            f.write(line)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass

    # ------------------------------------------------------------------ read
    def load(self) -> list[dict[str, Any]]:
        return load_results(self.path)

    def resolved(self) -> dict[str, dict[str, Any]]:
        """case_id -> latest clear outcome, else latest any (V2 resolve parity)."""
        rows = self.load()
        last_any: dict[str, dict[str, Any]] = {}
        last_clear: dict[str, dict[str, Any]] = {}
        clear_vals = {o.value for o in CLEAR_OUTCOMES}
        for r in rows:
            cid = r.get("case_id")
            if not cid:
                continue
            last_any[cid] = r
            if r.get("outcome") in clear_vals:
                last_clear[cid] = r
        out: dict[str, dict[str, Any]] = {}
        for cid, rec in last_any.items():
            out[cid] = last_clear.get(cid, rec)
        return out

    def clear_case_ids(self) -> set[str]:
        return set(clear_outcome_index(self.load()).keys())

    def cooldown_case_ids(self) -> set[str]:
        """case_ids whose latest outcome is upstream_cooldown (need retest)."""
        latest = latest_outcomes(self.load())
        return {
            cid
            for cid, rec in latest.items()
            if rec.get("outcome") == Outcome.UPSTREAM_COOLDOWN.value
        }

    # ------------------------------------------------------------------ misc
    def manifest_hash_of(self, cases_blob: str) -> str:
        return manifest_hash(cases_blob)
