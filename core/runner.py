"""Serial execution engine: throttle, retry, append-only jsonl, resume, retest-cooldown."""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from core.schema import Manifest, ResultRecord, Sample
from linemod_guard_client import CLEAR_OUTCOMES, is_clear_outcome

REQUEST_GAP = float(os.environ.get("LINEMOD_REQUEST_GAP", "3.5"))
MAX_ATTEMPTS = int(os.environ.get("LINEMOD_MAX_ATTEMPTS", "6"))

ClientFn = Callable[[str], dict[str, Any]]


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_results(path: Path) -> list[dict[str, Any]]:
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
    """sample_id -> latest record (by file order / ts)."""
    out: dict[str, dict[str, Any]] = {}
    for r in rows:
        sid = r.get("sample_id")
        if not sid:
            continue
        out[sid] = r
    return out


def clear_outcome_index(rows: Iterable[dict[str, Any]]) -> dict[str, str]:
    """sample_id -> latest clear outcome (for resume skip)."""
    latest = latest_outcomes(rows)
    clear: dict[str, str] = {}
    for sid, rec in latest.items():
        oc = rec.get("outcome") or ""
        if is_clear_outcome(oc):
            clear[sid] = oc
    return clear


def append_result(path: Path, rec: ResultRecord) -> None:
    """Append one jsonl line with flush + fsync."""
    path.parent.mkdir(parents=True, exist_ok=True)
    line = rec.to_jsonl_line() + "\n"
    with path.open("a", encoding="utf-8") as f:
        f.write(line)
        f.flush()
        try:
            os.fsync(f.fileno())
        except OSError:
            pass


def _backoff_sleep(attempt: int, gap: float) -> None:
    # min(2**attempt * gap, 120)
    pause = min((2**attempt) * gap, 120.0)
    time.sleep(pause)


def _call_with_retry(
    client: ClientFn,
    prompt: str,
    *,
    gap: float,
    max_attempts: int,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Retry on 429 / retryable errors. Clear outcomes stop early.

    Gap between *samples* is handled by run_manifest; here we only backoff on retry.
    """
    last: dict[str, Any] = {
        "outcome": "error",
        "status": 0,
        "security_flag": "",
        "latency_ms": 0,
        "blocked": False,
    }
    for attempt in range(max_attempts):
        result = client(prompt)
        last = dict(result)
        last["attempts"] = attempt + 1
        outcome = last.get("outcome") or "error"
        if is_clear_outcome(outcome):
            return last
        if outcome == "rate_limited" or last.get("retryable_cooldown"):
            if attempt + 1 < max_attempts:
                pause = min((2**attempt) * gap, 120.0)
                sleep_fn(pause)
                continue
            return last
        # non-retryable error
        if outcome == "error" and last.get("retryable_cooldown"):
            if attempt + 1 < max_attempts:
                pause = min((2**attempt) * gap, 120.0)
                sleep_fn(pause)
                continue
        return last
    return last


def run_manifest(
    manifest: Manifest,
    out_path: Path,
    *,
    client: ClientFn,
    run_version: str = "dev",
    request_gap: float | None = None,
    max_attempts: int | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
    only_ids: set[str] | None = None,
) -> dict[str, Any]:
    """Serially run samples; append-only jsonl; skip clear outcomes (resume).

    Returns summary counts.
    """
    gap = REQUEST_GAP if request_gap is None else request_gap
    attempts_max = MAX_ATTEMPTS if max_attempts is None else max_attempts

    existing = load_results(out_path)
    clear_map = clear_outcome_index(existing)

    stats = {"total": len(manifest.samples), "skipped": 0, "ran": 0, "written": 0}

    for sample in manifest.samples:
        if only_ids is not None and sample.sample_id not in only_ids:
            continue
        if sample.sample_id in clear_map:
            stats["skipped"] += 1
            continue

        # serial gap before each live call
        if gap > 0:
            sleep_fn(gap)

        result = _call_with_retry(
            client,
            sample.prompt_text,
            gap=gap,
            max_attempts=attempts_max,
            sleep_fn=sleep_fn,
        )
        rec = ResultRecord(
            sample_id=sample.sample_id,
            manifest_name=manifest.name,
            run_version=run_version,
            http_status=int(result.get("status") or 0),
            outcome=str(result.get("outcome") or "error"),
            security_flag=str(result.get("security_flag") or ""),
            latency_ms=int(result.get("latency_ms") or 0),
            attempts=int(result.get("attempts") or 1),
            ts=_now_iso(),
            response=str(result.get("response") or "")[:2000],
        )
        append_result(out_path, rec)
        stats["ran"] += 1
        stats["written"] += 1
        # update clear map for subsequent logic in same run
        if is_clear_outcome(rec.outcome):
            clear_map[sample.sample_id] = rec.outcome

    return stats


def retest_cooldown(
    manifest: Manifest,
    results_path: Path,
    *,
    client: ClientFn,
    run_version: str = "dev",
    request_gap: float | None = None,
    max_attempts: int | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Re-run sample_ids whose latest outcome is still passed_upstream_cooldown.

    Appends newer records; analyze takes latest clear.
    """
    rows = load_results(results_path)
    latest = latest_outcomes(rows)
    cooldown_ids = {
        sid
        for sid, rec in latest.items()
        if rec.get("outcome") == "passed_upstream_cooldown"
    }
    # also include samples never written? no — only retest cooldown
    # If latest is cooldown, temporarily treat as non-clear so run_manifest will re-issue
    # We pass only_ids and a filtered clear map by using a custom approach:
    if not cooldown_ids:
        return {"total": len(manifest.samples), "skipped": len(manifest.samples), "ran": 0, "written": 0, "cooldown_ids": 0}

    gap = REQUEST_GAP if request_gap is None else request_gap
    attempts_max = MAX_ATTEMPTS if max_attempts is None else max_attempts
    stats = {"total": len(cooldown_ids), "skipped": 0, "ran": 0, "written": 0, "cooldown_ids": len(cooldown_ids)}

    for sample in manifest.samples:
        if sample.sample_id not in cooldown_ids:
            continue
        if gap > 0:
            sleep_fn(gap)
        result = _call_with_retry(
            client,
            sample.prompt_text,
            gap=gap,
            max_attempts=attempts_max,
            sleep_fn=sleep_fn,
        )
        rec = ResultRecord(
            sample_id=sample.sample_id,
            manifest_name=manifest.name,
            run_version=run_version,
            http_status=int(result.get("status") or 0),
            outcome=str(result.get("outcome") or "error"),
            security_flag=str(result.get("security_flag") or ""),
            latency_ms=int(result.get("latency_ms") or 0),
            attempts=int(result.get("attempts") or 1),
            ts=_now_iso(),
            response=str(result.get("response") or "")[:2000],
        )
        append_result(results_path, rec)
        stats["ran"] += 1
        stats["written"] += 1
    return stats
