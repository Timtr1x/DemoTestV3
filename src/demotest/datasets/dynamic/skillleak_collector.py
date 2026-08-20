"""Dynamic trace collector — orchestration (guide §3).

candidate → sandbox run → parser → raw traces.jsonl + trace_meta.json + lock.

This module orchestrates only; it does not interpret sandbox artifacts (that is
parser.py) and does not build SecurityCases (that is the adapter + existing
projection). Every execution — including failures that produce no trace — is
recorded in executions.jsonl for audit (guide §18/§19).
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ...config import get_dataset
from ..source_lock import DatasetSourceLock, now_utc, write_source_lock
from ..traces.models import CredentialTrace
from .parser import parse_execution
from .sandbox import SkillLeakBenchSandboxRunner, injected_credentials
from .schemas import COLLECTOR_VERSION, DynamicExecutionRecord, trace_snapshot_sha256
from .snapshot import SNAPSHOTS_ROOT, SnapshotManifest, load_snapshot

DATASET_ID = "credential_dynamic_traces"


@dataclass(frozen=True)
class CollectReport:
    snapshot_id: str
    n_skills_attempted: int = 0
    n_executions: int = 0
    n_traces: int = 0
    n_stdout_block: int = 0
    n_network_block: int = 0
    n_allow: int = 0
    n_unresolved: int = 0
    trace_file: str = ""
    snapshot_sha256: str = ""
    problems: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "n_skills_attempted": self.n_skills_attempted,
            "n_executions": self.n_executions,
            "n_traces": self.n_traces,
            "n_stdout_block": self.n_stdout_block,
            "n_network_block": self.n_network_block,
            "n_allow": self.n_allow,
            "n_unresolved": self.n_unresolved,
            "trace_file": self.trace_file,
            "snapshot_sha256": self.snapshot_sha256,
            "problems": list(self.problems),
        }


class DynamicTraceCollector:
    """Runs a frozen skill snapshot through the sandbox and freezes traces."""

    def __init__(
        self,
        *,
        runner: SkillLeakBenchSandboxRunner,
        raw_dir: Path | str | None = None,
        snapshots_root: Path | str | None = None,
        metadata_root: Path | str | None = None,
    ) -> None:
        self.runner = runner
        if raw_dir is None:
            raw_dir = get_dataset(DATASET_ID).raw_path
        self.raw_dir = Path(raw_dir)
        self.snapshots_root = Path(snapshots_root) if snapshots_root else SNAPSHOTS_ROOT
        self.metadata_root = Path(metadata_root) if metadata_root else None

    def collect(
        self,
        *,
        snapshot_id: str,
        limit: int | None = None,
        condition: str = "deterministic",
    ) -> CollectReport:
        manifest = load_snapshot(snapshot_id, root=self.snapshots_root)
        problems: list[str] = []
        executions: list[DynamicExecutionRecord] = []
        traces: list[CredentialTrace] = []
        skills = list(manifest.skills)[: limit or None]

        for entry in skills:
            skill_dir = self.snapshots_root / snapshot_id / "skills" / entry.skill_id
            creds = injected_credentials(
                pipeline_revision=self.runner.pipeline_revision,
                skill_id=entry.skill_id,
            )
            try:
                record = self.runner.run_skill(
                    skill_id=entry.skill_id,
                    skill_dir=skill_dir,
                    skill_snapshot_sha256=entry.sha256,
                    credentials=creds,
                    condition=condition,
                    declared_providers=entry.declared_providers,
                    command=entry.entry_command or None,
                    work_root=self.raw_dir / "executions" / f"{snapshot_id}-{entry.skill_id}",
                )
            except Exception as e:
                problems.append(f"{entry.skill_id}: sandbox error: {e}")
                continue
            executions.append(record)
            traces.extend(parse_execution(record, creds))

        return self._freeze(
            manifest=manifest,
            executions=executions,
            traces=traces,
            problems=problems,
            n_attempted=len(skills),
        )

    def _freeze(
        self,
        *,
        manifest: SnapshotManifest,
        executions: list[DynamicExecutionRecord],
        traces: list[CredentialTrace],
        problems: list[str],
        n_attempted: int,
    ) -> CollectReport:
        self.raw_dir.mkdir(parents=True, exist_ok=True)

        # executions.jsonl — every execution incl. unresolved ones (audit trail)
        exec_path = self.raw_dir / "executions.jsonl"
        with exec_path.open("w", encoding="utf-8") as f:
            for rec in sorted(executions, key=lambda r: r.execution_id):
                f.write(json.dumps(rec.to_dict(), ensure_ascii=False, sort_keys=True) + "\n")

        # traces.jsonl — dataset-eligible traces only, deterministic order
        traces.sort(key=lambda t: t.trace_id)
        out_path = self.raw_dir / "traces.jsonl"
        with out_path.open("w", encoding="utf-8") as f:
            for tr in traces:
                f.write(json.dumps(tr.to_dict(), ensure_ascii=False, sort_keys=True) + "\n")

        # snapshot hash over file BYTES (same convention as the synthetic builder)
        file_bytes = out_path.read_bytes() if out_path.exists() else b""
        snap_sha = trace_snapshot_sha256(file_bytes)
        n_unsafe = sum(
            1 for t in traces
            if not (t.metadata.get("authorized_sink") or t.metadata.get("safe_redaction"))
        )
        meta = {
            "source_revision": self.runner.pipeline_revision,
            "n_traces": len(traces),
            "n_unsafe": n_unsafe,
            "by_channel": _count(traces, lambda t: t.gateway_channel),
            "by_visibility": _count(traces, lambda t: t.gateway_visibility),
            "by_flow_class": _count(traces, lambda t: t.flow_class),
            "trace_file": str(out_path),
            "trace_hash": hashlib.sha256(
                "\n".join(sorted(t.trace_id for t in traces)).encode()).hexdigest()[:16],
            "snapshot_sha256": snap_sha,
            "evidence_type": "DYNAMIC_TRACE",
            "quality_tier": "A/B",
            "builder_version": COLLECTOR_VERSION,
            "snapshot_id": manifest.snapshot_id,
            "skill_snapshot_archive_sha256": manifest.archive_sha256,
            "sandbox_image_digest": self.runner.image_digest(),
            "pipeline_revision": self.runner.pipeline_revision,
            "execution_mode": "deterministic",
        }
        (self.raw_dir / "trace_meta.json").write_text(
            json.dumps(meta, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        # source lock — same derived-lock convention as credential_catalog_synthetic
        # metadata_root is only used by isolated tests to avoid polluting the repo lock
        meta_path = None if self.metadata_root is None else self.metadata_root / f"{DATASET_ID}.lock.json"
        write_source_lock(DatasetSourceLock(
            dataset_id=DATASET_ID,
            source_type="derived",
            source_uri="skillleakbench_pipeline",
            revision=self.runner.pipeline_revision,
            license="MIT",
            raw_sha256=snap_sha,
            extra={
                "derived_from": "skillleakbench_pipeline",
                "snapshot_id": manifest.snapshot_id,
                "snapshot_sha256": manifest.archive_sha256,
                "sandbox_image_digest": self.runner.image_digest(),
                "trace_hash": meta["trace_hash"],
                "collector_version": COLLECTOR_VERSION,
            },
            adapter_name=DATASET_ID,
            adapter_version="1.0.0",
            acquired_at=now_utc(),
        ), path=meta_path)

        n_stdout = sum(1 for t in traces if t.sink == "stdout" and t.flow_class == "STDOUT_EXPOSURE")
        n_network = sum(1 for t in traces if t.sink == "network" and t.flow_class == "NETWORK_EXFIL")
        n_allow = sum(
            1 for t in traces
            if t.metadata.get("authorized_sink") or t.metadata.get("safe_redaction")
        )
        return CollectReport(
            snapshot_id=manifest.snapshot_id,
            n_skills_attempted=n_attempted,
            n_executions=len(executions),
            n_traces=len(traces),
            n_stdout_block=n_stdout,
            n_network_block=n_network,
            n_allow=n_allow,
            n_unresolved=len(executions) - sum(
                1 for r in executions if r.exit_code == 0 and not r.timeout),
            trace_file=str(out_path),
            snapshot_sha256=snap_sha,
            problems=tuple(problems),
        )


def _count(traces: list[CredentialTrace], key) -> dict[str, int]:
    out: dict[str, int] = {}
    for t in traces:
        k = str(key(t) or "")
        out[k] = out.get(k, 0) + 1
    return out
