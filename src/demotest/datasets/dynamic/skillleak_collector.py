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
from .markers import SkillLeakBenchMarkerProvider
from .parser import parse_execution
from .sandbox import SkillLeakBenchSandboxRunner
from .schemas import COLLECTOR_VERSION, DynamicExecutionRecord, trace_snapshot_sha256
from .snapshot import SNAPSHOTS_ROOT, SnapshotManifest, load_snapshot

DATASET_ID = "credential_dynamic_traces"


@dataclass(frozen=True)
class CollectReport:
    snapshot_id: str
    offset: int = 0
    limit: int | None = None
    n_skills_selected: int = 0
    n_skills_attempted: int = 0
    n_skills_skipped_existing: int = 0
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
            "offset": self.offset,
            "limit": self.limit,
            "n_skills_selected": self.n_skills_selected,
            "n_skills_attempted": self.n_skills_attempted,
            "n_skills_skipped_existing": self.n_skills_skipped_existing,
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

    def _marker_provider(self) -> SkillLeakBenchMarkerProvider:
        try:
            return SkillLeakBenchMarkerProvider(self.runner.pipeline_root)
        except Exception as e:
            raise RuntimeError(
                "official SkillLeakBench credential marker provider unavailable; "
                "Core collection refused"
            ) from e

    def collect(
        self,
        *,
        snapshot_id: str,
        offset: int = 0,
        limit: int | None = None,
        condition: str = "deterministic",
    ) -> CollectReport:
        manifest = load_snapshot(snapshot_id, root=self.snapshots_root)
        problems: list[str] = []
        executions, traces = self._load_existing(manifest)
        completed = {(r.skill_id, r.condition) for r in executions}

        all_skills = list(manifest.skills)
        start_idx = max(0, int(offset))
        stop_idx = None if limit is None else start_idx + max(0, int(limit))
        skills = all_skills[start_idx:stop_idx]
        skipped_existing = 0
        attempted = 0
        marker_provider = self._marker_provider()

        for entry in skills:
            if (entry.skill_id, condition) in completed:
                skipped_existing += 1
                continue
            attempted += 1
            skill_dir = self.snapshots_root / snapshot_id / "skills" / entry.skill_id
            # Official forged markers — same values the container's entrypoint
            # generates via mock_creds.generate_mock_credentials(skill_id).
            # Core never falls back to TEST_SECRET — that would diverge from
            # the container's actual injected values.
            creds: dict[str, str] = marker_provider.markers_for_skill(entry.skill_id)
            # Condition-isolated workdir: <raw>/executions/<snapshot>/<skill>/<condition>/
            exec_work = self.raw_dir / "executions" / snapshot_id / entry.skill_id / condition
            try:
                record = self.runner.run_skill(
                    skill_id=entry.skill_id,
                    skill_dir=skill_dir,
                    skill_snapshot_sha256=entry.sha256,
                    credentials=creds,
                    condition=condition,
                    declared_providers=entry.declared_providers,
                    command=entry.entry_command or None,
                    work_root=exec_work,
                )
            except Exception as e:
                problems.append(f"{entry.skill_id}: sandbox error: {e}")
                continue
            executions.append(record)
            traces.extend(parse_execution(record, creds))
            completed.add((entry.skill_id, condition))

        return self._freeze(
            manifest=manifest,
            executions=executions,
            traces=traces,
            problems=problems,
            n_attempted=attempted,
            n_selected=len(skills),
            n_skipped_existing=skipped_existing,
            offset=start_idx,
            limit=limit,
        )

    def _load_existing(
        self, manifest: SnapshotManifest,
    ) -> tuple[list[DynamicExecutionRecord], list[CredentialTrace]]:
        """Load same-snapshot state for serial batch resume.

        Snapshot, pipeline, collector semantics, image digest and sandbox
        resource profile must remain identical across batches.
        """
        meta_path = self.raw_dir / "trace_meta.json"
        exec_path = self.raw_dir / "executions.jsonl"
        trace_path = self.raw_dir / "traces.jsonl"
        if not any(p.exists() for p in (meta_path, exec_path, trace_path)):
            return [], []
        if not meta_path.exists():
            raise RuntimeError(
                f"existing dynamic state under {self.raw_dir} has no trace_meta.json; "
                "refusing unsafe resume"
            )
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        if meta.get("snapshot_id") != manifest.snapshot_id:
            raise RuntimeError(
                f"existing snapshot_id {meta.get('snapshot_id')} != requested {manifest.snapshot_id}"
            )
        if meta.get("pipeline_revision") != self.runner.pipeline_revision:
            raise RuntimeError("pipeline revision changed; start a new raw dataset snapshot")
        if meta.get("builder_version") != COLLECTOR_VERSION:
            raise RuntimeError(
                f"collector version {meta.get('builder_version')} != current {COLLECTOR_VERSION}; "
                "refusing to mix collector semantics"
            )
        current_profile = self.runner.resource_profile() if hasattr(self.runner, "resource_profile") else {}
        existing_profile = meta.get("sandbox_profile") or {}
        if existing_profile != current_profile:
            raise RuntimeError(
                "sandbox resource/isolation profile changed; refusing to mix executions"
            )
        # Image digest drift must also be rejected — same profile can hide a rebuild.
        current_digest = self.runner.image_digest()
        existing_digest = str(meta.get("sandbox_image_digest") or "")
        if existing_digest and current_digest and existing_digest != current_digest:
            raise RuntimeError(
                f"sandbox image digest changed: {existing_digest} -> {current_digest}; "
                "refusing to mix executions from different images"
            )

        executions: list[DynamicExecutionRecord] = []
        if exec_path.exists():
            for raw in exec_path.read_text(encoding="utf-8").splitlines():
                if raw.strip():
                    executions.append(DynamicExecutionRecord.from_dict(json.loads(raw)))
        traces: list[CredentialTrace] = []
        if trace_path.exists():
            for raw in trace_path.read_text(encoding="utf-8").splitlines():
                if raw.strip():
                    traces.append(CredentialTrace.from_dict(json.loads(raw)))
        return executions, traces

    def _freeze(
        self,
        *,
        manifest: SnapshotManifest,
        executions: list[DynamicExecutionRecord],
        traces: list[CredentialTrace],
        problems: list[str],
        n_attempted: int,
        n_selected: int,
        n_skipped_existing: int,
        offset: int,
        limit: int | None,
    ) -> CollectReport:
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        executions = list({r.execution_id: r for r in executions}.values())
        traces = list({t.trace_id: t for t in traces}.values())

        # executions.jsonl — every execution incl. unresolved ones (audit trail)
        exec_path = self.raw_dir / "executions.jsonl"
        exec_text = "".join(
            json.dumps(rec.to_dict(), ensure_ascii=False, sort_keys=True) + "\n"
            for rec in sorted(executions, key=lambda r: r.execution_id)
        )
        _atomic_write_text(exec_path, exec_text)

        # traces.jsonl — dataset-eligible traces only, deterministic order
        traces.sort(key=lambda t: t.trace_id)
        out_path = self.raw_dir / "traces.jsonl"
        trace_text = "".join(
            json.dumps(tr.to_dict(), ensure_ascii=False, sort_keys=True) + "\n"
            for tr in traces
        )
        _atomic_write_text(out_path, trace_text)

        # snapshot hash over file BYTES (same convention as the synthetic builder)
        file_bytes = out_path.read_bytes() if out_path.exists() else b""
        snap_sha = trace_snapshot_sha256(file_bytes)
        n_unsafe = sum(
            1 for t in traces
            if not (t.metadata.get("authorized_sink") or t.metadata.get("safe_redaction"))
        )
        marker_prov = self._marker_provider()
        cred_prov = marker_prov.provenance
        cand_prov = dict(getattr(manifest, "candidate_provenance", {}) or {})
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
            "candidate_provenance": cand_prov,
            "candidate_set_id": cand_prov.get("candidate_set_id", ""),
            "materialization_sha256": cand_prov.get("materialization_sha256", ""),
            "sandbox_image_digest": self.runner.image_digest(),
            "sandbox_profile": self.runner.resource_profile() if hasattr(self.runner, "resource_profile") else {},
            "isolation_level": getattr(self.runner, "isolation_level", ""),
            "pipeline_revision": self.runner.pipeline_revision,
            "execution_modes": sorted({r.execution_mode for r in executions}),
            "conditions": sorted({r.condition for r in executions}),
            "credential_provenance": cred_prov,
        }
        _atomic_write_text(
            self.raw_dir / "trace_meta.json",
            json.dumps(meta, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
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
                "candidate_set_id": cand_prov.get("candidate_set_id", ""),
                "materialization_sha256": cand_prov.get("materialization_sha256", ""),
                "candidate_policy_version": cand_prov.get("candidate_policy_version", ""),
                "sandbox_image_digest": self.runner.image_digest(),
                "sandbox_profile": meta["sandbox_profile"],
                "isolation_level": meta["isolation_level"],
                "trace_hash": meta["trace_hash"],
                "collector_version": COLLECTOR_VERSION,
                "credential_provenance": cred_prov,
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
            offset=offset,
            limit=limit,
            n_skills_selected=n_selected,
            n_skills_attempted=n_attempted,
            n_skills_skipped_existing=n_skipped_existing,
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


def _atomic_write_text(path: Path, text: str) -> None:
    """Replace collector state atomically so interrupted batches remain resumable."""
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)
