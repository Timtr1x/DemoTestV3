"""Credential dynamic traces adapter — P4 Core (DYNAMIC_TRACE only, guide §15).

This adapter has NO code path for synthetic/catalog data:
  * evidence_type != DYNAMIC_TRACE  → reject
  * dynamic_confirmed != True       → reject
  * missing trace_hash              → reject
  * projected quality not in {A,B}  → reject (defense in depth; projection
    already maps DYNAMIC_TRACE DIRECT→A / PROJECTED→B)

Core rules (config/v3/datasets/credential_dynamic_traces.yaml):
  stdout → tool_result (DIRECT, quality A, original)
  network → tool_call (PROJECTED, quality B, deterministic_projection)
  group_id = source_skill_id (skill-level split, guide §25)
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator

from ...config import DatasetSourceConfig, get_dataset
from ...core.enums import ExpectedAction, LeakageExpectation
from ...core.exceptions import DatasetSourceError
from ...core.models import SecurityCase
from ..base import DatasetAdapter, ValidationReport
from ..registry import register_adapter
from ..source_lock import load_source_lock
from ..traces.models import CredentialTrace
from ..traces.projection import project_trace_to_case


@register_adapter
class CredentialDynamicTracesAdapter(DatasetAdapter):
    dataset_id = "credential_dynamic_traces"
    adapter_version = "1.0.0"

    def __init__(
        self,
        *,
        raw_dir: Path | str | None = None,
        source_config: DatasetSourceConfig | None = None,
        trace_provider: Any | None = None,
        strict: bool = True,
    ) -> None:
        if source_config is None:
            source_config = get_dataset(self.dataset_id)
        self.source_config = source_config
        self.raw_dir = Path(raw_dir) if raw_dir else source_config.raw_path
        self._trace_provider = trace_provider
        self.strict = strict
        self._rejected: list[dict[str, Any]] = []

    def _trace_file(self) -> Path:
        return self.raw_dir / "traces.jsonl"

    def _load_traces(self) -> Iterator[CredentialTrace]:
        if self._trace_provider is not None:
            yield from self._trace_provider
            return
        fp = self._trace_file()
        if not fp.exists():
            return
        with fp.open("r", encoding="utf-8") as f:
            for lineno, raw in enumerate(f, 1):
                line = raw.strip()
                if not line:
                    continue
                try:
                    yield CredentialTrace.from_dict(json.loads(line))
                except Exception as e:
                    self._rejected.append({"lineno": lineno, "error": str(e), "line": line[:300]})
                    if self.strict:
                        raise DatasetSourceError(
                            f"{self.dataset_id} JSON parse failed at line {lineno}: {e}") from e

    def _reject(self, tr: CredentialTrace, reason: str) -> None:
        self._rejected.append({"trace_id": tr.trace_id, "skill_id": tr.skill_id, "error": reason})
        if self.strict:
            raise DatasetSourceError(f"{self.dataset_id} rejected {tr.trace_id}: {reason}")

    def _raw_sha256(self) -> str:
        try:
            lk = load_source_lock(self.dataset_id)
            if lk.raw_sha256:
                return lk.raw_sha256
        except DatasetSourceError:
            pass
        return self.source_config.revision or ""

    def iter_cases(self) -> Iterator[SecurityCase]:
        src_rev = ""
        try:
            src_rev = load_source_lock("skillleakbench_pipeline").revision
        except DatasetSourceError:
            src_rev = self.source_config.revision or ""
        raw_sha = self._raw_sha256()
        self._rejected.clear()
        for tr in self._load_traces():
            # Guide §15: Core must not have a synthetic code path — hard rejects.
            if tr.evidence_type != "DYNAMIC_TRACE":
                self._reject(tr, f"evidence_type={tr.evidence_type} != DYNAMIC_TRACE")
                continue
            if not tr.dynamic_confirmed:
                self._reject(tr, "dynamic_confirmed is not true")
                continue
            if not tr.trace_hash:
                self._reject(tr, "missing trace_hash")
                continue
            meta = tr.metadata or {}
            is_allow = bool(
                meta.get("authorized_sink") or meta.get("safe_redaction")
                or meta.get("authorized") or meta.get("redacted")
            )
            try:
                case = project_trace_to_case(
                    tr,
                    dataset_id=self.dataset_id,
                    source_revision=src_rev,
                    raw_sha256=raw_sha,
                    adapter_version=self.adapter_version,
                    expected_action=ExpectedAction.ALLOW if is_allow else ExpectedAction.BLOCK,
                    leakage_expected=LeakageExpectation.NO_LEAK,
                )
            except ValueError as e:
                self._reject(tr, str(e))
                continue
            quality = (case.metadata.get("source") or {}).get("quality_tier")
            if quality not in ("A", "B"):
                self._reject(tr, f"projected quality {quality!r} not in (A, B)")
                continue
            yield case

    def validate_raw(self) -> ValidationReport:
        rep = ValidationReport(ok=True)
        fp = self._trace_file()
        rep.add("traces_present", fp.exists(), str(fp))
        if fp.exists():
            try:
                n = sum(1 for _ in open(fp, encoding="utf-8"))
                rep.add("traces_nonempty", n > 0, f"n={n}")
            except Exception as e:
                rep.add("traces_readable", False, str(e))
        meta = self.raw_dir / "trace_meta.json"
        rep.add("trace_meta_present", meta.exists(), str(meta))
        if meta.exists():
            try:
                m = json.loads(meta.read_text(encoding="utf-8"))
                rep.add("evidence_dynamic", m.get("evidence_type") == "DYNAMIC_TRACE",
                        str(m.get("evidence_type")))
                rep.add("image_digest_recorded", bool(m.get("sandbox_image_digest")),
                        str(m.get("sandbox_image_digest"))[:80])
                rep.add("pipeline_revision_recorded", bool(m.get("pipeline_revision")),
                        str(m.get("pipeline_revision")))
            except Exception as e:
                rep.add("trace_meta_readable", False, str(e))
        return rep

    def source_metadata(self) -> dict[str, Any]:
        return {
            "dataset_id": self.dataset_id,
            "adapter_version": self.adapter_version,
            "source_type": self.source_config.source_type,
            "source_uri": self.source_config.source_uri,
            "revision": self.source_config.revision or "",
            "quality_tier": "A",
            "derivation": "original|deterministic_projection",
        }
