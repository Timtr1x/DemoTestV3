"""Credential catalog synthetic adapter — catalog-derived Extended.

This is the downgraded synthetic dataset (review P0-1..P0-6). It must NOT be
counted as P4 Core (Core requires DYNAMIC_TRACE, quality A/B).

Source dir: cache/datasets_v3/raw/credential_catalog_synthetic/
Output:     cache/datasets_v3/normalized/credential_catalog_synthetic/
Manifests:  phase2-* / p4-* (never mutates phase1-* frozen suites).

Strict mode: every trace rejection is recorded; prepare fails fast if any
trace is rejected (no silent shadowing).
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
class CredentialCatalogSyntheticAdapter(DatasetAdapter):
    dataset_id = "credential_catalog_synthetic"
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

    def _raw_sha256(self) -> str:
        # Authoritative: the lock's raw_sha256 (snapshot hash of the file bytes,
        # per review P0-8). Do not hash trace_ids.
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
            src_rev = load_source_lock("skillleakbench").revision
        except DatasetSourceError:
            src_rev = self.source_config.revision or ""
        raw_sha = self._raw_sha256()
        self._rejected.clear()
        for tr in self._load_traces():
            meta = tr.metadata or {}
            if bool(meta.get("authorized_sink") or meta.get("safe_redaction") or meta.get("authorized") or meta.get("redacted")):
                ea = ExpectedAction.ALLOW
                le = LeakageExpectation.NO_LEAK
            else:
                ea = ExpectedAction.BLOCK
                le = LeakageExpectation.NO_LEAK
            try:
                yield project_trace_to_case(
                    tr,
                    dataset_id=self.dataset_id,
                    source_revision=src_rev,
                    raw_sha256=raw_sha,
                    adapter_version=self.adapter_version,
                    expected_action=ea,
                    leakage_expected=le,
                )
            except ValueError as e:
                rec = {"trace_id": tr.trace_id, "skill_id": tr.skill_id, "issue_id": tr.issue_id, "error": str(e)}
                self._rejected.append(rec)
                if self.strict:
                    raise DatasetSourceError(f"credential_catalog_synthetic rejected {tr.trace_id}: {e}") from e
                continue
        if self._rejected and self.strict and any("lineno" in r for r in self._rejected):
            # JSON parse rejections
            raise DatasetSourceError(f"credential_catalog_synthetic had {len(self._rejected)} parse rejections")

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
        return rep

    def source_metadata(self) -> dict[str, Any]:
        return {
            "dataset_id": self.dataset_id,
            "adapter_version": self.adapter_version,
            "source_type": self.source_config.source_type,
            "source_uri": self.source_config.source_uri,
            "revision": self.source_config.revision or "",
            "quality_tier": "C",
            "derivation": "catalog_derived",
        }
