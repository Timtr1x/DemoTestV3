"""CredentialTraceAdapter — CredentialTrace -> SecurityCase (guide §25-§28).

Strictly one job (guide §25):

  CredentialTrace (built offline from the real catalog)
  -> SecurityCase

It does NOT: crawl SkillsMP, run Docker, scan source, or call an LLM.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterator

from ...config import DatasetSourceConfig, get_dataset
from ...core.enums import ExpectedAction, LeakageExpectation
from ...core.models import SecurityCase
from ..base import DatasetAdapter, ValidationReport
from ..registry import register_adapter
from ..source_lock import load_source_lock
from ...core.exceptions import DatasetSourceError
from ..traces.models import CredentialTrace
from ..traces.projection import project_trace_to_case


@register_adapter
class CredentialTracesAdapter(DatasetAdapter):
    dataset_id = "credential_traces"
    adapter_version = "1.0.0"

    def __init__(
        self,
        *,
        raw_dir: Path | str | None = None,
        source_config: DatasetSourceConfig | None = None,
        trace_provider: Any | None = None,
    ) -> None:
        if source_config is None:
            source_config = get_dataset(self.dataset_id)
        self.source_config = source_config
        self.raw_dir = Path(raw_dir) if raw_dir else source_config.raw_path
        # Injected traces for tests.
        self._trace_provider = trace_provider

    # ------------------------------------------------------------------ trace IO
    def _trace_file(self) -> Path:
        # Preferred: raw/credential_traces/traces.jsonl (builder output)
        p = self.raw_dir / "traces.jsonl"
        if p.exists():
            return p
        # Back-compat: raw/traces.jsonl
        return self.raw_dir / "traces.jsonl"

    def _load_traces(self) -> Iterator[CredentialTrace]:
        if self._trace_provider is not None:
            yield from self._trace_provider
            return
        fp = self._trace_file()
        if not fp.exists():
            return
        with fp.open("r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except Exception:
                    continue
                yield CredentialTrace.from_dict(d)

    def _raw_sha256(self) -> str:
        # Chain to the catalog lock + trace hash (reproducible derived dataset).
        # The builder writes trace_meta.json with trace_hash.
        meta_fp = self.raw_dir / "trace_meta.json"
        if meta_fp.exists():
            try:
                meta = json.loads(meta_fp.read_text(encoding="utf-8"))
                th = str(meta.get("trace_hash") or "")
                if th:
                    return hashlib.sha256(th.encode("utf-8")).hexdigest()[:16]
            except Exception:
                pass
        return self.source_config.revision or ""

    # ------------------------------------------------------------------ cases
    def iter_cases(self) -> Iterator[SecurityCase]:
        src_rev = ""
        try:
            src_rev = load_source_lock("skillleakbench").revision
        except DatasetSourceError:
            src_rev = self.source_config.revision or ""
        raw_sha = self._raw_sha256()
        for tr in self._load_traces():
            # ALLOW benign vs BLOCK unsafe — derived from trace metadata.
            meta = tr.metadata or {}
            if bool(meta.get("authorized_sink") or meta.get("safe_redaction") or meta.get("authorized") or meta.get("redacted")):
                ea = ExpectedAction.ALLOW
                # Canary must NOT echo even for benign flows.
                le = LeakageExpectation.NO_LEAK
            else:
                ea = ExpectedAction.BLOCK
                le = LeakageExpectation.NO_LEAK
            try:
                case = project_trace_to_case(
                    tr,
                    dataset_id=self.dataset_id,
                    source_revision=src_rev,
                    raw_sha256=raw_sha,
                    adapter_version=self.adapter_version,
                    expected_action=ea,
                    leakage_expected=le,
                )
            except ValueError:
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
                rep.add("traces_scale", n >= 800, f"n={n} expect >=800 core")
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
            "quality_tier": "B",
            "derivation": "deterministic_projection",
        }
