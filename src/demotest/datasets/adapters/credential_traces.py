"""CredentialTraces adapter shim — delegates to catalog synthetic (Extended).

The legacy dataset_id ``credential_traces`` (quality B) is kept for compat
but now transparently delegates to ``credential_catalog_synthetic`` (quality C,
CATALOG_DERIVED). Any code still requesting ``credential_traces`` will resolve
to the synthetic store. Core DYNAMIC_TRACE will later re-introduce a separate
real-trace adapter under a new dataset_id.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Iterator

from ...config import DatasetSourceConfig, get_dataset
from ...core.models import SecurityCase
from ..base import DatasetAdapter, ValidationReport
from ..registry import register_adapter
from .credential_catalog_synthetic import CredentialCatalogSyntheticAdapter


@register_adapter
class CredentialTracesAdapter(DatasetAdapter):
    dataset_id = "credential_traces"
    adapter_version = "1.0.0"

    def __init__(self, *, raw_dir: Path | str | None = None, source_config: DatasetSourceConfig | None = None, trace_provider: Any | None = None) -> None:
        if source_config is None:
            source_config = get_dataset(self.dataset_id)
        self.source_config = source_config
        # redirect to the synthetic raw dir
        try:
            syn_cfg = get_dataset("credential_catalog_synthetic")
            syn_raw = syn_cfg.raw_path
        except Exception:
            syn_raw = source_config.raw_path
        self._inner = CredentialCatalogSyntheticAdapter(
            raw_dir=syn_raw if syn_raw.exists() else raw_dir,
            trace_provider=trace_provider,
        )

    def iter_cases(self) -> Iterator[SecurityCase]:
        yield from self._inner.iter_cases()

    def validate_raw(self) -> ValidationReport:
        return self._inner.validate_raw()

    def source_metadata(self) -> dict[str, Any]:
        m = self._inner.source_metadata()
        m["dataset_id"] = self.dataset_id
        return m
