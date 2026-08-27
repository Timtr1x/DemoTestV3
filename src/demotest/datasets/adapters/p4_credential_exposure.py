"""P4 Extended credential exposure adapter — seed-derived (Phase 10).

Maps one manifest row -> SecurityCase.

  channel = tool_result
  content = row.content
  expected_action = block/allow
  credential_markers = [marker] / []
  project_id = P4_credential_flow

No dynamic execution. Strict file presence for committed frozen path.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterator

from ...config import DatasetSourceConfig, get_dataset
from ...core.enums import Channel, ExpectedAction, LeakageExpectation, Operation
from ...core.exceptions import DatasetSourceError
from ...core.models import SecurityCase
from ..base import DatasetAdapter, ValidationReport
from ..quality import SourceProvenance, attach_provenance
from ..registry import register_adapter

FROZEN_MANIFEST = "benchmarks/frozen/datasets/p4_credential_exposure/manifest.jsonl"
LOCAL_MANIFEST = "data/p4_extended/manifest.jsonl"


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _resolve_manifest_path(raw_dir: Path | None, fallback_raw: Path | None) -> Path:
    # raw_dir is the adapter's raw_path; prefer frozen, fall back to local data/
    candidates: list[Path] = []
    if raw_dir is not None:
        candidates.append(Path(raw_dir) / "manifest.jsonl")
        candidates.append(Path(raw_dir))
    # repo-root-relative frozen + local
    from ...paths import REPO_ROOT
    candidates.append(REPO_ROOT / FROZEN_MANIFEST)
    candidates.append(REPO_ROOT / LOCAL_MANIFEST)
    if fallback_raw is not None:
        candidates.append(Path(fallback_raw))
    for p in candidates:
        if p.exists() and p.is_file():
            return p
        # if candidate is a dir containing manifest.jsonl
        if p.exists() and p.is_dir() and (p / "manifest.jsonl").exists():
            return p / "manifest.jsonl"
    # Return preferred (frozen) for error message
    return candidates[0] if candidates else Path(FROZEN_MANIFEST)


@register_adapter
class P4CredentialExposureAdapter(DatasetAdapter):
    dataset_id = "p4_credential_exposure"
    adapter_version = "1.0.0"

    def __init__(
        self,
        *,
        raw_dir: Path | str | None = None,
        source_config: DatasetSourceConfig | None = None,
        manifest_path: Path | str | None = None,
    ) -> None:
        if source_config is None:
            try:
                source_config = get_dataset(self.dataset_id)
            except Exception:
                # Until datasets.yaml is fully wired, synthesize a minimal config
                from ...config import DatasetSourceConfig as DSC
                source_config = DSC(
                    name=self.dataset_id,
                    adapter=self.dataset_id,
                    adapter_version=self.adapter_version,
                    source_type="local",
                    source_uri="data/p4_extended/manifest.jsonl",
                    revision="seeds-20260827-v1",
                    license="MIT",
                    raw_dir="benchmarks/frozen/datasets/p4_credential_exposure",
                    normalized_dir="cache/datasets_v3/normalized/p4_credential_exposure",
                )
        self.source_config = source_config
        if manifest_path is not None:
            self._manifest_path = Path(manifest_path)
        else:
            # Prefer explicit raw_dir, else frozen, else local
            rd = Path(raw_dir) if raw_dir is not None else None
            self._manifest_path = _resolve_manifest_path(rd, None)
        # Keep raw_dir for validation/source_metadata
        if raw_dir is not None:
            self.raw_dir = Path(raw_dir)
        else:
            try:
                self.raw_dir = Path(source_config.raw_path)  # type: ignore[attr-defined]
            except Exception:
                from ...paths import REPO_ROOT
                self.raw_dir = REPO_ROOT / "benchmarks" / "frozen" / "datasets" / self.dataset_id

    def _load_rows(self) -> Iterator[dict[str, Any]]:
        p = self._manifest_path
        if not p.exists():
            raise DatasetSourceError(
                f"p4_credential_exposure manifest not found: {p}. "
                f"Run: python scripts/p4_build_extended.py && python scripts/p4_freeze_extended.py"
            )
        with p.open("r", encoding="utf-8") as f:
            for lineno, raw in enumerate(f, 1):
                line = raw.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except Exception as e:
                    raise DatasetSourceError(f"manifest JSON parse failed at line {lineno}: {e}") from e

    def iter_cases(self) -> Iterator[SecurityCase]:
        src_rev = str(getattr(self.source_config, "revision", "") or "seeds-20260827-v1")
        # manifest raw sha for provenance parent
        manifest_sha = ""
        try:
            manifest_sha = hashlib.sha256(self._manifest_path.read_bytes()).hexdigest() if self._manifest_path.exists() else src_rev
        except Exception:
            manifest_sha = src_rev
        for row in self._load_rows():
            content = str(row.get("content") or "")
            subtype = str(row.get("subtype") or "")
            expected = str(row.get("expected_action") or "block").lower()
            ea = ExpectedAction.BLOCK if expected == "block" else ExpectedAction.ALLOW
            marker = str(row.get("credential_marker") or "")
            markers = [marker] if marker else []
            source_id = str(row.get("source_id") or row.get("case_id") or "")
            # Frozen case_id is the manifest's row case_id (stable, e.g. case-p4e-...)
            # SecurityCase.build would re-derive from dataset_id/source_id/channel/operation
            # which would give case-... and mismatch load_frozen_manifest_cases.
            # So we pass the frozen case_id directly.
            frozen_case_id = str(row.get("case_id") or "")
            seed_id = str(row.get("seed_id") or "")
            group_id = str(row.get("group_id") or f"p4_extended:seed:{seed_id}")
            secret_kind = str(row.get("secret_kind") or "")
            presentation_style = str(row.get("presentation_style") or "structured")
            # content must be non-empty per SecurityCase; validator already checked
            case = SecurityCase(
                case_id=frozen_case_id,
                dataset_id=self.dataset_id,
                source_id=source_id,
                channel=Channel.TOOL_RESULT,
                operation=Operation.READ,
                content=content,
                expected_action=ea,
                project_id="P4_credential_flow",
                threat_id="credential_exposure",
                presentation_style=presentation_style,
                credential_markers=markers,
                leakage_expected=LeakageExpectation.NO_LEAK,
                labels={"p4_subtype": subtype, "seed_id": seed_id},
                metadata={
                    "p4_subtype": subtype,
                    "seed_id": seed_id,
                    "secret_kind": secret_kind,
                    "group_id": group_id,
                    "source_case_id": source_id,
                },
            )
            prov = SourceProvenance(
                source_dataset="p4_extended",
                source_revision=src_rev,
                source_id=source_id,
                group_id=group_id,
                raw_sha256=_sha256_text(content),
                normalized_sha256=_sha256_text(content),
                adapter_name="p4_credential_exposure",
                adapter_version=self.adapter_version,
                quality_tier="C",
                derivation="catalog_derived",
                parent_source_id=source_id,
            )
            # Attach extra metadata via from_dict so we keep group_id in metadata too
            d = case.to_dict()
            # Ensure metadata carries group_id for sampler
            meta = dict(d.get("metadata") or {})
            meta.setdefault("group_id", group_id)
            meta.setdefault("p4_subtype", subtype)
            meta.setdefault("secret_kind", secret_kind)
            meta.setdefault("seed_id", seed_id)
            meta.setdefault("manifest_sha256", manifest_sha)
            d["metadata"] = meta
            case = SecurityCase.from_dict(d)
            case = attach_provenance(case, prov)
            yield case

    def validate_raw(self) -> ValidationReport:
        rep = ValidationReport(ok=True)
        p = self._manifest_path
        rep.add("manifest_present", p.exists(), str(p))
        if p.exists():
            try:
                n = sum(1 for _ in open(p, encoding="utf-8") if _.strip())
                rep.add("manifest_nonempty", n > 0, f"n={n}")
                rep.add("manifest_is_800", n == 800, f"n={n} expected 800")
            except Exception as e:
                rep.add("manifest_readable", False, str(e))
        return rep

    def source_metadata(self) -> dict[str, Any]:
        return {
            "dataset_id": self.dataset_id,
            "adapter_version": self.adapter_version,
            "source_type": getattr(self.source_config, "source_type", "local"),
            "source_uri": getattr(self.source_config, "source_uri", "data/p4_extended/manifest.jsonl"),
            "revision": getattr(self.source_config, "revision", "seeds-20260827-v1"),
            "manifest": str(self._manifest_path),
            "quality_tier": "C",
            "derivation": "catalog_derived",
        }
