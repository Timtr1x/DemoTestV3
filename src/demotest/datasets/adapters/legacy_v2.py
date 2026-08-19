"""LegacyV2Adapter — bridge frozen V2 manifests into SecurityCase (plan §19).

This is the most important safety rope of the refactor: it lets V3 run the
*exact same* frozen V2 data (``cache/sample_manifests/*.json``) so we can prove
the architecture upgrade does not change historical conclusions.

Mapping (plan §17):
  Sample.prompt_text   -> SecurityCase.content  (channel=USER_PROMPT, operation=CHAT)
  Sample.sample_id     -> SecurityCase.source_id
  Sample.project       -> SecurityCase.project_id
  Sample.expected      -> SecurityCase.expected_action
                         (blocked -> BLOCK, passed -> ALLOW,
                          payload_too_large -> ALLOW with a metadata flag)

V2 manifests are READ ONLY here (plan §48): the adapter never writes to
``cache/sample_manifests``.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator, Mapping

from ...core.enums import ExpectedAction
from ...core.models import SecurityCase
from ..base import DatasetAdapter
from ..registry import register_adapter

# V2 manifest store (repo root / cache / sample_manifests). Imported lazily to
# avoid a hard import cycle when the package is loaded from an odd cwd.
from ...paths import MANIFEST_DIR  # noqa: E402  (paths is a flat module)


def _v2_expected_to_action(expected: str) -> ExpectedAction:
    e = (expected or "").strip().lower()
    if e == "blocked":
        return ExpectedAction.BLOCK
    # V2 "passed" and "payload_too_large" both map to ALLOW at the action level;
    # the latter is a transport-limit test, not a security decision.
    if e in ("passed", "payload_too_large"):
        return ExpectedAction.ALLOW
    # unknown: default to ALLOW (benign) so we don't silently inflate TPR
    return ExpectedAction.ALLOW


def _presentation_style(sample: Mapping[str, Any]) -> str:
    """Derive presentation_style from V2 subset/labels where available."""
    subset = str(sample.get("subset") or "")
    src = str(sample.get("source_dataset") or "").lower()
    meta = sample.get("generator_meta") or {}
    if meta.get("presentation_style"):
        return str(meta["presentation_style"])
    # ASB / agentdojo hard packs used "stealth" markers
    if "stealth" in subset or "hard" in subset:
        return "stealth"
    if "easy" in subset:
        return "explicit"
    if "spear" in src or "human_manip" in src:
        return "structured"
    return "explicit"


def _threat_label(sample: Mapping[str, Any]) -> str:
    meta = sample.get("generator_meta") or {}
    if meta.get("threat"):
        return str(meta["threat"])
    return str(sample.get("category") or "")


@register_adapter
class LegacyV2Adapter(DatasetAdapter):
    """Read a frozen V2 manifest and yield SecurityCase objects.

    All V2 samples become ``channel=USER_PROMPT, operation=CHAT`` — that is
    precisely what V2 actually sent to LineMod (a single user message), so the
    V3 ``UserPromptRenderer`` reproduces the V2 request byte-for-byte.
    """

    dataset_id = "legacy_v2"
    adapter_version = "1.0"

    def __init__(
        self,
        manifest_name: str | None = None,
        manifest_path: Path | None = None,
        project: str = "",
    ) -> None:
        if manifest_path is None and manifest_name is None:
            raise ValueError("LegacyV2Adapter requires manifest_name or manifest_path")
        self.manifest_path = (
            manifest_path
            if manifest_path is not None
            else MANIFEST_DIR / f"{manifest_name}.json"
        )
        self.manifest_name = manifest_name or self.manifest_path.stem
        self.project = project
        self._data: dict[str, Any] | None = None

    # ------------------------------------------------------------------ load
    def _load(self) -> dict[str, Any]:
        if self._data is None:
            if not self.manifest_path.exists():
                raise FileNotFoundError(
                    f"V2 manifest not found: {self.manifest_path}"
                )
            self._data = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        return self._data

    def provenance(self) -> dict[str, str]:
        d = self._load()
        return {
            "dataset_id": self.dataset_id,
            "adapter_version": f"legacy_v2@{self.adapter_version}",
            "dataset_version": str(d.get("dataset_version") or "unknown"),
            "source_manifest": self.manifest_name,
            "manifest_path": str(self.manifest_path),
        }

    # ------------------------------------------------------------------ iter
    def iter_cases(self) -> Iterator[SecurityCase]:
        data = self._load()
        samples = data.get("samples") or []
        for s in samples:
            case = self._sample_to_case(s)
            if case is not None:
                yield case

    def _sample_to_case(self, sample: Mapping[str, Any]) -> SecurityCase:
        sample_id = str(sample.get("sample_id") or "")
        if not sample_id:
            # skip malformed rows defensively rather than crash a whole run
            return None  # type: ignore[return-value]
        expected_action = _v2_expected_to_action(str(sample.get("expected") or ""))
        meta = dict(sample.get("generator_meta") or {})
        labels = {
            "label": str(sample.get("label") or ""),
            "subset": str(sample.get("subset") or ""),
            "category": str(sample.get("category") or ""),
            "source_dataset": str(sample.get("source_dataset") or ""),
        }
        metadata: dict[str, Any] = {
            "v2_sample_id": sample_id,
            "v2_expected": str(sample.get("expected") or ""),
            "v2_subset": str(sample.get("subset") or ""),
            "v2_category": str(sample.get("category") or ""),
            "is_payload_too_large_test": str(sample.get("expected") or "")
            == "payload_too_large",
        }
        if meta.get("canary_token"):
            metadata["canary_token"] = str(meta["canary_token"])
        case = SecurityCase.build(
            dataset_id=self.dataset_id,
            source_id=sample_id,
            channel="user_prompt",
            operation="chat",
            content=str(sample.get("prompt_text") or ""),
            expected_action=expected_action,
            project_id=self.project or str(sample.get("project") or ""),
            threat_id=_threat_label(sample),
            presentation_style=_presentation_style(sample),
            labels=labels,
            metadata=metadata,
        )
        return case

    @staticmethod
    def list_available(manifest_dir: Path | None = None) -> list[str]:
        d = manifest_dir or MANIFEST_DIR
        return sorted(p.stem for p in d.glob("*.json"))
