"""Load cases from fixtures or legacy V2 manifests (plan §40-44, §19)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .core.exceptions import ValidationError
from .core.models import SecurityCase
from .datasets.adapters.legacy_v2 import LegacyV2Adapter
from .paths import FIXTURES_DIR, MANIFEST_DIR


def load_fixture_cases(name: str) -> list[SecurityCase]:
    """Load a JSON fixture of SecurityCase dicts from tests/fixtures."""
    p = FIXTURES_DIR / f"{name}.json"
    if not p.exists():
        raise FileNotFoundError(f"fixture not found: {p}")
    data = json.loads(p.read_text(encoding="utf-8"))
    cases_raw = data.get("cases") or []
    return [SecurityCase.from_dict(c) for c in cases_raw]


def load_legacy_manifest_cases(manifest_name: str, project: str = "") -> list[SecurityCase]:
    """Load cases from a frozen V2 manifest via LegacyV2Adapter."""
    ad = LegacyV2Adapter(manifest_name=manifest_name, project=project)
    return ad.cases()


def load_cases(source: str, *, project: str = "") -> list[SecurityCase]:
    """Dispatch: 'fixture:<name>' or 'legacy:<manifest_name>'."""
    if source.startswith("fixture:"):
        return load_fixture_cases(source.split(":", 1)[1])
    if source.startswith("legacy:"):
        return load_legacy_manifest_cases(source.split(":", 1)[1], project=project)
    raise ValidationError(
        f"unknown case source {source!r}; use 'fixture:<name>' or 'legacy:<manifest>'"
    )


def validate_case_ids_unique(cases: list[SecurityCase]) -> None:
    seen: dict[str, int] = {}
    dupes: list[str] = []
    for c in cases:
        seen[c.case_id] = seen.get(c.case_id, 0) + 1
        if seen[c.case_id] == 2:
            dupes.append(c.case_id)
    if dupes:
        raise ValidationError(f"duplicate case_ids: {dupes[:10]}")
