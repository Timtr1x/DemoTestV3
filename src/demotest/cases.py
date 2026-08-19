"""Load cases from fixtures or legacy V2 manifests (plan §40-44, §19)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .config import load_datasets
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


def load_frozen_manifest_cases(manifest_path: str, project: str = "") -> list[SecurityCase]:
    """Resolve cases for a frozen V3 benchmark manifest (guide §38, §47).

    The manifest stores only identity (case_id / source_id / fingerprint / split).
    We load the normalized snapshots for every dataset feeding the project,
    then keep the cases whose case_id appears in the manifest — in the manifest's
    canonical order. This makes a frozen run reproduce exactly the frozen
    selection, independent of normalized-snapshot ordering.
    """
    from .cli import _dataset_pipeline as pipeline
    from .cli.manifest import _DATASETS_BY_PROJECT

    p = Path(manifest_path)
    if not p.exists():
        raise FileNotFoundError(f"manifest not found: {p}")
    manifest = json.loads(p.read_text(encoding="utf-8"))
    entries = manifest.get("cases") or []
    wanted_ids = [e["case_id"] for e in entries]
    wanted_set = set(wanted_ids)

    proj = project or manifest.get("project", "")
    datasets = load_datasets()
    by_id: dict[str, SecurityCase] = {}
    for ds_id in _DATASETS_BY_PROJECT.get(proj, []):
        ds = datasets.get(ds_id)
        if ds is None or not ds.enabled:
            continue
        try:
            for c in pipeline.load_normalized(ds):
                if c.case_id in wanted_set and c.case_id not in by_id:
                    by_id[c.case_id] = c
        except Exception:
            continue
    # preserve manifest order
    cases = [by_id[cid] for cid in wanted_ids if cid in by_id]
    missing = [cid for cid in wanted_ids if cid not in by_id]
    if missing:
        raise ValidationError(
            f"manifest references {len(missing)} unresolved cases (e.g. {missing[:3]}); "
            "run 'dataset prepare' for every feeding dataset"
        )
    return cases


def load_cases(source: str, *, project: str = "") -> list[SecurityCase]:
    """Dispatch: 'fixture:<name>' | 'legacy:<manifest>' | 'manifest:<path>'."""
    if source.startswith("fixture:"):
        return load_fixture_cases(source.split(":", 1)[1])
    if source.startswith("legacy:"):
        return load_legacy_manifest_cases(source.split(":", 1)[1], project=project)
    if source.startswith("manifest:"):
        return load_frozen_manifest_cases(source.split(":", 1)[1], project=project)
    raise ValidationError(
        f"unknown case source {source!r}; use 'fixture:<name>', 'legacy:<manifest>', "
        "or 'manifest:<path>'"
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


def validate_cases_for_project(
    cases: list[SecurityCase],
    project_id: str,
    project_channels: list[str],
) -> None:
    """Enforce Project ↔ Channel ↔ Case consistency (external review P0-1).

    A case is rejected when:
      * its channel is not in the project's declared channels, OR
      * its project_id is non-empty and disagrees with the CLI --project.

    This is checked in BOTH ``validate`` and ``run`` so a user cannot bypass it
    by skipping validate. Without this, wrong-channel data runs silently and
    the report still labels it as the requested project.
    """
    allowed = set(project_channels or [])
    errors: list[str] = []
    for c in cases:
        if c.channel.value not in allowed:
            errors.append(
                f"case {c.case_id} channel={c.channel.value!r} not in "
                f"project {project_id!r} channels {sorted(allowed)}"
            )
        if c.project_id and c.project_id != project_id:
            errors.append(
                f"case {c.case_id} project_id={c.project_id!r} != "
                f"requested project {project_id!r}"
            )
    if errors:
        raise ValidationError(
            f"project/channel mismatch ({len(errors)} cases):\n"
            + "\n".join(errors[:10])
        )
