"""Shared benchmark context resolver — single source of truth for track/headline.

All CLIs (run / analyze / report / compare) must use this resolver so the
same P4_credential_flow extended manifest cannot be displayed as core.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..core.exceptions import ConfigError, ManifestError
from .manifest_builder import load_manifest, manifest_sha256, validate_benchmark_track, verify_manifest


@dataclass(frozen=True)
class BenchmarkContext:
    source: str
    manifest_path: str | None  # None for fixture:/legacy: sources
    manifest_sha256: str | None
    benchmark_track: str  # core | extended
    headline_eligible: bool
    manifest: dict[str, Any] | None  # loaded manifest dict if available


def resolve_benchmark_context(source: str, *, project: str = "") -> BenchmarkContext:
    """Resolve track/headline from the actual manifest, fail-closed on invalid.

    Rules:
      - manifest: source -> load + verify + validate_benchmark_track; any error -> raise
      - missing track/headline fields -> legacy core compat (Phase 1 frozen)
      - invalid track value (present but not core/extended) -> ConfigError/ManifestError
      - extended + headline_eligible=true -> ConfigError
      - fixture:/legacy: sources -> best-effort from suites.yaml, default core
    """
    if isinstance(source, str) and source.startswith("manifest:"):
        mpath = source.split(":", 1)[1]
        p = Path(mpath)
        if not p.exists():
            raise ManifestError(f"manifest not found for --source: {mpath}")
        manifest = load_manifest(str(p))
        # verify SHA + track invariants before trusting fields
        problems = verify_manifest(manifest)
        if problems:
            raise ManifestError(f"manifest verify failed for {mpath}: {'; '.join(problems)}")
        bt_raw = manifest.get("benchmark_track")
        he_raw = manifest.get("headline_eligible")
        if bt_raw is None and he_raw is None:
            # legacy Phase 1 frozen — treat as core
            return BenchmarkContext(
                source=source,
                manifest_path=str(p),
                manifest_sha256=manifest.get("manifest_sha256"),
                benchmark_track="core",
                headline_eligible=True,
                manifest=manifest,
            )
        # present -> must be valid; distinguish MISSING vs INVALID
        bt = str(bt_raw).strip().lower() if bt_raw is not None else "core"
        he = bool(he_raw) if he_raw is not None else (bt == "core")
        # validate_benchmark_track is fail-closed
        validate_benchmark_track(bt, he)
        return BenchmarkContext(
            source=source,
            manifest_path=str(p),
            manifest_sha256=manifest.get("manifest_sha256"),
            benchmark_track=bt,
            headline_eligible=he,
            manifest=manifest,
        )
    # fixture:/legacy: — best-effort from suites.yaml
    track = "core"
    eligible = True
    manifest_path: str | None = None
    manifest_sha: str | None = None
    manifest_dict: dict[str, Any] | None = None
    try:
        from ..config import load_suites
        for suite in load_suites().values():
            if project and project in suite.projects:
                pt = suite.projects[project]
                mp = Path(pt.manifest)
                if mp.exists():
                    m = load_manifest(str(mp))
                    # use manifest's own track if present, else suite's track
                    bt_raw = m.get("benchmark_track")
                    if bt_raw is not None:
                        track = str(bt_raw).strip().lower() or "core"
                        eligible = bool(m.get("headline_eligible", track == "core"))
                    else:
                        track = pt.track
                        eligible = pt.headline_eligible
                    manifest_path = str(mp)
                    manifest_sha = m.get("manifest_sha256")
                    manifest_dict = m
                    break
    except Exception:
        pass
    return BenchmarkContext(
        source=source,
        manifest_path=manifest_path,
        manifest_sha256=manifest_sha,
        benchmark_track=track,
        headline_eligible=eligible,
        manifest=manifest_dict,
    )


def verify_run_meta(
    base: Path,
    ctx: BenchmarkContext,
    *,
    expected_project: str,
    expected_target: str,
    expected_run_version: str,
    allow_legacy: bool = False,
) -> dict[str, Any]:
    """Mandatory provenance check for manifest-sourced runs (fail-closed).

    - _run_meta.json must exist, parse, and carry manifest_sha256.
    - SHA must match the --source manifest, project/target/run_version must match.
    - allow_legacy permits old runs without meta (explicit opt-out) — but if the
      file exists and fails SHA/identity checks we still fail hard even with
      allow_legacy, because that is corruption, not legacy.
    """
    meta_path = base / "_run_meta.json"
    if not meta_path.exists():
        if allow_legacy:
            return {}
        raise ManifestError(f"missing _run_meta.json at {meta_path} for manifest-sourced run")
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except Exception as e:
        raise ManifestError(f"corrupt _run_meta.json at {meta_path}: {e}")
    sha = meta.get("manifest_sha256")
    if not sha:
        raise ManifestError(f"_run_meta.json missing manifest_sha256")
    if ctx.manifest_sha256 and sha != ctx.manifest_sha256:
        raise ManifestError(f"manifest SHA mismatch: run meta {sha} != --source {ctx.manifest_sha256}")
    for key, expected in (("project", expected_project), ("target", expected_target), ("run_version", expected_run_version)):
        got = meta.get(key)
        if got != expected:
            raise ManifestError(f"_run_meta.json {key}={got!r} != expected {expected!r}")
    return meta
