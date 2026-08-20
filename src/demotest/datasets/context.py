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
    benchmark_track: str  # core | extended | adhoc (fixture/legacy)
    headline_eligible: bool
    manifest: dict[str, Any] | None  # loaded manifest dict if available


def resolve_benchmark_context(source: str, *, project: str = "") -> BenchmarkContext:
    """Resolve track/headline from the actual manifest, fail-closed on invalid.

    Rules:
      - manifest: source -> load + verify + validate_benchmark_track; any error -> raise
      - missing track/headline fields -> legacy core compat (Phase 1 frozen)
      - invalid track value (present but not core/extended) -> ConfigError/ManifestError
      - extended + headline_eligible=true -> ConfigError
      - fixture:/legacy: sources -> adhoc, no frozen manifest identity (never headline)
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
    # fixture:/legacy: — no frozen benchmark identity; adhoc (never headline)
    return BenchmarkContext(
        source=source,
        manifest_path=None,
        manifest_sha256=None,
        benchmark_track="adhoc",
        headline_eligible=False,
        manifest=None,
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


def run_preflight_check(
    base: Path,
    ctx: BenchmarkContext,
    *,
    project: str,
    target: str,
    run_version: str,
    experiment_hash: str,
    fidelity_blob: str,
    allow_legacy_adopt: bool = False,
) -> None:
    """Run-start preflight: prevent resume from a different experiment.

    - If directory doesn't exist -> normal run, meta will be written.
    - If meta exists -> experiment_hash + manifest_sha + identity must match,
      even when no results exist yet (a prior dry-run already fixed the dir's identity).
    - If results exist but no meta -> fail (unknown provenance); allow_legacy_adopt opt-in.
    """
    meta_path = base / "_run_meta.json"
    if not base.exists():
        return  # fresh run
    if not meta_path.exists():
        if not any(base.glob("*.jsonl")) or allow_legacy_adopt:
            return  # no results yet, or explicit legacy adoption
        raise ManifestError(
            f"run directory {base} has existing results but no _run_meta.json; "
            "cannot prove provenance. Use --adopt-legacy-run to resume anyway."
        )
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except Exception as e:
        raise ManifestError(f"corrupt _run_meta.json at {meta_path}: {e}")
    # manifest SHA (if manifest-sourced)
    if ctx.manifest_sha256 and meta.get("manifest_sha256") != ctx.manifest_sha256:
        raise ManifestError(
            f"existing run manifest_sha256 {meta.get('manifest_sha256')} != current {ctx.manifest_sha256}"
        )
    # experiment hash covers dataset/project/target/fidelity — different config => different experiment
    if meta.get("experiment_hash") and meta.get("experiment_hash") != experiment_hash:
        raise ManifestError(
            f"existing run experiment_hash {meta.get('experiment_hash')} != current {experiment_hash}"
        )
    for key, expected in (("project", project), ("target", target), ("run_version", run_version)):
        if meta.get(key) != expected:
            raise ManifestError(f"existing run {key}={meta.get(key)!r} != current {expected!r}")
