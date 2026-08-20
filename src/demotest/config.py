"""Config loading for V3 (plan §36, §37).

V3 config lives under ``config/v3/`` to stay separate from V2's ``config/``.
Project configs map P1-P5 to channels + renderers + oracle + metrics.
Target configs define transport (url/key/model/headers/no-failover).

Dataset Integration (Phase 1) adds three more config files:
  * ``datasets.yaml``  — registry of pinned external sources
  * ``datasets/<id>.yaml`` — per-dataset adapter mapping + dedup/stratification
  * ``suites.yaml``    — frozen benchmark suites (smoke/standard/full)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .core.exceptions import ConfigError, ValidationError
from .paths import CONFIG_DIR, V3_CONFIG_DIR

V3_CONFIG_DIR = CONFIG_DIR / "v3"
DATASETS_CONFIG_DIR = V3_CONFIG_DIR / "datasets"


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


@dataclass
class TargetConfig:
    name: str
    type: str = "gateway"
    url_env: str = "LINEMOD_URL"
    key_env: str = "LINEMOD_API_KEY"
    model_env: str = "LINEMOD_MODEL"
    timeout: float = 60.0
    benchmark_mode: bool = True
    headers: dict[str, str] = field(default_factory=dict)
    request: dict[str, Any] = field(default_factory=dict)
    classification: dict[str, Any] = field(default_factory=dict)

    def generation_profile(self) -> dict[str, Any]:
        """The request generation params (temperature / max_tokens) for this target.

        F11: V2 regression keeps ``max_tokens=8``; P4 credential/outbound cases
        need a larger budget (e.g. 128) so a leak is not silently truncated by
        the token cap rather than blocked by the gateway.
        """
        req = self.request or {}
        return {
            "temperature": float(req.get("temperature", 0.0)),
            "max_tokens": int(req.get("max_tokens", 8)),
        }


@dataclass
class ProjectConfig:
    project_id: str
    name: str = ""
    channels: list[str] = field(default_factory=list)
    renderer: dict[str, str] = field(default_factory=dict)
    oracle: str = "block_pass"
    metrics: list[str] = field(default_factory=list)
    thresholds: dict[str, Any] = field(default_factory=dict)
    caveats: list[str] = field(default_factory=list)
    manifests: list[dict[str, Any]] = field(default_factory=list)
    # F11: per-project generation override (wins over target default).
    generation: dict[str, Any] = field(default_factory=dict)
    # P0-3: per-channel primary fidelity — which tier is the headline number.
    primary_fidelity: dict[str, str] = field(default_factory=dict)

    def generation_profile(self, target: TargetConfig | None = None) -> dict[str, Any]:
        base = target.generation_profile() if target else {
            "temperature": 0.0, "max_tokens": 8,
        }
        if self.generation:
            g = self.generation
            if "temperature" in g:
                base["temperature"] = float(g["temperature"])
            if "max_tokens" in g:
                base["max_tokens"] = int(g["max_tokens"])
        return base


def load_targets(path: Path | None = None) -> dict[str, TargetConfig]:
    p = path or (V3_CONFIG_DIR / "targets.yaml")
    data = _load_yaml(p)
    targets: dict[str, TargetConfig] = {}
    for name, cfg in (data.get("targets") or {}).items():
        cfg = dict(cfg or {})
        targets[name] = TargetConfig(
            name=name,
            type=cfg.get("type", "gateway"),
            url_env=cfg.get("url_env", "LINEMOD_URL"),
            key_env=cfg.get("key_env", "LINEMOD_API_KEY"),
            model_env=cfg.get("model_env", "LINEMOD_MODEL"),
            timeout=float(cfg.get("timeout", 60.0)),
            benchmark_mode=bool(cfg.get("benchmark_mode", True)),
            headers=dict(cfg.get("headers") or {}),
            request=dict(cfg.get("request") or {}),
            classification=dict(cfg.get("classification") or {}),
        )
    return targets


def load_projects(path: Path | None = None) -> dict[str, ProjectConfig]:
    p = path or (V3_CONFIG_DIR / "projects.yaml")
    data = _load_yaml(p)
    projects: dict[str, ProjectConfig] = {}
    for pid, cfg in (data.get("projects") or {}).items():
        cfg = dict(cfg or {})
        projects[pid] = ProjectConfig(
            project_id=pid,
            name=str(cfg.get("name", pid)),
            channels=list(cfg.get("channels") or []),
            renderer=dict(cfg.get("renderer") or {}),
            oracle=str(cfg.get("oracle", "block_pass")),
            metrics=list(cfg.get("metrics") or []),
            thresholds=dict(cfg.get("thresholds") or {}),
            caveats=list(cfg.get("caveats") or []),
            manifests=list(cfg.get("manifests") or []),
            generation=dict(cfg.get("generation") or {}),
            primary_fidelity=dict(cfg.get("primary_fidelity") or {}),
        )
    return projects


def get_project(project_id: str, path: Path | None = None) -> ProjectConfig:
    projects = load_projects(path)
    if project_id not in projects:
        raise ConfigError(f"unknown project {project_id!r}; known: {sorted(projects)}")
    return projects[project_id]


def get_target(name: str, path: Path | None = None) -> TargetConfig:
    targets = load_targets(path)
    if name not in targets:
        raise ConfigError(f"unknown target {name!r}; known: {sorted(targets)}")
    return targets[name]


# ===========================================================================
# Dataset Integration (Phase 1) — datasets.yaml + suites.yaml + per-dataset
# ===========================================================================
@dataclass
class DatasetSourceConfig:
    """One pinned external source (datasets.yaml)."""

    name: str
    adapter: str
    adapter_version: str = "1.0.0"
    enabled: bool = True
    quality_tier: str = "A"
    source_type: str = ""  # huggingface_dataset | github
    source_uri: str = ""  # repo_id or owner/repo
    revision: str = ""
    license: str | None = None
    benchmark_version: str | None = None  # agentdojo
    allow_patterns: list[str] = field(default_factory=list)  # HF snapshot_download
    hash_globs: list[str] = field(default_factory=list)  # git clone snapshot hash scope
    raw_dir: str = ""
    normalized_dir: str = ""

    @property
    def raw_path(self) -> Path:
        from .paths import REPO_ROOT
        return REPO_ROOT / self.raw_dir if self.raw_dir else REPO_ROOT / "cache" / "datasets_v3" / "raw" / self.name

    @property
    def normalized_path(self) -> Path:
        from .paths import REPO_ROOT
        return (
            REPO_ROOT / self.normalized_dir
            if self.normalized_dir
            else REPO_ROOT / "cache" / "datasets_v3" / "normalized" / self.name
        )


@dataclass
class DatasetProjectionConfig:
    """Per-dataset adapter mapping + dedup + stratification (datasets/<id>.yaml)."""

    dataset_id: str
    benchmark_version: str | None = None
    suites: list[str] = field(default_factory=list)
    files: dict[str, list[str]] = field(default_factory=dict)
    projection: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    dedup: dict[str, Any] = field(default_factory=dict)
    stratification: dict[str, Any] = field(default_factory=dict)
    split_group: dict[str, Any] = field(default_factory=dict)
    suite_targets: dict[str, dict[str, int]] = field(default_factory=dict)
    runtime: dict[str, Any] = field(default_factory=dict)


def load_datasets(path: Path | None = None) -> dict[str, DatasetSourceConfig]:
    p = path or (V3_CONFIG_DIR / "datasets.yaml")
    data = _load_yaml(p)
    out: dict[str, DatasetSourceConfig] = {}
    for name, cfg in (data.get("datasets") or {}).items():
        cfg = dict(cfg or {})
        src = dict(cfg.get("source") or {})
        stype = str(src.get("type", ""))
        out[name] = DatasetSourceConfig(
            name=name,
            adapter=str(cfg.get("adapter", name)),
            adapter_version=str(cfg.get("adapter_version", "1.0.0")),
            enabled=bool(cfg.get("enabled", True)),
            quality_tier=str(cfg.get("quality_tier", "A")),
            source_type=stype,
            source_uri=str(src.get("repo_id") or src.get("repository") or ""),
            revision=str(src.get("revision") or ""),
            license=src.get("license"),
            benchmark_version=src.get("benchmark_version"),
            allow_patterns=list(src.get("allow_patterns") or []),
            hash_globs=list(src.get("hash_globs") or []),
            raw_dir=str(cfg.get("raw_dir") or ""),
            normalized_dir=str(cfg.get("normalized_dir") or ""),
        )
    return out


def get_dataset(name: str, path: Path | None = None) -> DatasetSourceConfig:
    ds = load_datasets(path)
    if name not in ds:
        raise ConfigError(f"unknown dataset {name!r}; known: {sorted(ds)}")
    return ds[name]


def load_dataset_projection(dataset_id: str, path: Path | None = None) -> DatasetProjectionConfig:
    """Load the per-dataset adapter mapping YAML."""
    p = path or (DATASETS_CONFIG_DIR / f"{dataset_id}.yaml")
    data = _load_yaml(p)
    if not data:
        raise ConfigError(f"dataset projection config not found: {p}")
    return DatasetProjectionConfig(
        dataset_id=str(data.get("dataset_id") or dataset_id),
        benchmark_version=data.get("benchmark_version"),
        suites=list(data.get("suites") or []),
        files=dict(data.get("files") or {}),
        projection=dict(data.get("projection") or {}),
        metadata=dict(data.get("metadata") or {}),
        dedup=dict(data.get("dedup") or {}),
        stratification=dict(data.get("stratification") or {}),
        split_group=dict(data.get("split_group") or {}),
        suite_targets=dict(data.get("suite_targets") or {}),
        runtime=dict(data.get("runtime") or {}),
    )


@dataclass
class SuiteProjectTarget:
    project: str
    manifest: str  # repo-relative path to frozen manifest
    target: int = 0
    strata: list[dict] = field(default_factory=list)
    max_cluster_share: float | None = None
    # Phase 2.1: hard isolation CORE vs EXTENDED (review P0 — Synthetic must not be headline)
    track: str = "core"  # core | extended
    headline_eligible: bool = True


@dataclass
class SuiteConfig:
    suite_id: str
    seed: int = 42
    split: list[str] = field(default_factory=list)  # ["eval"] or ["eval","holdout"]
    split_version: str = "split-v1"
    projects: dict[str, SuiteProjectTarget] = field(default_factory=dict)
    track: str = "core"  # core | extended | mixed (suite-level convenience, not authoritative; per-project track is authoritative)
    headline_eligible: bool = True

    def split_set(self) -> set[str]:
        s = self.split or ["eval"]
        return set(s)


def load_suites(path: Path | None = None) -> dict[str, SuiteConfig]:
    p = path or (V3_CONFIG_DIR / "suites.yaml")
    data = _load_yaml(p)
    out: dict[str, SuiteConfig] = {}
    for sid, cfg in (data.get("suites") or {}).items():
        cfg = dict(cfg or {})
        split = cfg.get("split", "eval")
        if isinstance(split, str):
            split = [split]
        projects: dict[str, SuiteProjectTarget] = {}
        for pid, pcfg in (cfg.get("projects") or {}).items():
            pcfg = dict(pcfg or {})
            mcs = pcfg.get("max_cluster_share")
            # track/headline_eligible: explicit in YAML wins; fallback: P4 synthetic is extended/non-headline
            raw_track = str(pcfg.get("track") or "").strip().lower()
            if not raw_track:
                # default core, but P4 via synthetic dataset is extended by construction
                _has_synthetic = any((str(s.get("dataset") or "") == "credential_catalog_synthetic") for s in (pcfg.get("strata") or []))
                raw_track = "extended" if (pid == "P4_credential_flow" and _has_synthetic) else "core"
            if raw_track not in ("core", "extended"):
                raw_track = "core"
            raw_hl = pcfg.get("headline_eligible")
            if raw_hl is None:
                raw_hl = (raw_track == "core")
            else:
                raw_hl = bool(raw_hl)
            projects[pid] = SuiteProjectTarget(
                project=pid,
                manifest=str(pcfg.get("manifest") or ""),
                target=int(pcfg.get("target", 0)),
                strata=list(pcfg.get("strata") or []),
                max_cluster_share=float(mcs) if mcs is not None else None,
                track=raw_track,
                headline_eligible=raw_hl,
            )
        # suite-level track: explicit wins else derived (mixed if projects disagree)
        raw_suite_track = str(cfg.get("track") or "").strip().lower()
        raw_suite_hl = cfg.get("headline_eligible")
        if not raw_suite_track:
            _tracks = {v.track for v in projects.values()}
            if len(_tracks) == 1:
                raw_suite_track = next(iter(_tracks))
            elif len(_tracks) > 1:
                raw_suite_track = "mixed"
            else:
                raw_suite_track = "core"
        if raw_suite_track not in ("core", "extended", "mixed"):
            raw_suite_track = "core"
        if raw_suite_hl is None:
            raw_suite_hl = (raw_suite_track == "core")
        else:
            raw_suite_hl = bool(raw_suite_hl)
        out[sid] = SuiteConfig(
            suite_id=sid,
            seed=int(cfg.get("seed", 42)),
            split=list(split),
            split_version=str(cfg.get("split_version", "split-v1")),
            projects=projects,
            track=raw_suite_track,
            headline_eligible=raw_suite_hl,
        )
    return out


def get_suite(suite_id: str, path: Path | None = None) -> SuiteConfig:
    suites = load_suites(path)
    if suite_id not in suites:
        raise ConfigError(f"unknown suite {suite_id!r}; known: {sorted(suites)}")
    return suites[suite_id]
