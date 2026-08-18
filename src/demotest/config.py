"""Config loading for V3 (plan §36, §37).

V3 config lives under ``config/v3/`` to stay separate from V2's ``config/``.
Project configs map P1-P5 to channels + renderers + oracle + metrics.
Target configs define transport (url/key/model/headers/no-failover).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .core.exceptions import ConfigError, ValidationError
from .paths import CONFIG_DIR

V3_CONFIG_DIR = CONFIG_DIR / "v3"


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
