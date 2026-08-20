"""Credential markers — official forged canaries (guide P4 P0-2).

DemoTest's ``TEST_SECRET_*`` canaries are deterministically injected but the
pinned SkillLeakBench entrypoint then *overwrites* them by running its own
``mock_creds.generate_mock_credentials(skill_id)`` and ``eval``-ing the result.
If the parser still searches for ``TEST_SECRET`` markers, real leaks are missed.

``SkillLeakBenchMarkerProvider`` mirrors the container's own generator so Host,
Docker and Parser finally agree on the same credential values.
"""
from __future__ import annotations

import hashlib
import importlib.util
import re
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any


class CredentialMarkerProvider(ABC):
    @abstractmethod
    def markers_for_skill(self, skill_id: str) -> dict[str, str]:
        """Return ``{env_name: marker_value}`` for ``skill_id``."""

    @property
    @abstractmethod
    def provenance(self) -> dict[str, str]:
        """Provenance snippet for trace metadata."""


def _load_pinned_mock_creds(pipeline_root: Path | str) -> Any:
    pipeline_root = Path(pipeline_root)
    mod_path = pipeline_root / "code" / "phase3_dynamic" / "mock_creds.py"
    if not mod_path.exists():
        raise FileNotFoundError(f"pinned mock_creds.py not found: {mod_path}")
    spec = importlib.util.spec_from_file_location("slb_mock_creds_pinned", str(mod_path))
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load spec for {mod_path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod  # type: ignore[arg-type]
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def _pinned_revision(pipeline_root: Path | str) -> str:
    # best-effort: read source-lock revision if available
    try:
        from ..source_lock import load_source_lock

        return load_source_lock("skillleakbench_pipeline").revision
    except Exception:
        return ""


def _sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class SkillLeakBenchMarkerProvider(CredentialMarkerProvider):
    """Markers from the pinned ``generate_mock_credentials``.

    These are the same ``sk-leakbench-mock-*`` / ``AKIA-LEAKBENCH-*`` values
    the container writes to ``/skills/.env`` and exports into the skill process.
    """

    def __init__(self, pipeline_root: Path | str) -> None:
        self.pipeline_root = Path(pipeline_root)
        self._mod = _load_pinned_mock_creds(self.pipeline_root)
        mock_path = self.pipeline_root / "code" / "phase3_dynamic" / "mock_creds.py"
        self._mock_sha256 = _sha256_of(mock_path) if mock_path.exists() else ""
        self._revision = _pinned_revision(self.pipeline_root)

    def markers_for_skill(self, skill_id: str) -> dict[str, str]:
        creds = self._mod.generate_mock_credentials(skill_id)
        env_vars = dict(creds.get("env_vars") or {})
        # The entrypoint never exports a mock ANTHROPIC_API_KEY (it would break
        # the agent's own auth), so we mirror that exclusion host-side.
        env_vars.pop("ANTHROPIC_API_KEY", None)
        return {str(k): str(v) for k, v in env_vars.items()}

    @property
    def provenance(self) -> dict[str, str]:
        return {
            "credential_kind": "official_forged_canary",
            "credential_generator": "SkillLeakBench/mock_creds.py",
            "credential_generator_revision": self._revision,
            "credential_generator_sha256": self._mock_sha256,
        }


class TestSecretMarkerProvider(CredentialMarkerProvider):
    """Legacy TEST_SECRET provider — kept for offline tests only."""

    def __init__(self, pipeline_revision: str) -> None:
        self.pipeline_revision = pipeline_revision

    def markers_for_skill(self, skill_id: str) -> dict[str, str]:
        from .sandbox import injected_credentials

        return injected_credentials(
            pipeline_revision=self.pipeline_revision, skill_id=skill_id
        )

    @property
    def provenance(self) -> dict[str, str]:
        return {
            "credential_kind": "TEST_SECRET",
            "credential_generator": "demotest/datasets/dynamic/sandbox.py:injected_credentials",
            "credential_generator_revision": self.pipeline_revision,
            "credential_generator_sha256": "",
        }
