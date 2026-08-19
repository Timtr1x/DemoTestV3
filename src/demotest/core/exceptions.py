"""Framework exceptions."""
from __future__ import annotations


class DemoTestError(Exception):
    """Base class for all demotest errors."""


class ValidationError(DemoTestError):
    """A SecurityCase / config / manifest failed validation."""


class ManifestError(DemoTestError):
    """Manifest read/write integrity violation (e.g. duplicate case_id)."""


class ConfigError(DemoTestError):
    """Invalid project / target / renderer config."""


class RendererError(DemoTestError):
    """A renderer could not render a case (wrong channel, missing fields)."""


class TargetError(DemoTestError):
    """Target adapter misconfiguration or unrecoverable transport failure."""


class DatasetSourceError(DemoTestError):
    """Dataset source problem: missing files, bad revision, hash mismatch."""


class DatasetSourceDirtyError(DatasetSourceError):
    """A pinned source was locally modified (e.g. agentdojo working tree not clean).

    Guide §29: a dirty working tree must fail verify-source rather than silently
    run as "official" data.
    """
