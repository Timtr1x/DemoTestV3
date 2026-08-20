"""Built-in dataset adapters (registration happens on import)."""
from __future__ import annotations

from . import legacy_v2  # noqa: F401  (registers LegacyV2Adapter)
from . import llmail  # noqa: F401  (registers LLMailAdapter)
from . import agentdojo  # noqa: F401  (registers AgentDojoAdapter)
from . import credential_traces  # noqa: F401  (registers CredentialTracesAdapter)
from . import credential_catalog_synthetic  # noqa: F401  (registers CredentialCatalogSyntheticAdapter)
from . import credential_dynamic_traces  # noqa: F401  (registers CredentialDynamicTracesAdapter)
from . import skillleakbench  # noqa: F401  (registers SkillLeakbench adapters)

__all__ = ["legacy_v2", "llmail", "agentdojo", "credential_traces", "credential_catalog_synthetic", "credential_dynamic_traces", "skillleakbench"]
