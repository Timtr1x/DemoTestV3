"""Unit tests for LegacyV2Adapter (Commit 2)."""
from __future__ import annotations

from pathlib import Path

import pytest

from demotest.core import Channel, ExpectedAction, Operation, SecurityCase
from demotest.datasets import get_adapter
from demotest.datasets.adapters.legacy_v2 import LegacyV2Adapter
from demotest.paths import MANIFEST_DIR

# A small real V2 manifest present in the frozen cache.
SPEAR = MANIFEST_DIR / "spear_explicit_30.json"
AUTOCOMPLETE = MANIFEST_DIR / "autocomplete_400.json"


def test_legacy_adapter_loads_real_manifest():
    if not SPEAR.exists():
        pytest.skip("spear_explicit_30.json not in frozen cache")
    ad = LegacyV2Adapter(manifest_name="spear_explicit_30", project="e6")
    cases = ad.cases()
    assert len(cases) == 30
    c0 = cases[0]
    assert isinstance(c0, SecurityCase)
    assert c0.channel == Channel.USER_PROMPT
    assert c0.operation == Operation.CHAT
    assert c0.expected_action == ExpectedAction.BLOCK  # spear = attack
    assert c0.content  # prompt_text carried over
    assert c0.source_id.startswith("spear_exp30:")
    assert c0.dataset_id == "legacy_v2"
    assert c0.project_id == "e6"
    assert c0.presentation_style == "structured"  # spear -> structured
    # provenance
    prov = ad.provenance()
    assert prov["source_manifest"] == "spear_explicit_30"
    assert "dataset_version" in prov


def test_legacy_adapter_payload_too_large_maps_to_allow():
    """V2 'payload_too_large' is a transport test, not a block decision."""
    if not AUTOCOMPLETE.exists():
        pytest.skip("autocomplete_400.json not in frozen cache")
    ad = LegacyV2Adapter(manifest_name="autocomplete_400", project="e10")
    cases = ad.cases()
    assert cases
    # autocomplete manifests are benign (expected=passed or payload_too_large)
    allow = [c for c in cases if c.expected_action == ExpectedAction.ALLOW]
    assert allow, "expected some ALLOW cases from autocomplete"


def test_registry_lookup():
    ad = get_adapter("legacy_v2", manifest_name="spear_explicit_30", project="e6")
    assert isinstance(ad, LegacyV2Adapter)
    assert ad.dataset_id == "legacy_v2"


def test_unknown_adapter_raises():
    from demotest.core.exceptions import ConfigError

    with pytest.raises(ConfigError):
        get_adapter("does_not_exist")


def test_case_id_stable_across_loads():
    if not SPEAR.exists():
        pytest.skip("spear_explicit_30.json not in frozen cache")
    a = LegacyV2Adapter(manifest_name="spear_explicit_30").cases()[0].case_id
    b = LegacyV2Adapter(manifest_name="spear_explicit_30").cases()[0].case_id
    assert a == b
