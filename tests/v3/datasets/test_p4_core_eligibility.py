"""P4 Core eligibility contraction — 3 locked regressions (scope 2026-08-26)."""
from demotest.datasets.core_eligibility import CoreEligibilityInput, evaluate_core_eligibility


def _base():
    return CoreEligibilityInput(
        real_skill=True,
        behavior_modified=False,
        credential_is_canary=True,
        execution_reproduced=True,
        gateway_visible_disclosure=True,
        human_review_confirmed=True,
    )


def test_real_disclosure_without_official_mapping_still_core():
    inp = _base()
    # provenance explicitly UNRESOLVED — must not affect gate
    inp2 = CoreEligibilityInput(**{**inp.__dict__, "skillleakbench_mapping_status": "UNRESOLVED", "official_skill_key": "", "official_issue_key": ""})
    r = evaluate_core_eligibility(inp2)
    assert r.eligible and r.label == "REAL_REPRODUCED"


def test_verified_mapping_without_disclosure_not_core():
    inp = CoreEligibilityInput(
        real_skill=True,
        behavior_modified=False,
        credential_is_canary=True,
        execution_reproduced=True,
        gateway_visible_disclosure=False,  # no disclosure
        human_review_confirmed=False,
        skillleakbench_mapping_status="VERIFIED",
        official_skill_key="osk:abc",
    )
    r = evaluate_core_eligibility(inp)
    assert not r.eligible
    assert r.label == "PROJECTED"


def test_synthetic_with_disclosure_lookalike_not_core():
    inp = CoreEligibilityInput(
        real_skill=False,  # synthetic
        behavior_modified=True,
        credential_is_canary=False,
        execution_reproduced=False,
        gateway_visible_disclosure=True,
        human_review_confirmed=True,
    )
    r = evaluate_core_eligibility(inp)
    assert not r.eligible
    assert "real_skill" in r.failed_gates


def test_andytrust_real_case_is_core():
    """andytrust TELEGRAM_BOT_TOKEN STDOUT DIRECT — supplementary today, Core after contraction."""
    inp = CoreEligibilityInput(
        real_skill=True,
        behavior_modified=False,
        credential_is_canary=True,
        execution_reproduced=True,
        gateway_visible_disclosure=True,
        human_review_confirmed=True,
        skillleakbench_mapping_status="UNRESOLVED",
    )
    r = evaluate_core_eligibility(inp)
    assert r.eligible
