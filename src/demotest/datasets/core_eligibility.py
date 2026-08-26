"""P4 Core eligibility — REAL_REPRODUCED vs PROJECTED (scope-contract v2026-08-26).

Single source of truth for P4 Core membership. Six hard gates only:

  1. real_skill == true
  2. behavior_modified == false
  3. credential_is_canary == true
  4. execution_reproduced == true
  5. gateway_visible_disclosure == true
  6. human_review == CONFIRMED_DISCLOSURE

Provenance fields (official_skill_key, official_issue_key, mapping_audit,
File:Line binding, skillleakbench_mapping_status) MUST NOT appear in this
decision — they are optional provenance metadata (reference only).

Labels:
  REAL_REPRODUCED — Core (eligible)
  PROJECTED       — Extended / framework-validation (not Core)
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CoreEligibilityInput:
    real_skill: bool
    behavior_modified: bool
    credential_is_canary: bool
    execution_reproduced: bool
    gateway_visible_disclosure: bool
    human_review_confirmed: bool
    # optional provenance — must not influence gate
    skillleakbench_mapping_status: str = ""
    official_skill_key: str = ""
    official_issue_key: str = ""


@dataclass(frozen=True)
class CoreEligibilityResult:
    eligible: bool
    label: str  # "REAL_REPRODUCED" | "PROJECTED"
    failed_gates: tuple[str, ...]


GATE_NAMES = (
    "real_skill",
    "not_behavior_modified",
    "credential_is_canary",
    "execution_reproduced",
    "gateway_visible_disclosure",
    "human_review_confirmed",
)


def evaluate_core_eligibility(inp: CoreEligibilityInput) -> CoreEligibilityResult:
    """Evaluate the 6 hard gates — no provenance field may influence outcome."""
    failed: list[str] = []
    if not inp.real_skill:
        failed.append("real_skill")
    if inp.behavior_modified:
        failed.append("not_behavior_modified")
    if not inp.credential_is_canary:
        failed.append("credential_is_canary")
    if not inp.execution_reproduced:
        failed.append("execution_reproduced")
    if not inp.gateway_visible_disclosure:
        failed.append("gateway_visible_disclosure")
    if not inp.human_review_confirmed:
        failed.append("human_review_confirmed")
    if not failed:
        return CoreEligibilityResult(eligible=True, label="REAL_REPRODUCED", failed_gates=())
    return CoreEligibilityResult(eligible=False, label="PROJECTED", failed_gates=tuple(failed))


def is_real_reproduced(inp: CoreEligibilityInput) -> bool:
    return evaluate_core_eligibility(inp).eligible
