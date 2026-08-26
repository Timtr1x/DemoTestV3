# P4 Credential Leakage Core — Contract (contraction 2026-08-26)

> **Single sentence**: P4 evaluates whether the gateway blocks credential disclosures reproduced from real agent skills. SkillLeakBench is candidate discovery / risk taxonomy / provenance enrichment only.

## 1. Core eligibility (6 hard gates, provenance-independent)

A case is `REAL_REPRODUCED` (Core) iff all 6 are true; otherwise `PROJECTED` (Extended):

1. `real_skill == true` — skill existed before DemoTest, behavior not modified
2. `behavior_modified == false`
3. `credential_is_canary == true` — injected value is P4CANARY / source-bound canary, never a real secret
4. `execution_reproduced == true` — deterministic sandbox execution reached the disclosure path
5. `gateway_visible_disclosure == true` — marker observed at a Gateway-visible sink (tool_result / tool_call / outbound_response with declared visibility)
6. `human_review == CONFIRMED_DISCLOSURE` — 7-gate review accepted (`source_real && dynamic_execution_real && fake_credential_confirmed && marker_observed && sink_confirmed && gateway_projection_valid && expected_action_valid`)

**Provenance fields MUST NOT gate eligibility**:

```
skillleakbench_mapping_status
official_skill_key / official_issue_key
mapping_audit / File:Line binding / official manifest
```

are optional `reference` metadata. `reference.mapping_status = UNRESOLVED` does not affect `core_eligible`. See `src/demotest/datasets/core_eligibility.py`.

## 2. What changed (contraction)

Before: `Official SkillLeakBench-bound DIRECT >= 50` blocked Core. `andytrust` stayed `REAL_SKILL_UNBOUND / supplementary` because its `skill_name` not in official 487.
After:  `andytrust` (real skill + P4CANARY + DIRECT stdout + reviewed) is `REAL_REPRODUCED` and Core-eligible. SkillLeakBench binding is旁路 enrichment, not a gate.

Existing acquisition tooling (`candidate / runtime spec / snapshot / sandbox / P4CANARY / trace / review / publishing bridge`) is **kept and frozen** — not rewritten. Only the eligibility gate and docs/tests are contracted.

Complex identity lattice (`SOURCE_OBJECT_VERIFIED / OFFICIAL_SOURCE_DECLARED / OFFICIAL_SKILL_BOUND / OFFICIAL_ISSUE_BOUND / BOUND_EXACT / BOUND_AMBIGUOUS / REAL_SKILL_UNBOUND`) is demoted to `optional provenance metadata`. Optional tooling in `scripts/p4_*` and `docs/P4_OFFICIAL_SOURCE_RECOVERY.md` is preserved but marked enrichment.

## 3. Main chain

```
Real Skill -> runtime spec -> P4CANARY injection -> sandbox execution
  -> Gateway-visible trace -> human review -> REAL_REPRODUCED -> freeze
  -> CredentialDynamicTracesAdapter -> SecurityCase -> P4 Benchmark
```

20 `SOURCE_OBJECT_VERIFIED` objects become **candidate priority pool**, not a prerequisite for proving official mapping.

## 4. Scale

No `Official DIRECT >= 50` gate. Gates are evidence-count:

- **10 `REAL_REPRODUCED`** — method stability
- **50 `REAL_REPRODUCED`** — distribution review (provider / channel / mechanism / dedup / family dominance), then decide 100–250

`50` healthy real cases is sufficient; 150–250 is ample. No 1,000 target.

## 5. Publishing

`benchmarks/frozen/datasets/credential_dynamic_traces/` remains the frozen artifact. Headline rule in `docs/PROJECT_SCOPE.md` §5 (≥20) is superseded by this contract: first headline at 10, formal review at 50.

---
*Freezes: `src/demotest/datasets/core_eligibility.py` + 3 regression tests (`test_p4_core_eligibility.py`).*
