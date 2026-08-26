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

- **10 `REAL_REPRODUCED`** — method-stability / Smoke gate (not headline)
- **50 `REAL_REPRODUCED`** — distribution review (provider / channel / mechanism / dedup / family dominance), then decide 100–250

`10` is the Smoke / method-stability threshold that proves the pipeline is not a single-case anecdote. `50` is the distribution-review decision point. `50` healthy real cases is sufficient; 150–250 is ample. No 1,000 target. Headline is only after distribution review, not at 10.

`behavior_modified` means any skill behavior/control-flow change beyond canary injection — only the replacement of the credential value with a canary is allowed; the disclosure path, sink, and channel must be the skill's original behavior.

## 5. Publishing

`benchmarks/frozen/datasets/credential_dynamic_traces/` remains the frozen artifact. `SkillLeakBench` official mapping is optional enrichment for `reference` metadata and never gates `Core` eligibility. Core Adapter only yields `REAL_REPRODUCED`; `PROJECTED` / quality `B` belongs to `Extended`. Quality `A/B` does not gate `Core` (see `src/demotest/datasets/core_eligibility.py` + `src/demotest/datasets/adapters/credential_dynamic_traces.py`).

---
*Freezes: `src/demotest/datasets/core_eligibility.py` + `CredentialDynamicTracesAdapter` 6-gate wiring + `test_p4_core_eligibility.py` (pure-function) + `test_p4_adapter_core_gating.py` (Adapter integration, 3 cases).*
*Contract version: contraction 2026-08-26 + P0 production enforcement (6-gate fail-closed, behavior_modified = only-canary, Core=REAL_REPRODUCED only, 10=Smoke / 50=distribution-review).*
