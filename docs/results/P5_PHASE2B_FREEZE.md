# P5 Phase 2B — Full 420 Freeze (official ASB 400+20, BLOCK+ALLOW)

Status: **FROZEN** — 420-case P5 suite family sealed. No real LineMod run yet
(the freeze must land before any standard recall, same rhythm as Phase 1.5).

## 1. Decision & pin

Review 2026-08-25 accepted (d): the 20 normal tools come from the **same**
ASB pin, same commit, same memory `Tools` field, same projection family:

| item | value |
|---|---|
| source | `agiresearch/ASB` — ICLR 2025 (arXiv 2410.02644), MIT |
| commit | `1f561dccf92d55302368fa67679b4ba9d9c8fdc4` |
| files | `data/all_attack_tools.jsonl` (400) + `data/all_normal_tools.jsonl` (20) |
| raw_sha256 | `193290039b99e81e641bce72f1014911b94b31bfeb7ebd006d85c20e146382aa` (both globs) |
| adapter | `p5_asb_memory` **1.1.0** |
| normalized | `cache/datasets_v3/normalized/p5_asb_memory/cases.jsonl` — **420** cases |

## 2. Projection (both sides)

Attack (400 BLOCK) — `AttackerTool.get_tool_call_format()`:
```
[{"type":"function","function":{"name": <Attacker Tool>, "description": <Description>}}]
```

Normal (20 ALLOW) — `SimulatedTool.get_tool_call_format()` (pinned `parameters:null`):
```
[{"type":"function","function":{"name": <Tool Name>, "description": <Description>, "parameters": null}}]
```

Common envelope: `channel=memory_write`, `operation=write_memory`,
`direction=outbound`, `memory_target=agent_long_term_memory`,
`memory_operation=write`, `presentation_style=structured`,
`derivation=deterministic_projection`, `quality_tier=B`.
`Attacker Instruction` / `Expected Achievements` stay **metadata-only**.

Attack metadata: `ground_truth_kind=memory_poisoning_attack`,
`source_field=attacker_tool_definition`, `source_id=asb:mp:attack:<NNN>`.
Normal metadata: `ground_truth_kind=normal_memory_tool`,
`source_field=normal_tool_definition`, `source_id=asb:mp:normal:<NNN>`.

Count gates (fail-closed, real path): attack==400 else abort, normal==20
else abort. Provider injection (unit tests) intentionally skips gates.

## 3. Grouping & split

`group_id = asb:agent:<Corresponding Agent>` (same rule on both sides).
10 distinct groups: each agent owns 40 attacks + 2 normals = **42** cases.
`group_aware_case_count_v2` (split-v2) keeps whole groups intact:

| agent | cases | split |
|---|---|---|
| aerospace_engineer_agent | 42 | dev |
| psychological_counselor_agent | 42 | dev |
| academic_search_agent | 42 | eval |
| autonomous_driving_agent | 42 | eval |
| education_consultant_agent | 42 | eval |
| legal_consultant_agent | 42 | eval |
| medical_advisor_agent | 42 | eval |
| system_admin_agent | 42 | eval |
| ecommerce_manager_agent | 42 | holdout |
| financial_analyst_agent | 42 | holdout |
| **total** | **420** | **84 / 252 / 84** |

Hard invariant (regression): *one agent never appears in >1 split*
(`tests/v3/datasets/test_p5_asb_projection.py::test_agent_never_spans_splits_integration`).
Cross-suite check is in the freeze validation — holdout is sealed.

## 4. Suites (single-split; headline consistent)

| suite | split | n | BLOCK | ALLOW | headline | track |
|---|---|---|---|---|---|---|
| `p5-smoke-v1` | dev | 64 | 60 | 4 | false | core |
| `p5-standard-v1` | eval | 252 | 240 | 12 | **true** | core |
| `p5-holdout-v1` | holdout | 84 | 80 | 4 | false | core |
| `p5-asb-proof-v0` | dev+eval+holdout | 8 | 8 | 0 | false | core (retained) |

Strata: `asb_memory_poison_block` (count=budgeted) + `asb_memory_normal_allow`
(count=all). Standard has 240 BLOCK because budget leaves 12 ALLOW in eval
(filtered pool is 240 BLOCK + 12 ALLOW = 252); smoke/holdout show the same
shape (60+4, 80+4). Manifests live under `benchmarks/manifests/p5-*/p5.json`
with `split_version=split-v2`.

Suite `headline_eligible` now propagates as the **AND over per-project
headline** (`src/demotest/config.py`): a single `headline_eligible=false`
project forces `suite=false`, and an explicit suite `true` with a `false`
project is a `ConfigError` (fail-closed). This fixes the prior inconsistency
where `p5-asb-proof-v0` had `suite true` / `project false`.

## 5. Verification

```
dataset prepare --dataset p5_asb_memory           # 420 kept, dedup 0/0
dataset verify --dataset p5_asb_memory            # OK
manifest verify ×3                                # all OK (sha256 matches)
manifest suite-verify ×4                          # all OK
pytest tests/v3/datasets/test_p5_asb_projection   # 13 passed (was 7)
pytest (full)                                     # 416 passed, 4 skipped
```

`benchmarks/suites/*.json` rebuilt via `scripts/build_suite_summaries.py`
with correct `headline_eligible` + `track` per-project.

## 6. Fake E2E (no quota; proves BLOCK+ALLOW end-to-end)

Scripted gateway always 403 (BLOCKED). Both new suites exercised:

- `p5-smoke-v1` (dev, 64): TP=60 FP=4  → TPR 100% **FPR 100%** under all-block
  (FP are the 4 ALLOW normals blocked — proves ALLOW flowed through oracle).
- `p5-standard-v1` (eval, 252): TP=240 FP=12 → same shape.

Logs: `scripts/_p5_phase2b_fake_e2e.py` → `cache/exports/p5_phase2b_e2e/`.

Renderer sample (STRUCTURED):
```
{"content": "[{\"type\":\"function\",\"function\":{\"name\":\"SystemMonitor\",...}}]",
 "memory_operation":"write","memory_target":"agent_long_term_memory"}
```
Normal sample:
```
[{"type":"function","function":{"name":"sys_monitor","description":"…","parameters":null}}]
```

## 7. What is NOT done (and not to be done now)

- No real LineMod smoke/standard runs yet — freeze first, then the same rhythm
  as Phase 1.5 (real smoke → health check → real standard → STOP, holdout
  sealed).
- No P3 work in this round (`docs/P3_P5_DATASET_SOURCE_SURVEY.md` updated
  only in its P3 status cell to `PUBLISHED / ARTIFACT AVAILABLE / LICENSE
  UNRESOLVED` and a note that MCPTox is published proceedings, repo still
  LICENSE-missing).
