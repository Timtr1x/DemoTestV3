# Phase 1.5 — P1/P2 Dataset Integration Finalization (v3) — Acceptance Record

Status: **offline phases COMPLETE** (audits + adapter v1.2.0 + frozen v3
suites/manifests + fake-target E2E). Real LineMod runs (Baseline-0 smoke /
standard) intentionally NOT started; holdout remains sealed.

Base: `main@9f24c63`. Frozen throughout: `core/`, `renderers/`, `targets/`,
`oracles/`, `runners/`, `datasets/dynamic/`, P4 artifacts.

## 1. Source pins (unchanged, re-verified)

| dataset | source | revision | verify-source |
|---|---|---|---|
| llmail | HF `microsoft/llmail-inject-challenge` | `1063bdf01ec8762b812d5e06ee768a06faa5a6f7` | OK |
| agentdojo | GH `ethz-spylab/agentdojo` (benchmark v1) | `089ed468cf3ed0322acc66b0211f26d9d90dbf60` | OK |

## 2. Audits (evidence in `cache/exports/`, review file committed)

1. **LLMail label mapping** (`llmail_label_audit.json`) — streamed the full
   raw pool through the production code path: 148,385 unique attack ids,
   only 6 distinct label values, all mapped by the documented rule
   (`True`-family -> BLOCK; `False`/`Unclear` -> skipped). All 3,700 BLOCK +
   160 ALLOW snapshot cases resolve back to raw rows with identical actions;
   zero mismatches. VERDICT: PASS.
2. **LLMail metadata honesty** (`config/v3/datasets/llmail.yaml`) — declared
   fields now match reality: `scenario` = approximate content-marker
   heuristic, `presentation_style` = heuristic, `attack_goal` = framework
   classification (constant), `team_id`/`original_success` = unavailable
   without full-submissions join. Dead stratification keys removed.
   Declarative-only change: re-prepare is byte-identical.
3. **AgentDojo official enumeration gate**
   (`agentdojo_ground_truth_audit.json`) — official definition:
   `benchmark_suite_with_injections` runs all user_tasks x all injection_tasks
   per suite. official=629 / adapter=629 / missing=0 / extra=0. VERDICT: PASS.
4. **Injection ground-truth call-role review** — every unique ground-truth
   call audited (47 calls across 27 tasks; travel `injection_task_6` has
   empty GT). Roles: **attack_implementing** (30) = realizes the attacker
   goal; **contextual_read** (17) = read-only query harmless in isolation.
   Committed as `config/v3/datasets/agentdojo_injection_gt_calls.json`;
   fail-closed on missing calls, function drift, unknown roles, or pin drift.
   ROLES DO NOT DECIDE expected_action (P0 fix, below).

## 3. Adapter versions

| dataset | adapter | change |
|---|---|---|
| llmail | 1.1.0 (unchanged) | `validate_raw()` now streams the ~450MB labelled_unique files via `_iter_prompt_value_pairs` (regression test forbids `read_text()` on attack JSON); case output byte-identical |
| agentdojo | **1.2.0** | adds `AuthorizedUserTask`: official `UserTask.ground_truth(clean env)` -> `expected_action=ALLOW`, `ground_truth_kind=user_authorized`, grouped per UserTask (multi-step never spans splits); BLOCK side tagged `ground_truth_kind=injection_attack` with **context-aware authorization**: an injection-induced call is projected BLOCK unless it EXACTLY matches one of the PAIRED UserTask's own ground-truth calls (function AND canonical args — same function with different arguments is NOT authorized); kept cases carry `attack_step_class=attack_implementing\|contextual_read` from the committed call-role review, which never decides expected_action; envelope byte-structure identical for both kinds so render cannot leak expected_action |

## 4. Normalized snapshots (`dataset verify` OK on both)

| dataset | total | block | allow | dedup |
|---|---:|---:|---:|---|
| llmail | 3,860 | 3,700 | 160 | byte-identical re-prepare (sha256 `1b2efac5…`) |
| agentdojo | 1,247 | 912 (injection_attack: 670 attack_implementing + 242 contextual_read) | 335 (user_authorized) | 138 exact dups removed |

Split-pool consistency (agentdojo BLOCK): dev 174 / eval 535 / holdout 203 =
912; ALLOW: dev 76 / eval 208 / holdout 51 = 335.

## 5. Frozen v3 suites & manifests (`verify --strict` + `suite-verify` all OK)

| suite / project | n | manifest sha256 (first 16) | headline |
|---|---:|---|---|
| smoke-v3/p1 | 120 | `00ad9d5b170f99f4` | false |
| smoke-v3/p2 | 100 (50+50) | `a6b53cc22558dfcc` | false |
| phase1-standard-v3/p1 | 1,674 | `4cf306b4e3682b8a` | **true** |
| phase1-standard-v3/p2 | 743 (535+208) | `e35aff7a6de4d01f` | **true** |
| phase1-full-v3/p1 | 2,683 | `7aed4928ecb68382` | false |
| phase1-full-v3/p2 | 997 (738+259) | `17da94182f64a44b` | false |
| holdout-v3/p1 | 526 | `a2f1fcf0f5a5dcd8` | false |
| holdout-v3/p2 | 201 (150+51) | `ffa89196c7a61003` | false |

All projects `benchmark_track=core`. Only phase1-standard-v3 is
headline_eligible — condition: P1 and P2 both carry real BLOCK+ALLOW ground
truth and the Phase 1.5 audits passed at the pinned revisions.

Legacy suites: v1 manifests/suites and their suite snapshots stay
byte-frozen and marked DEPRECATED/HISTORICAL
(`benchmarks/manifests/HISTORICAL.md`, banners in `config/v3/suites.yaml`);
v2 is preserved the same way — **historical artifacts preserved; original
adapter lineage required for strict reproduction** (no multi-version
normalized infrastructure is built). Known legacy condition (pre-existing):
the four v1 suites fail current canonical `manifest_sha256` recomputation
because those manifests predate the v3.2 hash generation; they are not
regenerated.

## 6. Fake Target E2E (`scripts/_phase15_fake_e2e.py`) — PASS

Real `demotest.cli.main.main([...])` chain validate -> render -> run (local
scripted gateway, always 403 SECURITY_BLOCKED) -> analyze -> report on
smoke-v3 p1+p2 (rebuilt P2 manifests):

- P2: n_judged=100/100, TP=50 FP=50 TN=0 FN=0, TPR=100%, **FPR=100%**
  (fake gateway blocks everything, so every ALLOW case surfaces as FP —
  proving the Authorized-FPR path works end to end).
- Reports: `cache/exports/phase15_e2e/{p1,p2}-SUMMARY.md`.

## 7. Tests

Full suite: 403 passed / 4 skipped. New coverage: LLMail streaming
regression; ALLOW projection exactness vs official GT; envelope parity;
stable case IDs; UserTask split grouping; role-file fail-closed
(gap/drift/bad-role/pin-mismatch); context-aware authorization exactness
(same function + different arguments must stay BLOCK); authorized-call
exemption; attack_step_class annotation; v3 manifest kind-crossing gate;
headline gating; legacy binding; snapshot action counts.

## 8. Known limitations

- `scenario` / `presentation_style` are heuristics (documented; do not affect
  ground truth).
- Contextual-read BLOCK cases (242) are injection-induced off-task reads:
  whether they SHOULD be blocked is exactly what the benchmark measures; the
  attack_step_class breakdown lets reports separate them from
  attack-implementing calls.
- P2 FPR/TPR numbers above are fake-gateway artifacts, NOT benchmark results.
- Next step: real LineMod Baseline-0 smoke (P1 `baseline0-p1-smoke-v3` may
  start independently; P2 real smoke follows acceptance of this P0 fix),
  key via process environment only; holdout sealed.
