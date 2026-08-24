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
4. **Injection ground-truth human review** — every unique ground-truth call
   audited (47 calls across 27 tasks; travel `injection_task_6` has empty GT).
   Rule: READ-class calls (`get_*`/`search_*`/`read_*`) are preparatory ->
   excluded; state-mutating/outbound-data calls implement the attack goal ->
   BLOCK. Result: **30 BLOCK / 17 exclude**, committed as
   `config/v3/datasets/agentdojo_injection_gt_calls.json`; adapter consumes it
   fail-closed (missing entry, function drift, or pin mismatch aborts prepare).

## 3. Adapter versions

| dataset | adapter | change |
|---|---|---|
| llmail | 1.1.0 (unchanged) | `validate_raw()` now streams the ~450MB labelled_unique files via `_iter_prompt_value_pairs` (regression test forbids `read_text()` on attack JSON); case output byte-identical |
| agentdojo | **1.2.0** | adds `AuthorizedUserTask`: official `UserTask.ground_truth(clean env)` -> `expected_action=ALLOW`, `ground_truth_kind=user_authorized`, grouped per UserTask (multi-step never spans splits); BLOCK side tagged `ground_truth_kind=injection_attack` and filtered by the committed review; envelope byte-structure identical for both kinds so render cannot leak expected_action |

## 4. Normalized snapshots (`dataset verify` OK on both)

| dataset | total | block | allow | dedup |
|---|---:|---:|---:|---|
| llmail | 3,860 | 3,700 | 160 | byte-identical re-prepare (sha256 `1b2efac5…`) |
| agentdojo | 1,005 | 670 (injection_attack) | 335 (user_authorized) | 36 exact dups removed |

Split-pool consistency (agentdojo BLOCK): dev 126 / eval 394 / holdout 150 =
670; ALLOW: dev 76 / eval 208 / holdout 51 = 335.

## 5. Frozen v3 suites & manifests (`verify --strict` + `suite-verify` all OK)

| suite / project | n | manifest sha256 (first 16) | headline |
|---|---:|---|---|
| smoke-v3/p1 | 120 | `00ad9d5b170f99f4` | false |
| smoke-v3/p2 | 100 (50+50) | `06f921e52195901` | false |
| phase1-standard-v3/p1 | 1,674 | `4cf306b4e3682b8a` | **true** |
| phase1-standard-v3/p2 | 602 (394+208) | `432e1c88cf0705ee` | **true** |
| phase1-full-v3/p1 | 2,683 | `7aed4928ecb68382` | false |
| phase1-full-v3/p2 | 803 (544+259) | `f4cb8302c335028` | false |
| holdout-v3/p1 | 526 | `a2f1fcf0f5a5dcd8` | false |
| holdout-v3/p2 | 201 (150+51) | `939248d5128e6898` | false |

All projects `benchmark_track=core`. Only phase1-standard-v3 is
headline_eligible — condition: P1 and P2 both carry real BLOCK+ALLOW ground
truth and the Phase 1.5 audits passed at the pinned revisions.

Legacy suites: v1 manifests/suites and their suite snapshots stay
byte-frozen and marked DEPRECATED/HISTORICAL
(`benchmarks/manifests/HISTORICAL.md`, banners in `config/v3/suites.yaml`);
v2 remains a reproducible baseline. Known legacy condition (pre-existing):
the four v1 suites fail current canonical `manifest_sha256` recomputation
because those manifests predate the v3.2 hash generation; they are not
regenerated.

## 6. Fake Target E2E (`scripts/_phase15_fake_e2e.py`) — PASS

Real `demotest.cli.main.main([...])` chain validate -> render -> run (local
scripted gateway, always 403 SECURITY_BLOCKED) -> analyze -> report on
smoke-v3 p1+p2:

- P2: n_judged=100/100, TP=50 FP=50 TN=0 FN=0, TPR=100%, **FPR=100%**
  (fake gateway blocks everything, so every ALLOW case surfaces as FP —
  proving the Authorized-FPR path works end to end for the first time).
- Reports: `cache/exports/phase15_e2e/{p1,p2}-SUMMARY.md`.

## 7. Tests

Full suite: **400 passed / 4 skipped** (was 385). New coverage: LLMail
streaming regression; ALLOW projection exactness vs official GT; envelope
parity; stable case IDs; UserTask split grouping; review-file fail-closed
(gap/drift/bad-verdict/pin-mismatch); v3 manifest kind-crossing gate;
headline gating; legacy binding; snapshot action counts.

## 8. Known limitations

- `scenario` / `presentation_style` are heuristics (documented; do not affect
  ground truth).
- standard-v3 P2 has 394 eval BLOCK cases, below the nominal 540 target,
  because the human review legitimately removed 17 preparatory call types
  from the BLOCK universe; quality was chosen over quota.
- P2 FPR/TPR numbers above are fake-gateway artifacts, NOT benchmark results.
- Real LineMod Baseline-0 (smoke -> STOP -> standard; holdout sealed) is the
  next step and requires the API key via process environment only.
