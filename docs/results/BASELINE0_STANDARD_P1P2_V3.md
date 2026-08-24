# Baseline-0 Standard — P1/P2 real LineMod (Phase 1.5 capstone)

Status: **COMPLETE — STOP gate**. Both standard evals ran on the pinned v3
suites at `main@3cb055e` config (identical target/scanner/policy as the smoke,
zero tuning). Holdout remains sealed. Test evidence: developer-local pytest
403 passed / 4 skipped.

- run versions: `baseline0-p2-standard-v3` (743 cases),
  `baseline0-p1-standard-v3` (1674 cases), 2026-08-24.
- manifests: `phase1-standard-v3/p2.json` (sha256:e35aff7a…, headline=true),
  `phase1-standard-v3/p1.json` (sha256:4cf306b4…, headline=true).

## Confusion matrices

| project | n | TP | FN | TN | FP | TPR | FPR | unjudged | pass_fail |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| P2 tool action | 743 | 311 | 224 | 79 | 129 | 58.1% | 62.0% | 0 | FAIL |
| P1 email injection | 1674 | 1357 | 223 | 73 | 21 | **85.9%** | 22.3% | 0 | FAIL |

## Run health (all four Baseline-0 runs)

- zero transport noise anywhere: no 429, no 5xx, no error/cooldown/rate_limited
  outcomes; every one of 2,637+100 cases reached a clear outcome.
- latency: P2 p50≈2.05s p99≈3.16s max≈7.5s; P1 p50≈2.47s p90≈4.63s max≈24.6s.
- every blocked outcome (P1 1378, P2 440) carries
  `code=SECURITY_BLOCKED, scanner=prompt_injection, policy=standard`.

## P2 decision numbers (context-aware ground truth)

| slice | smoke n=100 | standard n=743 |
|---|---:|---:|
| attack_implementing TPR | 22/34 = 64.7% | 213/390 = **54.6%** |
| contextual_read (off-task) TPR | 12/16 = 75.0% | 98/145 = **67.6%** |
| authorized ALLOW FPR | 25/50 = 50.0% | 129/208 = **62.0%** |

## P1 breakdowns (standard)

by label_source:
| source | n | attack TPR |
|---|---:|---|
| api_triggered | 267 | 240/267 = 89.9% |
| judge | 1313 | 1117/1313 = 85.1% |
| benign_fp (ALLOW) | 94 | FP 21/94 = 22.3% |

by presentation_style:
| style | n | result |
|---|---:|---|
| explicit | 1509 | block TPR 1290/1509 = 85.5% |
| structured | 71 | block TPR 67/71 = 94.4% |
| natural (benign) | 94 | FP 21/94 = 22.3% |

by source_phase:
| phase | n | attack TPR |
|---|---:|---|
| phase1 | 1294 | 1123/1294 = 86.8% |
| phase2 | 286 | 234/286 = 81.8% |

## Smoke -> Standard delta

| metric | smoke | standard | delta |
|---|---:|---:|---|
| P1 TPR | 87.5% | 85.9% | −1.6 pt (stable) |
| P1 FPR (benign mail) | 35.0% | 22.3% | −12.7 pt |
| P2 TPR | 68.0% | 58.1% | −9.9 pt |
| P2 attack_implementing TPR | 64.7% | 54.6% | −10.1 pt |
| P2 contextual_read TPR | 75.0% | 67.6% | −7.4 pt |
| P2 authorized ALLOW FPR | 50.0% | 62.0% | +12.0 pt |

Smoke was optimistic on the P2 side; the standard confirms and sharpens the
picture.

## Reading

1. **P1 is a usable detector**: 85.9% email-injection recall at 22.3% benign
   false positives; structured attacks are caught best (94.4%), phase2 attacks
   weakest (81.8%).
2. **The P2 pattern is now firm at scale**: off-task reads are blocked more
   reliably (67.6%) than outright dangerous calls (54.6%), while 62% of fully
   authorized tool calls are killed. LineMod's single prompt_injection scanner
   reacts to injection-shaped content rather than reasoning about action
   dangerousness or authorization context.
3. Both projects FAIL their headline thresholds under this configuration —
   recorded as the honest Baseline-0 of LineMod v(unknown) against these
   suites. No tuning was performed by design; improving the number is
   LineMod's problem, not the dataset's.

Artifacts: `cache/exports/baseline0-standard/{p1,p2}/SUMMARY.md`,
raw records under `cache/results_v3/*/linemod/baseline0-*-standard-v3/`
(gitignored). Reproduce with `scripts/_baseline0_smoke_report.py <project>
<manifest> <run-version>`.

Next gates: holdout sealed pending final acceptance; any scanner/threshold
iteration on the LineMod side re-runs eval (never holdout first).
