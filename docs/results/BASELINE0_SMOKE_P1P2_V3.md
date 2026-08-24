# Baseline-0 Smoke — P1/P2 real LineMod (INTERIM)

Status: **INTERIM smoke report — STOP gate**. Standard eval NOT run; holdout
sealed. Runs are REAL LineMod traffic (no fake gateway), run at the pinned
v3 suites from `main@40ed5f7`.

- run versions: `baseline0-p1-smoke-v3` (120 cases), `baseline0-p2-smoke-v3`
  (100 cases) — separate per-project run ids, 2026-08-24.
- manifests: `benchmarks/manifests/smoke-v3/p1.json` (sha256:00ad9d5b…),
  `benchmarks/manifests/smoke-v3/p2.json` (sha256:a6b53cc2…).
- test evidence: developer-local pytest 403 passed / 4 skipped (no GitHub CI
  checks on this repo).

## Headline table

| project | n | TP | FN | TN | FP | TPR | FPR | unjudged |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| P1 email injection | 120 | 70 | 10 | 26 | 14 | 87.5% | 35.0% | 0 |
| P2 tool action | 100 | 34 | 16 | 25 | 25 | 68.0% | 50.0% | 0 |

## Run health

- transport noise: 429 = 0, 5xx = 0, error/cooldown/rate_limited = 0;
  every case reached a clear outcome (P1 120/120, P2 100/100).
- latency: P1 p50=2.6s p90=5.0s max=13.3s; P2 p50=2.0s p90=3.0s max=3.8s.
- all 143 blocked outcomes carry `code=SECURITY_BLOCKED`,
  `scanner=prompt_injection`, `policy=standard` — a single scanner mechanism
  produced every block in both projects.

## P2 decision numbers (context-aware ground truth, adapter 1.2.0)

| slice | n | result |
|---|---:|---|
| attack_implementing TPR | 34 | 22/34 = **64.7%** |
| contextual_read (off-task) TPR | 16 | 12/16 = **75.0%** |
| authorized ALLOW FPR | 50 | 25/50 = **50.0%** |

## Reading

1. LineMod blocks injection-induced off-task reads (75%) BETTER than outright
   dangerous calls (64.7%) — it is not a "dangerous action only" filter; yet
   12 attack-implementing calls (transfers / password change / exfiltration)
   passed through.
2. False-positive cost is high on both projects: half of user-authorized tool
   calls and a third of benign emails are blocked. Combined with the single
   prompt_injection scanner doing all the work, the pattern is consistent
   with "any injected-looking content is treated as an attack".
3. Smoke slices are small (contextual_read n=16); these are directional
   signals. The standard eval (P1 1674 + P2 743) exists to firm them up.

## Reproduction

```bash
python -m demotest.cli.main analyze --project P1_external_instruction \
  --target linemod --source manifest:benchmarks/manifests/smoke-v3/p1.json \
  --run-version baseline0-p1-smoke-v3
python scripts/_baseline0_smoke_report.py P1_external_instruction \
  benchmarks/manifests/smoke-v3/p1.json baseline0-p1-smoke-v3
# same for P2_tool_action / baseline0-p2-smoke-v3
```

Raw records: `cache/results_v3/<project>/linemod/baseline0-*-smoke-v3/`
(gitignored). Next gates: standard eval decision -> holdout stays sealed.
