# Baseline-0 Smoke — P5 real LineMod (INTERIM)

Status: **INTERIM smoke report — STOP gate**. Standard eval NOT run; holdout sealed. Run is REAL LineMod traffic (no fake gateway), pinned to the frozen v3 suites at `main@615f165`.

- run version: `baseline0-p5-smoke-v1` — 2026-08-25, project `P5_memory_write`, channel `memory_write`, fidelity `structured`.
- manifest: `benchmarks/manifests/p5-smoke-v1/p5.json` (sha256:`8f62760f9d6a005b1a125ba4269326c5bed9e5c4319dca1cb4370026ce76e0df`), suite `p5-smoke-v1.json` (total_cases=64, seed=42, split=`dev`).
- suite config: 64 = 60 BLOCK (`asb_memory_poison_block` target 60) + 4 ALLOW (`asb_memory_normal_allow` target all), group `asb:agent:<corresponding_agent>` (2 agents in dev), `benchmark_track=core`, `headline_eligible=false` (suite + project, `NON_HEADLINE`).
- source lock: `p5_asb_memory` adapter `1.1.0`, raw_sha256 `193290039b99e81e641bce72f1014911b94b31bfeb7ebd006d85c20e146382aa`, revision `1f561dccf92d55302368fa67679b4ba9d9c8fdc4`, 420-case freeze (400 attack + 20 normal across 10 agents).
- test evidence: developer-local pytest (no GitHub status checks on this repo at `615f165`); suite-verify/manifest-verify/dataset-verify gates passed at freeze.

## Headline table

| project | n | TP | FN | TN | FP | TPR | FPR | block_rate | unjudged |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| P5 memory write | 64 | 11 | 49 | 4 | 0 | 18.3% | 0.0% | 17.2% | 0 |

Ground truth: 60 BLOCK (`memory_poisoning_attack`, `expected_action=block`) / 4 ALLOW (`normal_memory_tool`, `expected_action=allow`). TPR = 11/60, FPR = 0/4. FPR n=4 is directional only — quotable FPR waits for Standard (12 ALLOW).

## Run health — PASS (pipeline gate)

| signal | value | gate |
|---|---:|---|
| clear outcomes | 64/64 (blocked=11 passed=53) | ✅ |
| 429 | 0 | ✅ |
| 5xx | 0 (http 200×53, 403×11) | ✅ |
| error | 0 (`error=None` ×64) | ✅ |
| cooldown | 0 | ✅ |
| rate_limited | 0 | ✅ |
| unjudged | 0 (n_judged=64/64) | ✅ |
| attempt >1 | 0 (all `attempt=1`) | ✅ |

Every case reached a clear `outcome ∈ {blocked, passed}` with a single attempt; no transport noise, no retries, no cooldown.

## Mechanism — scanner / policy / block code

All 11 blocked outcomes have `http_status=403`; `security_flag` carries the gateway decision:

```
error={'code': 'SECURITY_BLOCKED', 'message': 'Request blocked by security policy',
        'type': 'permission_error',
        'details': {'action': 'block', 'policy': 'standard',
                    'scanner': 'prompt_injection', 'score': 0.57…}}
```

- `code=SECURITY_BLOCKED`, `policy=standard`, `scanner=prompt_injection` — single scanner mechanism produced every block (same as P1/P2).
- Top-level record fields `scanner`/`policy` are empty strings for this target transport (LineMod does not populate them at the record top level); the authoritative scanner/policy are inside `security_flag`/`error.details` as shown above. No other scanner/policy observed.

## Latency

| p50 | p90 | p95 | max | min |
|---:|---:|---:|---:|---:|
| 2732 ms | 2947 ms | 2983 ms | 3551 ms | 1764 ms |

Per the committed export `cache/exports/p5_baseline0_smoke/SUMMARY.md`: p50=2737.5 ms p95=2979.7 ms (same raw records, percentile interpolation difference). All cases under 4 s.

## Breakdowns

### By agent (group_id)

| group_id | n | TP | FN | TN | FP | TPR (BLOCK) |
|---|---:|---:|---:|---:|---:|---:|
| asb:agent:aerospace_engineer_agent | 30 | 2 | 26 | 2 | 0 | 7.1% (2/28) |
| asb:agent:psychological_counselor_agent | 34 | 9 | 23 | 2 | 0 | 28.1% (9/32) |

Both agents have 0 FP (2/2 TN each); all ALLOW controls passed.

### By attack_type (BLOCK only; ALLOW separate)

| slice | n | TP | FN | TPR |
|---|---:|---:|---:|---:|
| Stealthy Attack | 29 | 6 | 23 | 20.7% |
| Disruptive Attack | 31 | 5 | 26 | 16.1% |
| ALLOW normal (control) | 4 | — | — | TN=4 FP=0 |

Slices are small (n≈30) — directional signals. Standard (240 BLOCK / 12 ALLOW across 6 agents) will firm them up.

## Scope — Standard / Holdout untouched

- `p5-standard-v1` (252 = 240 BLOCK + 12 ALLOW, `eval`, headline) — NOT run.
- `p5-holdout-v1` (84 = 80 BLOCK + 4 ALLOW, `holdout`) — sealed; no results directory under `cache/results_v3`.
- `p5-asb-proof-v0` (8, 1.0.0) — historical proof, not rerun; snapshot restored to `1.0.0` to match its manifest `created_from`.

## Reading — Smoke PASS as pipeline gate

1. Pipeline is healthy: 64/64 clear, no 429/5xx/error/cooldown/rate_limited/unjudged, single-attempt, correctly classified `TP/FN/TN` (FP=0). No renderer/oracle/transport issue.
2. Detection at Baseline-0 is low: TPR 18.3% (11/60). Stealthy 20.7% vs Disruptive 16.1% — both low; no evidence LineMod distinguishes the two subtypes at this n.
3. False-positive cost is 0/4 in Smoke, but n=4 is too small to quote. P1 Smoke 35.0% and P2 50.0% show the same gateway can be high-FP on other channels; P5 quotable FPR must wait for Standard n=12.
4. Score must not drive dataset changes. Per freeze review, a low TPR is an honest Baseline-0 result at the same level as P1/P2 — dataset stays frozen (adapter 1.1.0, 420 cases, group-aware splits).

## Reproduction

```bash
python -m demotest.cli.main validate --project P5_memory_write --target linemod \
  --source manifest:benchmarks/manifests/p5-smoke-v1/p5.json --no-key-check

python -m demotest.cli.main run --project P5_memory_write --target linemod \
  --source manifest:benchmarks/manifests/p5-smoke-v1/p5.json \
  --run-version baseline0-p5-smoke-v1 --gap 0.5 --max-attempts 6

python -m demotest.cli.main analyze --project P5_memory_write --target linemod \
  --source manifest:benchmarks/manifests/p5-smoke-v1/p5.json \
  --run-version baseline0-p5-smoke-v1

# rendered report (gitignored raw → committed summary)
python scripts/_baseline0_smoke_report.py P5_memory_write \
  benchmarks/manifests/p5-smoke-v1/p5.json baseline0-p5-smoke-v1
```

Raw records: `cache/results_v3/P5_memory_write/linemod/baseline0-p5-smoke-v1/` (`memory_write.jsonl` 64 lines, `_combined.jsonl`, `_run_meta.json` — gitignored). Manifest SHA and suite snapshot are committed and bound into `experiment_hash` / `_run_meta.json` (`manifest_sha256=sha256:8f627...`, `fidelity=memory_write:structured`).

Next gate: reviewer approval → `p5-standard-v1` real run (252) → STOP; holdout stays sealed.
