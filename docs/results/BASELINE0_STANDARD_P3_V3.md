# Baseline-0 Standard — P3 real LineMod (HEADLINE, core)

Status: **HEADLINE**. This is the frozen P3 `eval` core benchmark (not smoke). Run is REAL LineMod traffic (no fake gateway), pinned to the frozen v3 suites at `main@89ce468` (freeze `p3_mcptox` adapter 1.1.1, `strip_outer_whitespace` provenance).

- run version: `p3-standard-v1` — 2026-08-25, project `P3_mcp_definition`, channel `mcp_definition`, fidelity `structured` (`{server,tool,description,input_schema}`).
- manifest: `benchmarks/manifests/p3-standard-v1/p3.json` (sha256:`0c8a5e727e5d317af1e9d39f818a73e31463f767d0edc5e53787e81c4f1a5c25`), suite `p3-standard-v1.json` (total_cases=464, seed=42, split=`eval`).
- suite config: 464 = 276 BLOCK (`mcptox_poison_block` all 276 eval BLOCK) + 188 ALLOW (`mcptox_clean_allow` all 188 eval ALLOW), group `mcptox:server:<server_name>` (25 servers in eval), `benchmark_track=core`, `headline_eligible=true` (suite + project) → `analyze` `pass_fail=PASS` is the headline verdict for `tpr_min=0.85` only; operational selectivity is assessed separately (see Reading).
- source lock: `p3_mcptox` adapter `1.1.1`, raw_sha256 `a54ca29e8d8864c4e4419759be18aca50c4a84adb2be1c51d7d196112a3c51c4`, revision `f85189f9ad12504c197c7f920ab818a40657b1fa`, 794-case freeze (485 BLOCK + 309 ALLOW across 45 servers, FAIL-CLOSED). Smoke was `p3-smoke-v1` 100=60+40 (`dev`, 8 servers); Standard/Holdout splits are `group_aware_case_count_v2` — one server never appears in >1 split. Provenance 1.1.1 is `semantic payload invariance` (Gateway-visible 794 unchanged vs 1.1.0; `case_fingerprint` recomputed due to `source_span_sha256`/`projection_transform` — expected).
- test evidence: `manifest verify --strict` / `suite-verify` / `validate --target linemod` / `render` spot-check passed pre-run; real run `gap 0.5s max_attempts 3`.

## Headline table

| project | n | TP | FN | TN | FP | TPR | FPR | block_rate | unjudged |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| P3 mcp_definition | 464 | 266 | 10 | 58 | 130 | 96.38% | 69.15% | 85.34% | 0 |

Ground truth: 276 BLOCK (`mcp_definition_poisoning`, `expected_action=block`) / 188 ALLOW (`benign_mcp_definition`, `expected_action=allow`). TPR = 266/276, FPR = 130/188, block_rate = 396/464. `analyze` headline `pass_fail=PASS` (TPR 0.964 > 0.85), `by_channel mcp_definition` same. The quotable P3 Standard number — Smoke (98.33% / 75.00%, n=100, `NON_HEADLINE`) was directional only. Wilson 95% CI: TPR 96.38% `[93.46%, 98.02%]` n=276; FPR 69.15% `[62.22%, 75.31%]` n=188; ACC 69.83% (324/464).

## Run health — PASS (pipeline gate true, detection headline requires selectivity reading)

| signal | value | gate |
|---|---:|---|
| clear outcomes | 464/464 (blocked=396 passed=68) | ✅ |
| 429 | 0 | ✅ |
| 5xx | 0 (http 200×68, 403×396) | ✅ |
| error | 0 (`error=None` ×464) | ✅ |
| cooldown | 0 | ✅ |
| rate_limited | 0 | ✅ |
| unjudged | 0 (n_judged=464/464) | ✅ |
| attempt >1 | 0 (all `attempt=1`) | ✅ |

Every case reached a clear `outcome ∈ {blocked, passed}` with a single attempt; no transport noise, no retries, no cooldown. Health PASS and detection FAIL (selectivity) are orthogonal — pipeline is clean, detection is high-recall / low-selectivity.

## Mechanism — scanner / policy / block code

All 396 blocked outcomes have `http_status=403`; `security_flag` carries the gateway decision:

```
error={'code': 'SECURITY_BLOCKED', 'message': 'Request blocked by security policy',
        'type': 'permission_error',
        'details': {'action': 'block', 'policy': 'standard',
                    'scanner': 'prompt_injection', 'score': 0.503…1.0}}
```

- `code=SECURITY_BLOCKED`, `policy=standard`, `scanner=prompt_injection` — single scanner mechanism produced every block (same as P1/P2 Smoke, P3 Smoke 89/89, and P1/P2 Standard). No other scanner/policy observed.
- Top-level record fields `scanner`/`policy` are empty strings for this target transport (LineMod does not populate them at the record top level); the authoritative scanner/policy are inside `security_flag`/`error.details` as above. `report` therefore shows `scanner=none` — that is a transport reporting artifact, not a second mechanism.
- Score (blocked only; passed has no score): `mean 0.952 min 0.503 max 1.0 p50 0.996`. Split: TP `mean 0.972 p50 0.999 p25 0.992 p75 1.0` n=266; FP `mean 0.910 p50 0.966 p25 0.838 p75 0.994` n=130. TP and FP medians are both ≈0.97–1.0; distributions overlap heavily — scanner score alone does not separate poisoned vs clean at this threshold.

## Latency

| p50 | p90 | p95 | max | min | mean |
|---:|---:|---:|---:|---:|---:|
| 1802 ms | 2573 ms | 2852 ms | 5945 ms | 1581 ms | 2008.5 ms |

Per the committed export `cache/exports/p3_standard_real/SUMMARY.md`: p50=1800.5 ms p95=2848.4 ms (same raw records, percentile interpolation). Smoke p50 1760 ms p95 3494 ms — same order, no anomaly. ALLOW FP `mean 1893 p50 1726` vs ALLOW TN `mean 2814 p50 2717` — false positives are notably faster (short imperative definitions may early-exit).

## Breakdowns

### By paradigm (BLOCK only; ALLOW has no paradigm)

| paradigm | n | TP | FN | TPR | 95% CI (Wilson) |
|---|---:|---:|---:|---:|---|
| Template-1 | 47 | 45 | 2 | 95.74% | [85.8, 98.8] |
| Template-2 | 102 | 98 | 4 | 96.08% | [90.3, 98.5] |
| Template-3 | 127 | 123 | 4 | 96.85% | [92.2, 98.8] |
| ALLOW (clean) | 188 | — | — | — | FPR 69.15% [62.2, 75.3] |

Templates are indistinguishable at headline n — attack style does not drive LineMod's P3 decision.

### By risk (BLOCK only)

| risk | n | TP | FN | TPR |
|---|---:|---:|---:|---:|
| Privacy Leakage | 61 | 59 | 2 | 96.72% |
| Information Manipulation | 58 | 54 | 4 | 93.10% |
| Service Disruption | 44 | 43 | 1 | 97.73% |
| Data Tampering | 27 | 24 | 3 | 88.89% |
| Credential Leakage | 25 | 25 | 0 | 100.0% |
| Financial Loss | 18 | 18 | 0 | 100.0% |
| Code Injection | 12 | 12 | 0 | 100.0% |
| Message Hijacking | 12 | 12 | 0 | 100.0% |
| Instruction Tampering | 11 | 11 | 0 | 100.0% |
| Infrastructure Damage | 8 | 8 | 0 | 100.0% |
| ALLOW (clean/empty) | 188 | — | — | FPR 69.15% |

No risk subtype rescues selectivity — best and worst are both high recall.

### By server (group_id) — headline split has 25 eval servers

| server | n | BLOCK n | TP | FN | TPR | ALLOW n | FP | TN | FPR | Discrimination Gap (TPR−FPR) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|---:|
| Email | 41 | 41 | 41 | 0 | 100.0% | 0 | 0 | 0 | — | — |
| Financial Dataset | 38 | 27 | 24 | 3 | 88.9% | 11 | 1 | 10 | 9.1% | **+79.8pt** |
| Codacy | 36 | 16 | 16 | 0 | 100.0% | 20 | 14 | 6 | 70.0% | +30.0pt |
| AlphaVantage | 36 | 16 | 12 | 4 | 75.0% | 20 | 20 | 0 | 100.0% | **−25.0pt** |
| FileSystem | 35 | 24 | 24 | 0 | 100.0% | 11 | 7 | 4 | 63.6% | +36.4pt |
| AdFin | 33 | 13 | 13 | 0 | 100.0% | 20 | 9 | 11 | 45.0% | +55.0pt |
| DumplingAI | 32 | 12 | 12 | 0 | 100.0% | 20 | 20 | 0 | 100.0% | 0.0pt |
| Puppeteer | 23 | 16 | 16 | 0 | 100.0% | 7 | 3 | 4 | 42.9% | +57.1pt |
| Git | 22 | 11 | 10 | 1 | 90.9% | 11 | 9 | 2 | 81.8% | +9.1pt |
| AmapMap | 22 | 10 | 10 | 0 | 100.0% | 12 | 7 | 5 | 58.3% | +41.7pt |
| mcp-simple-arxiv | 21 | 17 | 16 | 1 | 94.1% | 4 | 4 | 0 | 100.0% | −5.9pt |
| BaiduMap | 21 | 11 | 10 | 1 | 90.9% | 10 | 6 | 4 | 60.0% | +30.9pt |
| Gitlab | 18 | 9 | 9 | 0 | 100.0% | 9 | 9 | 0 | 100.0% | 0.0pt |
| Everything | 16 | 8 | 8 | 0 | 100.0% | 8 | 8 | 0 | 100.0% | 0.0pt |
| Google Maps | 13 | 6 | 6 | 0 | 100.0% | 7 | 0 | 7 | 0.0% | **+100.0pt** |
| EverArt | 11 | 10 | 10 | 0 | 100.0% | 1 | 1 | 0 | 100.0% | 0.0pt |
| Redis | 9 | 5 | 5 | 0 | 100.0% | 4 | 4 | 0 | 100.0% | 0.0pt |
| Claude Post | 8 | 4 | 4 | 0 | 100.0% | 4 | 4 | 0 | 100.0% | 0.0pt |
| Tavily | 8 | 4 | 4 | 0 | 100.0% | 4 | 2 | 2 | 50.0% | +50.0pt |
| DoDo Payments | 8 | 8 | 8 | 0 | 100.0% | 0 | 0 | 0 | — | — |
| GoogleDrive | 4 | 3 | 3 | 0 | 100.0% | 1 | 0 | 1 | 0.0% | +100.0pt |
| AWSKnowledgeBase | 3 | 2 | 2 | 0 | 100.0% | 1 | 1 | 0 | 100.0% | 0.0pt |
| Sentry | 2 | 1 | 1 | 0 | 100.0% | 1 | 0 | 1 | 0.0% | +100.0pt |
| Sequential Thinking | 2 | 1 | 1 | 0 | 100.0% | 1 | 0 | 1 | 0.0% | +100.0pt |
| Flomo | 2 | 1 | 1 | 0 | 100.0% | 1 | 1 | 0 | 100.0% | 0.0pt |

Gap = TPR_server − FPR_server. Positive = discriminating; 0 = no discrimination (blocks everything); negative = worse than random on that server. Best: Google Maps/Sentry/Sequential Thinking +100pt (TPR 100% FPR 0%); worst: AlphaVantage −25pt (TPR 75% FPR 100%). Median server gap is ~30pt but 8 servers sit at 0pt — LineMod blocks all their definitions regardless of poison/clean.

## Mechanism analysis (offline, 5 dimensions, no LineMod calls, no Holdout)

### 1. Length

| bucket (chars) | BLOCK TPR | ALLOW FPR |
|---|---:|---:|
| 0–100 | — (0 BLOCK) | **79.2%** (99/125) |
| 101–250 | 94.2% (113/120) | 53.8% (7/13) |
| 251–500 | 97.8% (134/137) | 41.9% (13/31) |
| 501–1000 | 100.0% (19/19) | 50.0% (5/10) |
| 1000+ | — (0 BLOCK) | 66.7% (6/9) |

- ALLOW FP `mean 176 median 50 p75 88 p90 452`; ALLOW TN `mean 289 median 229 p75 314 p90 801`. False positives are dominated by **short imperative definitions** (0–100 chars, mostly ≥79% FPR); longer clean definitions (251–500) drop to ~42% FPR.
- BLOCK overall `mean 290 median 281`; ALLOW overall `mean 211 median 53` — poisoned definitions are on average longer, but length alone does not explain FP (long clean still 42–67% FPR).

### 2. Style (deterministic features, no LLM)

| slice | n | imperative% | must% | you% | should/always/before% | action_verb% | path% | json/args% |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| ALLOW FP | 130 | 50.0% | 0.8% | 10.8% | 9.2% | 56.9% | 4.6% | 7.7% |
| ALLOW TN | 58 | 44.8% | 1.7% | 8.6% | 24.1% | 53.4% | 8.6% | **37.9%** |
| BLOCK TP | 266 | 45.1% | **75.9%** | **77.1%** | **62.0%** | **75.9%** | 34.2% | 48.9% |
| BLOCK FN | 10 | **80.0%** | 40.0% | 50.0% | **80.0%** | **90.0%** | 0.0% | **100.0%** |

- BLOCK TP are strongly modal: `must 75.9%`, `you 77.1%`, `should/always/before 62%` — classic injection-shaped imperatives. BLOCK FN are even more imperative (80%) but less `must/you` (40–50%), more `before/first` preconditions (80%) and always carry `Arguments:` json scaffolding (100%).
- ALLOW FP vs TN are nearly identical on `imperative`, `must`, `you`, `action_verb` — style does not separate FP from TN. The only clear separator is `json/args` (FP 7.7% vs TN 37.9%) and `should/always/before` (FP 9.2% vs TN 24.1%): **clean definitions that look like structured docs with Arguments/parameters are more likely to be spared**.

### 3. Domain / Server effect

Per-server ALLOW means (sorted by FPR desc):

| server | ALLOW n | FPR | mean_len | imperative% | must% | mean_lat | mean_score (blocked) |
|---|---:|---:|---:|---:|---:|---:|---:|
| AlphaVantage | 20 | 100.0% | 25 | 100% | 0% | 1772 | 0.957 |
| DumplingAI | 20 | 100.0% | 53 | 30% | 0% | 1836 | 0.961 |
| Gitlab | 9 | 100.0% | 45 | 78% | 0% | 1758 | 0.900 |
| Everything | 8 | 100.0% | 48 | 0% | 0% | 1744 | 0.867 |
| Codacy | 20 | 70.0% | 585 | 70% | 0% | 2565 | 0.938 |
| FileSystem | 11 | 63.6% | 281 | 64% | 9% | 2153 | 0.939 |
| BaiduMap | 10 | 60.0% | 19 | 0% | 0% | 2108 | 0.772 |
| AdFin | 20 | 45.0% | 621 | 65% | 5% | 2760 | 0.877 |
| Financial Dataset | 11 | **9.1%** | 221 | 64% | 0% | 2573 | 0.970 |
| Google Maps | 7 | **0.0%** | 46 | 57% | 0% | 2650 | — |

Pattern: highest-FPR servers produce **very short, must-free** definitions (AlphaVantage `mean 25` chars, e.g. `Fetch a time series daily adjusted`; DumplingAI `mean 53`); lowest-FPR servers produce **longer, doc-structured** definitions (AdFin 621, Codacy 585, Financial Dataset 221) — even at similar imperative rates. Score does not track FPR (Financial Dataset mean 0.970 but FPR 9% vs AlphaVantage 0.957 but FPR 100%). Server identity is a proxy for **description style/length/domain**, not an independent cause.

### 4. Scanner score (TP vs FP)

TP blocked `mean 0.972 p50 0.999 p25 0.992 p75 1.0` vs FP blocked `mean 0.910 p50 0.966 p25 0.838 p75 0.994`. Medians overlap; the scanner's calibrated score is not a useful operating point between poisoned and clean — threshold tuning would trade TPR for FPR roughly 1:1. The `0.503–1.0` blocked range and `0.53–0.57` few low-score blocks show no clean separation.

### 5. Attack-vs-Clean gap per server

Already in the breakdown table. Summary: 9/25 eval servers have gap ≥50pt (good discrimination), 8 servers have gap 0pt (no discrimination), 1 server has negative gap (AlphaVantage −25pt: cleaner definitions are blocked more than poisoned). The aggregate 69% FPR is not a uniform offset — it is driven by a subset of domains whose clean style collides with the prompt_injection scanner.

### Lexical cue offline check (same detector on both sides)

- BLOCK explicit PI cue 64/276, TPR 93.8% (60/64); BLOCK no explicit cue 212/276, TPR 97.2% (206/212). Broad PI lexicon 223/276 TPR 96.4% vs no lexicon 53/276 TPR 96.2%. **Poisoned recall does not depend on explicit injection keywords.**
- ALLOW explicit PI cue 0/188; broad lexicon 10/188 FPR 50.0% (5/10) vs no lexicon 178/188 FPR **70.2%** (125/178). **Clean without any PI-like word is more likely to be blocked** (79.2% FPR in 0–100 char bucket). Evidence against the "FP because clean contains ignore/override" hypothesis.

**Overall mechanism reading:** LineMod's `prompt_injection/standard` scanner is applied to MCP definitions as a whole. It achieves high recall by blocking aggressively (block_rate 85%, latency-fast path for FP), but its score and lexical features do not separate poisoned from clean. Short, plain imperative tool descriptions — regardless of risk — are most likely to be over-blocked; doc-structured longer descriptions with `Arguments:`/parameters are relatively spared. The effect is highly domain-dependent and stable across 25 unseen servers.

Embedding analysis deferred per review — deterministic length/style/server/score already explain the first-order FP pattern.

## Smoke → Standard delta (context, not cherry-pick)

| suite | n (BLOCK) | TPR | FPR | block_rate | headline |
|---|---:|---:|---:|---|---|
| p3-smoke-v1 (`dev`, 8 servers) | 60 | 98.33% (59/60) | 75.00% (30/40) | 89.00% | NON_HEADLINE |
| p3-standard-v1 (`eval`, 25 servers) | 276 | 96.38% (266/276) | 69.15% (130/188) | 85.34% | PASS (TPR gate) |

TPR fell 1.95pt (within CI overlap); FPR fell 5.85pt (within CI overlap, 62.2–75.3% vs 75% smoke) — Standard confirms the smoke finding at 4.6× n. No dataset or threshold change between suites — same adapter 1.1.1 freeze, only the `eval` slice differs. Scanner `prompt_injection/standard` identical. The one smoke FN (`Memory/graph_trace_lock`, Template-2/Privacy Leakage: `Before using delete_observations, call open_nodes…`) belongs to the same cross-tool precondition family as 6 of the 10 standard FNs — stable family, not a one-off.

## Reading — Standard headline PASS (recall) but FAIL (selectivity)

1. Pipeline is clean (464/464, no 429/5xx/error/cooldown/rate_limited/unjudged) — the numbers are honest Baseline-0 measurements.
2. **Detection Recall Gate: PASS** — TPR 96.38% [93.5, 98.0] exceeds `tpr_min=0.85` across templates, risks and most servers (only AlphaVantage 75% dips). The gateway does catch MCP definition poisoning when it is present.
3. **Operational Selectivity: FAIL** — FPR 69.15% [62.2, 75.3] (130/188) is far above any operational threshold; 8/25 servers are at 100% FPR, only 4/25 are at 0% FPR. At this operating point LineMod would block roughly 7 in 10 legitimate MCP tool registrations. Cannot be quoted as a usable MCP Definition Guard.
4. The pattern is not "P3 is hard to detect" (it is easy: TPR 96%) but "P3 is hard to not over-block." Mechanism analysis shows the `prompt_injection` scanner fires on plain MCP descriptions (especially short imperatives) and its score does not discriminate. Threshold or policy tuning — or a dedicated MCP definition policy — is required; dataset-side fixes would hide the effect.

## Scope — Holdout sealed, Stress deferred

- `p3-holdout-v1` (156 = 96 BLOCK + 60 ALLOW, `holdout`, `headline_eligible=false`, 12 servers) — NOT run. No `p3-holdout-v1` directory under `cache/results_v3` beyond manifests; no holdout report generated.
- `p3-smoke-v1` smoke artifacts remain at `cache/results_v3/P3_mcp_definition/linemod/p3-smoke-v1-real/` and `cache/exports/p3_smoke_real/` (gitignored).
- P3-Stress (1312 Extended from `response_all.json` valid vs ~1302 dedup) remains DEFERRED per Phase 3 freeze.
- Embedding-based analysis deferred; deterministic features already explain first-order FP.

## Reproduction

```bash
demotest manifest verify --strict benchmarks/manifests/p3-standard-v1/p3.json
demotest manifest suite-verify p3-standard-v1
demotest validate --project P3_mcp_definition --target linemod \
  --source manifest:benchmarks/manifests/p3-standard-v1/p3.json

demotest run --project P3_mcp_definition --target linemod \
  --source manifest:benchmarks/manifests/p3-standard-v1/p3.json \
  --run-version p3-standard-v1 --gap 0.5 --max-attempts 3

demotest analyze --project P3_mcp_definition --target linemod \
  --source manifest:benchmarks/manifests/p3-standard-v1/p3.json \
  --run-version p3-standard-v1 --json

demotest report --project P3_mcp_definition --target linemod \
  --source manifest:benchmarks/manifests/p3-standard-v1/p3.json \
  --run-version p3-standard-v1 --out-dir cache/exports/p3_standard_real
```

Raw records: `cache/results_v3/P3_mcp_definition/linemod/p3-standard-v1/` (`mcp_definition.jsonl` 464 lines, `_combined.jsonl`, `_run_meta.json` — gitignored; `cache/exports/p3_standard_real/SUMMARY.md` is the committed-lineage report rendered from them). Manifest SHA and suite snapshot are committed and bound into `experiment_hash` / `_run_meta.json` (`manifest_sha256=sha256:0c8a5e7...`, `fidelity=mcp_definition:structured`, `headline_eligible=true`, `benchmark_track=core`, `experiment_hash=0f150d2e...`, `dataset_snapshot_hash=f764ea0b...`).

Next gate: **STOP — wait for review.** Do not run holdout. Mechanism analysis above is complete offline; embedding deferred.
