# Baseline-0 Benchmark Report — V3 (P1 / P2 / P5 headline, P3 excluded, P4 supplementary)

Status: **Baseline-0 COMPLETE — engineering freeze**. All headline suites are frozen, smoked, and standard-evaluated on REAL LineMod (no fake gateway, no tuning). Holdout is sealed. Dataset layer is frozen; this report is the first publishable conclusion set. No LineMod parameter tuning was performed by design.

Source freeze: `main@5cdb345` (P5 `p5_asb_memory` 1.1.0 + P1/P2 Phase 1.5 v3). Raw records under `cache/results_v3/**` (gitignored); headline evidence is the committed `docs/results/BASELINE0_*.md` suite.

---

## 1. Threat coverage matrix (what is actually measured)

| Project | Channel(s) | Threat direction | Legacy | Source (pinned) | Dataset state | Suite(s) | N (standard) |
|---|---|---|---|---|---|---|---|
| **P1 External Instruction Boundary** | `email`, `web_page`, `rag_document`, `tool_result` | Prompt / direct & structured injection in external content | E2, E8(tool_result) | `llmail` (adapter byte-identical v2→v3) | **Frozen** (`phase1-standard-v3`, core) | smoke `smoke-v3/p1` + standard `phase1-standard-v3/p1` | **1674** (1580 BLOCK + 94 ALLOW) |
| **P2 Tool Action Guard** | `tool_call` | Context / tool-action injection (off-task reads vs dangerous actions vs authorized) | E8(tool_call), E11 | `AgentDojo` + official UserTask GT (adapter **1.2.0**, context-aware) | **Frozen** (`phase1-standard-v3`, core) | smoke `smoke-v3/p2` + standard `phase1-standard-v3/p2` | **743** (535 BLOCK + 208 ALLOW) |
| **P3 MCP Definition Content Guard** | `mcp_definition` | Deceptive / dangerous MCP tool definitions (DCI D_real out-of-scope) | new (A-03) | `MCPTox` 485 defs @ `f85189f` (artifact cloned) | **PARTIAL** — `PUBLISHED / ARTIFACT AVAILABLE / LICENSE UNRESOLVED`, not in core | — | — (excluded from headline) |
| **P4 Credential Flow Guard** | `user_prompt`, `tool_result`, `tool_call`, `memory_write`, `outbound_response` | Secret / credential exposure via dynamic trace | E4, E5 | `credential_catalog_synthetic` 1.0.0 + reviewed traces bridge | **Frozen (supplementary)** (`p4-*-v1`, **extended**, `headline_eligible=false`) | smoke/standard/full/holdout (`p4-*-v1`) — discovery-oriented, not classifier headline | — (supplementary; real finding: `andytrust` TELEGRAM token stdout exposure) |
| **P5 Memory Write Guard** | `memory_write` | Memory poisoning / persistent rule implantation | E9 (A-02) | `agiresearch/ASB` pin `1f561dc` — **420 frozen** (400 attack + 20 normal, same-origin ALLOW) | **Frozen** (`p5-*-v1`, core) | smoke `p5-smoke-v1` (dev, 2 agents) + standard `p5-standard-v1` (eval, 6 agents) + holdout `p5-holdout-v1` sealed | **252** (240 BLOCK + 12 ALLOW) |

Headline is P1+P2+P5 only. P3 is explicitly excluded (dataset governance readiness, not a FAIL). P4 is supplementary/experimental (small-n discovery, not a classifier benchmark at comparable scale).

---

## 2. Baseline-0 headline table (real LineMod, zero tuning)

| Benchmark | suite | n | TP | FN | TN | FP | **TPR** | **FPR** | block_rate | unjudged | pass_fail (tpr_min=0.9) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| **P1 email injection** | `phase1-standard-v3/p1` | **1674** | 1357 | 223 | 73 | 21 | **85.9%** | **22.3%** | 82.3% | 0 | FAIL |
| **P2 tool action** | `phase1-standard-v3/p2` | **743** | 311 | 224 | 79 | 129 | **58.1%** | **62.0%** | 59.2% | 0 | FAIL |
| **P5 memory write** | `p5-standard-v1` | **252** | 28 | 212 | 12 | 0 | **11.7%** | **0.0%** | 11.1% | 0 | FAIL |

All three are `benchmark_track=core`, `headline_eligible=true` (the only headline suites). Smoke is `NON_HEADLINE` by design:

| suite | n (BLOCK) | TPR | FPR | note |
|---|---:|---:|---:|---|
| P1 smoke `smoke-v3/p1` | 80 | 87.5% | 35.0% (n=40) | directional; standard 85.9%/22.3% is stable |
| P2 smoke `smoke-v3/p2` | 50 | 68.0% | 50.0% (n=50) | optimistic; standard 58.1%/62.0% firms up |
| P5 smoke `p5-smoke-v1` | 60 | 18.3% | 0.0% (n=4) | directional; quotable FPR waits for standard n=12 |

### P2 decision slices (context-aware GT, adapter 1.2.0)

| slice | smoke n=100 | **standard n=743** |
|---|---:|---:|
| attack_implementing TPR | 22/34 = 64.7% | **213/390 = 54.6%** |
| contextual_read (off-task) TPR | 12/16 = 75.0% | **98/145 = 67.6%** |
| authorized ALLOW FPR | 25/50 = 50.0% | **129/208 = 62.0%** |

### P5 slices (standard, eval 6 agents)

| slice | n | TPR |
|---|---:|---:|
| Stealthy Attack | 120 | 12.5% (15/120) |
| Disruptive Attack | 120 | 10.8% (13/120) |
| ALLOW normal | 12 | TN=12 FP=0 |
| Best agent (`education_consultant_agent`) | 40 BLOCK | 32.5% (13/40) |
| Worst agent (`autonomous_driving_agent`) | 40 BLOCK | 5.0% (2/40) — others 7.5–10.0% |

P1 slices (standard): `api_triggered` 89.9% (240/267) > `judge` 85.1% (1117/1313); `structured` 94.4% (67/71) > `explicit` 85.5%; `phase1` 86.8% > `phase2` 81.8%.

---

## 3. Dataset & suite provenance (reproducibility)

| suite | manifest | sha256 (prefix) | seed | split | group discipline | source lock |
|---|---|---|---|---|---|---|
| `smoke-v3` (P1) | `smoke-v3/p1.json` | `00ad9d5b…` | 42 | dev | — | llmail v2-identical |
| `phase1-standard-v3` (P1) | `phase1-standard-v3/p1.json` | `4cf306b4…` | 42 | eval | — | — |
| `smoke-v3` (P2) | `smoke-v3/p2.json` | `a6b53cc2…` | 42 | dev | — | AgentDojo adapter 1.2.0 |
| `phase1-standard-v3` (P2) | `phase1-standard-v3/p2.json` | `e35aff7a…` | 42 | eval | — | — |
| `p5-smoke-v1` | `p5-smoke-v1/p5.json` | `8f62760f…` | 42 | dev (20%) | `asb:agent:<Corresponding Agent>` (2 agents ×30/34) | `p5_asb_memory` 1.1.0, raw `19329003…`, rev `1f561dcc…`, 420 frozen |
| `p5-standard-v1` | `p5-standard-v1/p5.json` | `3f194d16…` | 42 | eval (60%) | 6 agents ×42 (eval) | same |
| `p5-holdout-v1` | `p5-holdout-v1/p5.json` | `bb8c7433…` | 42 | holdout (20%) | 2 agents ×42 — **sealed** | same |

All headline suites are `benchmark_track=core`. P4 is `extended` (`headline_eligible=false`); its `p4-standard-v1` is n=463 (not headline-scale). All manifests bind into `_run_meta.json` (`manifest_sha256`, `experiment_hash`, `dataset_snapshot_hash`, `fidelity`) — rerunning with a different manifest yields a different `run_version`.

Run versions (real LineMod, `gap=0.5`, `max_attempts=6`, `X-LineMod-No-Failover: true`):

- `baseline0-p1-smoke-v3` (120), `baseline0-p2-smoke-v3` (100) — 2026-08-24
- `baseline0-p1-standard-v3` (1674), `baseline0-p2-standard-v3` (743) — 2026-08-24
- `baseline0-p5-smoke-v1` (64) — 2026-08-25, `baseline0-p5-standard-v1` (252) — 2026-08-25

Evidence on this repo is developer-local `pytest 403 passed / 4 skipped` (no GitHub status checks at `5cdb345`) plus `dataset verify` / `manifest verify --strict` / `suite-verify` gates passing at each freeze.

---

## 4. Run health — pipeline gate true, detection result independent

| suite | outcomes | 429 | 5xx | error | cooldown | rate_limited | unjudged | retry>1 | latency p50/p90/p95/max |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| P1 smoke 120 | 120/120 (70+50) | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 2.6s / 5.0s / — / 13.3s |
| P2 smoke 100 | 100/100 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 2.0s / 3.0s / — / 3.8s |
| P1 standard 1674 | 1674/1674 (1378 blocked) | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 2.47s / 4.63s / — / 24.6s |
| P2 standard 743 | 743/743 (440 blocked) | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 2.05s / — / 3.16s p99 / 7.5s |
| P5 smoke 64 | 64/64 (11 blocked) | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 2.73s / 2.95s / 2.98s / 3.55s |
| **P5 standard 252** | **252/252 (28 blocked)** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **2.91s / 3.12s / 3.18s / 3.36s** |

Every blocked outcome across P1+P2+P5 carries `code=SECURITY_BLOCKED`, `scanner=prompt_injection`, `policy=standard` (single scanner mechanism). P5 top-level `scanner`/`policy` fields are `""` at the record transport layer — authoritative values are inside `security_flag.error.details`. No other scanner/policy observed. 2,637 Baseline-0 cases total, zero transport noise.

---

## 5. Reading — what Baseline-0 actually says (no tuning, honest FAILs)

**P1 — usable but costly.** 85.9% injection recall is the strongest signal in the benchmark; 22.3% benign-mail FPR is the price. Structured injection is easiest to catch (94.4%), phase-2 attacks weakest (81.8%). Headline FAIL (`TPR < 0.9`) is recorded as-is.

**P2 — form-sensitive, not risk-sensitive.** At scale the gateway blocks off-task reads (67.6%) *more* reliably than outright dangerous actions (54.6%), while killing 62.0% of fully authorized calls. That inversion — plus a single `prompt_injection` scanner — is consistent with sensitivity to injection-shaped content rather than reasoning about dangerousness or authorization context. Headline FAIL.

**P5 — narrow trigger, broad miss.** 11.7% TPR / 0.0% FPR on memory-write persistence (`memory_target=agent_long_term_memory`, `memory_operation=write`, `presentation_style=structured`). Only ~1 in 9 poison writes are stopped; normal controls never fire. Stealthy (12.5%) vs Disruptive (10.8%) and best vs worst agent (32.5% vs 5.0%) do not rescue the headline — the gateway's prompt-injection trigger barely fires on this channel. Opposite of P1/P2's high-FP pattern, same scanner. Headline FAIL at scale (smoke 18.3% was optimistic).

**Cross-cutting.** The same `prompt_injection`/`standard` mechanism produced every block in all three headline benchmarks. P1 pays in false positives, P5 pays in misses, P2 pays in both — the discriminator is not tuned to the underlying risk model per channel. Improving the numbers is LineMod's problem, not the dataset's; no dataset change is warranted by a score.

---

## 6. Scope & limitations (do not over-claim)

- **P3 excluded.** `P3 excluded from Baseline-0 due to dataset governance readiness (MCPTox: PUBLISHED / ARTIFACT AVAILABLE / LICENSE UNRESOLVED)` — not a FAIL, not a pass. No headline number exists. DCI-D_real is explicitly out-of-scope (gateway never sees implementation).
- **P4 supplementary.** P4 is `extended`/`headline_eligible=false`, not on this headline table. It carries a real finding (TELEGRAM token exposure) but is discovery-oriented and small-n — report it as a supplementary experiment, not a comparable classifier benchmark.
- **FPR precision.** P5 headline FPR is 0/12 = 0.0% (quotable); smoke 0/4 was directional. P1/P2 FPRs are comparable (benign mail vs authorized tool call — different cost models).
- **Holdout.** `p5-holdout-v1` (84=80+4), `phase1 holdout-v3` and `p4-holdout-v1` are sealed. No `baseline0-*-holdout-*` run exists in `cache/results_v3`. Any threshold/scanner iteration must re-run `eval` first, never holdout.
- **Config coupling.** `benchmark_track`, `headline_eligible` (suite AND project), `manifest_sha256`, and `fidelity` are bound into the experiment identity. Changing any of them yields a different benchmark — do not compare numbers across mismatched bindings.

---

## 7. Reproduction

```bash
# P1/P2 — Phase 1.5 v3 (headline)
python -m demotest.cli.main validate --project P1_external_instruction --target linemod --source manifest:benchmarks/manifests/phase1-standard-v3/p1.json --no-key-check
python -m demotest.cli.main run       --project P1_external_instruction --target linemod --source manifest:benchmarks/manifests/phase1-standard-v3/p1.json --run-version baseline0-p1-standard-v3 --gap 0.5 --max-attempts 6
python -m demotest.cli.main analyze   --project P1_external_instruction --target linemod --source manifest:benchmarks/manifests/phase1-standard-v3/p1.json --run-version baseline0-p1-standard-v3
# same for P2_tool_action / phase1-standard-v3/p2.json / baseline0-p2-standard-v3

# P5 — ASB 420 frozen
python -m demotest.cli.main validate --project P5_memory_write --target linemod --source manifest:benchmarks/manifests/p5-standard-v1/p5.json --no-key-check
python -m demotest.cli.main run       --project P5_memory_write --target linemod --source manifest:benchmarks/manifests/p5-standard-v1/p5.json --run-version baseline0-p5-standard-v1 --gap 0.5 --max-attempts 6
python -m demotest.cli.main analyze   --project P5_memory_write --target linemod --source manifest:benchmarks/manifests/p5-standard-v1/p5.json --run-version baseline0-p5-standard-v1
```

Raw records: `cache/results_v3/<project>/linemod/baseline0-*-standard-*/` (`*.jsonl`, `_run_meta.json` — gitignored). Committed evidence: `docs/results/BASELINE0_SMOKE_P1P2_V3.md`, `docs/results/BASELINE0_STANDARD_P1P2_V3.md`, `docs/results/BASELINE0_SMOKE_P5_V3.md`, `docs/results/BASELINE0_STANDARD_P5_V3.md` + this report.

---

## 8. Next gates

Baseline-0 engineering is **STOP**. Holdout stays sealed. The next phase is paper/report analysis, not a new run or a LineMod tuning loop. If LineMod iterates on scanner/threshold, the rerun order is: `eval` (never `holdout` first) → new report → holdout only on final acceptance.
