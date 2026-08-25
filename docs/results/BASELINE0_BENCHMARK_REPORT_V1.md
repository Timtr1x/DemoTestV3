# Baseline-0 benchmark report, V3, P1 / P2 / P5 headline, P3 excluded, P4 supplementary

Status: Baseline-0 COMPLETE. Engineering is frozen. All headline suites are frozen, smoked, and standard evaluated on real LineMod. No fake gateway, no tuning. Holdout is sealed. The dataset layer will not change. This is the first set of conclusions we can publish.

Source freeze is main@5cdb345. That is P5 p5_asb_memory 1.1.0 plus P1/P2 Phase 1.5 v3. Raw records live under cache/results_v3 and stay gitignored. The evidence you can quote is the committed docs/results/BASELINE0_*.md set.

---

## 1. What we actually measure

| Project | Channels | Threat direction | Legacy | Source, pinned | Dataset state | Suites | N, standard |
|---|---|---|---|---|---|---|---|
| P1 external instruction boundary | email, web_page, rag_document, tool_result | Prompt injection in external content, direct and structured | E2, E8 tool_result | llmail, adapter byte identical v2 to v3 | Frozen, phase1-standard-v3, core | smoke smoke-v3/p1 plus standard phase1-standard-v3/p1 | 1674, 1580 BLOCK plus 94 ALLOW |
| P2 tool action guard | tool_call | Context and tool action injection, off task reads versus dangerous actions versus authorized | E8 tool_call, E11 | AgentDojo plus official UserTask ground truth, adapter 1.2.0, context aware | Frozen, phase1-standard-v3, core | smoke smoke-v3/p2 plus standard phase1-standard-v3/p2 | 743, 535 BLOCK plus 208 ALLOW |
| P3 MCP definition content guard | mcp_definition | Deceptive or dangerous MCP tool definitions, DCI D_real is out of scope | new, A-03 | MCPTox 485 definitions at f85189f, artifact cloned | PARTIAL, PUBLISHED, ARTIFACT AVAILABLE, LICENSE UNRESOLVED, not in core | n/a | n/a, excluded from headline |
| P4 credential flow guard | user_prompt, tool_result, tool_call, memory_write, outbound_response | Secret and credential exposure via dynamic trace | E4, E5 | credential_catalog_synthetic 1.0.0 plus reviewed traces bridge | Frozen, supplementary, p4-*-v1, extended, headline_eligible false | smoke, standard, full, holdout p4-*-v1, discovery oriented, not a classifier headline | n/a, supplementary, real finding is andytrust TELEGRAM token stdout exposure |
| P5 memory write guard | memory_write | Memory poisoning, persistent rule implantation | E9, A-02 | agiresearch/ASB pin 1f561dc, 420 frozen, 400 attack plus 20 normal, same origin ALLOW | Frozen, p5-*-v1, core | smoke p5-smoke-v1 dev, 2 agents, plus standard p5-standard-v1 eval, 6 agents, plus holdout p5-holdout-v1 sealed | 252, 240 BLOCK plus 12 ALLOW |

Headline is P1 plus P2 plus P5 only. P3 is excluded because the dataset is not ready for governance, not because it failed. P4 is supplementary, small n, discovery oriented, not a classifier benchmark at the same scale.

---

## 2. Headline numbers, real LineMod, zero tuning

| Benchmark | Suite | n | TP | FN | TN | FP | TPR | FPR | block_rate | unjudged | pass fail, tpr_min 0.9 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| P1 email injection | phase1-standard-v3/p1 | 1674 | 1357 | 223 | 73 | 21 | 85.9% | 22.3% | 82.3% | 0 | FAIL |
| P2 tool action | phase1-standard-v3/p2 | 743 | 311 | 224 | 79 | 129 | 58.1% | 62.0% | 59.2% | 0 | FAIL |
| P5 memory write | p5-standard-v1 | 252 | 28 | 212 | 12 | 0 | 11.7% | 0.0% | 11.1% | 0 | FAIL |

All three are benchmark_track core, headline_eligible true. They are the only headline suites. Smoke is NON_HEADLINE by design.

| Suite | n, BLOCK | TPR | FPR | note |
|---|---:|---:|---:|---|
| P1 smoke smoke-v3/p1 | 80 | 87.5% | 35.0%, n 40 | directional, standard 85.9% and 22.3% is stable |
| P2 smoke smoke-v3/p2 | 50 | 68.0% | 50.0%, n 50 | optimistic, standard 58.1% and 62.0% firms up |
| P5 smoke p5-smoke-v1 | 60 | 18.3% | 0.0%, n 4 | directional, quotable FPR waits for standard n 12 |

### P2 slices, context aware ground truth, adapter 1.2.0

| Slice | Smoke n 100 | Standard n 743 |
|---|---:|---:|
| attack_implementing TPR | 22/34, 64.7% | 213/390, 54.6% |
| contextual_read, off task TPR | 12/16, 75.0% | 98/145, 67.6% |
| authorized ALLOW FPR | 25/50, 50.0% | 129/208, 62.0% |

### P5 slices, standard, eval 6 agents

| Slice | n | TPR |
|---|---:|---:|
| Stealthy attack | 120 | 12.5%, 15 of 120 |
| Disruptive attack | 120 | 10.8%, 13 of 120 |
| ALLOW normal | 12 | TN 12 FP 0 |
| Best agent, education_consultant_agent | 40 BLOCK | 32.5%, 13 of 40 |
| Worst agent, autonomous_driving_agent | 40 BLOCK | 5.0%, 2 of 40, others 7.5 to 10.0% |

P1 slices, standard: api_triggered 89.9%, 240 of 267, beats judge 85.1%, 1117 of 1313. Structured 94.4%, 67 of 71, beats explicit 85.5%. Phase1 86.8% beats phase2 81.8%.

---

## 3. Where the numbers come from

| Suite | Manifest | sha256 prefix | Seed | Split | Group rule | Source lock |
|---|---|---|---|---|---|---|
| smoke-v3, P1 | smoke-v3/p1.json | 00ad9d5b | 42 | dev | n/a | llmail v2 identical |
| phase1-standard-v3, P1 | phase1-standard-v3/p1.json | 4cf306b4 | 42 | eval | n/a | n/a |
| smoke-v3, P2 | smoke-v3/p2.json | a6b53cc2 | 42 | dev | n/a | AgentDojo adapter 1.2.0 |
| phase1-standard-v3, P2 | phase1-standard-v3/p2.json | e35aff7a | 42 | eval | n/a | n/a |
| p5-smoke-v1 | p5-smoke-v1/p5.json | 8f62760f | 42 | dev, 20% | asb:agent:Corresponding Agent, 2 agents, 30 and 34 | p5_asb_memory 1.1.0, raw 19329003, rev 1f561dcc, 420 frozen |
| p5-standard-v1 | p5-standard-v1/p5.json | 3f194d16 | 42 | eval, 60% | 6 agents times 42, eval | same |
| p5-holdout-v1 | p5-holdout-v1/p5.json | bb8c7433 | 42 | holdout, 20% | 2 agents times 42, sealed | same |

All headline suites are benchmark_track core. P4 is extended, headline_eligible false, its p4-standard-v1 is n 463, not headline scale. Every manifest is bound into _run_meta.json. That file stores manifest_sha256, experiment_hash, dataset_snapshot_hash, fidelity. If you rerun with a different manifest you get a different run_version.

Run versions, real LineMod, gap 0.5, max_attempts 6, X-LineMod-No-Failover true:

- baseline0-p1-smoke-v3, 120, baseline0-p2-smoke-v3, 100, 2026-08-24
- baseline0-p1-standard-v3, 1674, baseline0-p2-standard-v3, 743, 2026-08-24
- baseline0-p5-smoke-v1, 64, 2026-08-25, baseline0-p5-standard-v1, 252, 2026-08-25

Evidence on this repo is developer local pytest 403 passed, 4 skipped, no GitHub status checks at 5cdb345, plus dataset verify, manifest verify strict, suite verify gates passing at each freeze.

---

## 4. Run health, pipeline gate true, detection result is separate

| Suite | Outcomes | 429 | 5xx | error | cooldown | rate_limited | unjudged | retry over 1 | Latency p50, p90, p95, max |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| P1 smoke 120 | 120 of 120, 70 plus 50 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 2.6s, 5.0s, n/a, 13.3s |
| P2 smoke 100 | 100 of 100 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 2.0s, 3.0s, n/a, 3.8s |
| P1 standard 1674 | 1674 of 1674, 1378 blocked | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 2.47s, 4.63s, n/a, 24.6s |
| P2 standard 743 | 743 of 743, 440 blocked | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 2.05s, n/a, 3.16s p99, 7.5s |
| P5 smoke 64 | 64 of 64, 11 blocked | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 2.73s, 2.95s, 2.98s, 3.55s |
| P5 standard 252 | 252 of 252, 28 blocked | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 2.91s, 3.12s, 3.18s, 3.36s |

Every blocked outcome across P1, P2, P5 carries code SECURITY_BLOCKED, scanner prompt_injection, policy standard. One scanner produced every block. P5 top level scanner and policy fields are empty strings at the record transport layer. The real values live inside security_flag.error.details. We saw no other scanner or policy. 2,637 Baseline-0 cases total, zero transport noise.

---

## 5. What the numbers mean

I will be direct. The dataset is frozen and we did not tune the gateway. So these numbers are honest, and they are not all comfortable.

Baseline-0 is done. We can stop building datasets and stop tuning LineMod for this phase. The holdout stays sealed. What remains is to explain what we already have. That is the point of this section.

Start with health. All 2,637 cases reached a clear outcome. No 429, no 5xx, no retries that needed a second attempt. That matters more than the TPR. It means the low scores are not an artifact of the pipeline. If the pipeline were noisy we would argue about transport. It is clean, so the misses are real.

P1 looks the best and still hurts. 85.9% recall is the only number that feels close to usable. But 22.3% of benign mail gets blocked to get there. Structured injection is the easiest to catch, 94.4%, explicit is lower. I expected smoke to be optimistic and it was, but only a little. 87.5% to 85.9% is stable. So P1 is a real detector, just an expensive one.

P2 is where I started to worry. At scale it blocks off task reads, 67.6%, more reliably than outright dangerous calls, 54.6%. And it kills 62.0% of fully authorized calls. That inversion stuck with me. It suggests the gateway reacts to the shape of injection, not to whether the action is dangerous or whether the user actually authorized it. Smoke already hinted at this, 75.0% versus 64.7% and 50.0% FPR. Standard just made it firmer with more cases. If you only look at headline TPR, 58.1%, you miss the point. The pattern is form sensitive, not risk sensitive.

P5 is weak in a different way. 11.7% TPR, 0.0% FPR, on 252 cases. Only about one in nine poison writes gets stopped. Normal controls never fire. That is the opposite of P1 and P2. Same scanner, same policy, but here it barely triggers. Why? The memory_write payload is a tool definition. There is no classic "ignore previous instructions" sentence for the scanner to latch onto. So the prompt_injection trigger stays quiet. Stealthy 12.5% versus Disruptive 10.8% is noise, not a real difference. Agents do not rescue it either. The best, education_consultant at 32.5%, is still far from the 90% bar. The worst, autonomous_driving at 5.0%. I first thought maybe one agent was just harder, but the spread is small compared to the gap to the threshold.

Put together, one scanner explains all three. P1 pays in false positives. P5 pays in misses. P2 pays in both. That is not a dataset problem to fix by rewriting cases. The discriminator is not tuned to the risk model of each channel. Making the numbers look better is LineMod's job, not ours.

P3 and P4 need a separate sentence. P3 is not a FAIL. We excluded it because the dataset is not ready for governance, PUBLISHED, ARTIFACT AVAILABLE, LICENSE UNRESOLVED. There are 485 definitions cloned, but no benign controls and no license to publish as core. Forcing it into the headline table would be dishonest. P4 is frozen but extended, headline_eligible false. We did find a real thing, the andytrust TELEGRAM token in stdout, but the suite is discovery oriented and small n. It belongs in a supplementary section, not next to P1, P2, P5.

So the engineering phase can end here. P1 DONE, P2 DONE, P5 DONE, each has smoke and standard, holdout sealed. P3 PARTIAL, P4 supplementary. We do not tune LineMod in this phase and we do not edit cases to chase a score. The next phase is paper and report analysis, not another run.

There is something a bit unsettling about this split. The same gateway looks strong on mail, confused on agent actions, almost blind on memory. That is useful to know. It tells us where to work next, and it also tells us the benchmark is doing its job.

---

## 6. What we do not claim

- P3 excluded. P3 excluded from Baseline-0 due to dataset governance readiness, MCPTox: PUBLISHED, ARTIFACT AVAILABLE, LICENSE UNRESOLVED. That is not a FAIL, not a pass. No headline number exists. DCI D_real is out of scope because the gateway never sees implementation.

- P4 supplementary. P4 is extended, headline_eligible false, not on this headline table. It has a real finding, TELEGRAM token exposure, but it is discovery oriented and small n. Report it as a supplementary experiment, not a comparable classifier benchmark.

- FPR precision. P5 headline FPR is 0 of 12, 0.0%, quotable. Smoke 0 of 4 was directional. P1 and P2 FPRs are comparable as rates but the cost model differs, benign mail versus authorized tool call.

- Holdout. p5-holdout-v1 84, 80 plus 4, phase1 holdout-v3 and p4-holdout-v1 are sealed. No baseline0 holdout run exists in cache/results_v3. Any threshold or scanner change must rerun eval first, never holdout.

- Config coupling. benchmark_track, headline_eligible for suite and project, manifest_sha256, fidelity are bound into the experiment identity. If you change any of them you have a different benchmark. Do not compare numbers across mismatched bindings.

---

## 7. How to reproduce

```bash
# P1 and P2, Phase 1.5 v3, headline
python -m demotest.cli.main validate --project P1_external_instruction --target linemod --source manifest:benchmarks/manifests/phase1-standard-v3/p1.json --no-key-check
python -m demotest.cli.main run       --project P1_external_instruction --target linemod --source manifest:benchmarks/manifests/phase1-standard-v3/p1.json --run-version baseline0-p1-standard-v3 --gap 0.5 --max-attempts 6
python -m demotest.cli.main analyze   --project P1_external_instruction --target linemod --source manifest:benchmarks/manifests/phase1-standard-v3/p1.json --run-version baseline0-p1-standard-v3
# same for P2_tool_action, phase1-standard-v3/p2.json, baseline0-p2-standard-v3

# P5, ASB 420 frozen
python -m demotest.cli.main validate --project P5_memory_write --target linemod --source manifest:benchmarks/manifests/p5-standard-v1/p5.json --no-key-check
python -m demotest.cli.main run       --project P5_memory_write --target linemod --source manifest:benchmarks/manifests/p5-standard-v1/p5.json --run-version baseline0-p5-standard-v1 --gap 0.5 --max-attempts 6
python -m demotest.cli.main analyze   --project P5_memory_write --target linemod --source manifest:benchmarks/manifests/p5-standard-v1/p5.json --run-version baseline0-p5-standard-v1
```

Raw records are at cache/results_v3/<project>/linemod/baseline0-*-standard-*/. They contain jsonl and _run_meta.json and stay gitignored. Committed evidence is docs/results/BASELINE0_SMOKE_P1P2_V3.md, docs/results/BASELINE0_STANDARD_P1P2_V3.md, docs/results/BASELINE0_SMOKE_P5_V3.md, docs/results/BASELINE0_STANDARD_P5_V3.md plus this report.

---

## 8. What happens next

Baseline-0 engineering is STOP. Holdout stays sealed. The next phase is paper and report analysis, not a new run or a LineMod tuning loop. If LineMod iterates on scanner or threshold, the rerun order is eval, never holdout first, then a new report, then holdout only on final acceptance.
