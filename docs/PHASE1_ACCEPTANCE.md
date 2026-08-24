> **HISTORICAL — SUPERSEDED.** This document describes the Phase 1 state
> (LLMail normalized=170, AgentDojo tool_result=629 + tool_call=952,
> phase1-standard-v1=1018). The AgentDojo P1 tool_result projection has
> since been removed (P0-2), P1 is LLMail-only, and the current acceptance
> record is [PHASE1_P1P2_ACCEPTANCE_V3.md](PHASE1_P1P2_ACCEPTANCE_V3.md).
> Kept for history; do not update.

# Phase 1 Dataset Integration — Acceptance Summary

This documents what Phase 1 delivered against the two guides (Development &
Execution §0-§70, Data-Source Acquisition §1-§38), the controlled changes to the
frozen core, and the current scale vs. the guide targets.

## Controlled changes to the frozen boundary (guide §2)

Phase 1 froze `core/`, `renderers/`, `targets/`, `oracles/`, `runners/`. The only
changes were additive and backward-compatible:

* `src/demotest/core/models.py` — `SecurityCase.build()` now `pop`s `direction`
  from kwargs before forwarding (prevents a double-pass TypeError when an
  adapter passes `direction` explicitly). No field or semantics change.
* `src/demotest/core/exceptions.py` — added `DatasetSourceError` /
  `DatasetSourceDirtyError` (new dataset layer only; core untouched).
* `src/demotest/config.py`, `cases.py`, `paths.py`, `cli/main.py` — additive:
  new dataset/suite config loaders, the `manifest:<path>` case source, and the
  `dataset`/`manifest` CLI subcommands. Existing `validate`/`render`/`run`/
  `analyze` paths unchanged.

No existing run semantics were altered. V2 regression contract test still
passes byte-identical.

## What was delivered

**Pipeline (committed code):** source_lock → adapters (llmail, agentdojo) →
quality/dedup (3-level) → sampler (hash + group-aware split) → manifest_builder
→ CLI (acquire/verify-source/prepare/verify/stats/hash, manifest build/verify)
→ 47 offline tests.

**Frozen artifacts (committed):**
* Source locks: `cache/datasets_v3/metadata/{llmail,agentdojo}.lock.json`
  (revision + raw_sha256 + license MIT + adapter version).
* Manifests: `benchmarks/manifests/{smoke-v1,phase1-standard-v1,phase1-full-v1,holdout-v1}/{p1,p2}.json`
  with self-stable `manifest_sha256`.
* Suite summaries: `benchmarks/suites/{smoke-v1,phase1-standard-v1,phase1-full-v1}.json`.
* HOLDOUT access policy: `benchmarks/manifests/holdout-v1/ACCESS_POLICY.md`.

**Raw data (gitignored, reproducible from locks):** LLMail (8 pinned files,
448 MB phase1) and AgentDojo (pinned clone, clean tree).

## Source provenance

| Dataset   | Provider   | Revision                  | raw_sha256 (prefix) | License |
|-----------|-----------|---------------------------|---------------------|---------|
| llmail    | Microsoft | `1063bdf01ec8…` (HF SHA)  | a223abaf159dfa6e…   | MIT     |
| agentdojo | ETH Zürich| `089ed468cf3e…` (git SHA) | 57726b746c7df67c…   | MIT     |

Both are full commit SHAs, never `main`/`latest`. AgentDojo `benchmark_version: v1`.

## Real-data scale (after dedup)

| Dataset   | Normalized | By channel                          |
|-----------|-----------|-------------------------------------|
| llmail    | 170       | email 170 (10 attack + 160 benign)  |
| agentdojo | 1581      | tool_result 629 (P1) + tool_call 952 (P2) |

LLMail is bounded by `max_attack_per_phase` in this Phase 1 dev build; the full
labelled_unique pool (160k+) is available for a larger standard run. AgentDojo
is the complete v1 projection (97 user tasks × 27 injection tasks, deduped).

## Frozen manifests

| Suite                | Split       | P1   | P2   | Total |
|----------------------|-------------|------|------|-------|
| smoke-v1             | dev         | 100  | 100  | 200   |
| phase1-standard-v1   | eval        | 478  | 540  | 1018  |
| phase1-full-v1       | eval+holdout| 641  | 773  | 1414  |
| holdout-v1           | holdout     | 163  | 187  | 350   |

Phase 1 standard is 1018 cases (below the guide's ~2200-2350). Per guide §70
("宁可少，不要凑" — better fewer than padded), this is the honest real-data
count; P2 is full coverage of AgentDojo v1. The gap to ~11,600 closes in
Phase 2/3 (Credential / AuthBench / MCP / Memory).

## Four-gate runtime verification (guide §55)

Ran against the smoke suite via the real CLI + a fake LineMod target:

1. **validate** — P1 (100) + P2 (100) pass project↔channel↔case consistency.
2. **render** — email/RAW, tool_result/STRUCTURED, tool_call/STRUCTURED all
   render with correct fidelity and no payload loss.
3. **run --dry-run** — P1 (18 email + 82 tool_result) + P2 (100 tool_call)
   render + serialize without API calls.
4. **fake-target run** — P1 100/100 oracle-correct (18 TN + 82 TP), P2 100/100
   (100 TP), No-Failover header sent, response_text stored, SecretRedactor wired.

## P2 Phase 1 coverage statement (guide §59)

P2 Phase 1 is **AgentDojo-only** and must be labeled "P2 Phase 1 Partial
Coverage" — it is not the full Tool Authorization Benchmark. AuthBench
(Phase 3) is required to upgrade P2 to full coverage.

## Known limitations

* `_scenario_of` (LLMail) and `presentation_style` are heuristic, not exact
  `scenarios.json` mappings — acceptable for Phase 1 stratification; documented
  as approximate.
* LLMail standard run is bounded (`max_attack_per_phase`); a full-pool run is a
  config change, not a code change.
* A real LineMod `Baseline-0` run (guide §60) is not included here — it requires
  live API credentials and is the next operational step after this acceptance.
