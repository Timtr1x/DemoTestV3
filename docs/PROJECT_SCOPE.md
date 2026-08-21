# DemoTest V3 — Project Scope Boundary

> **DemoTest V3 is a gateway security benchmark.**
>
> **Dynamic Agent / Skill execution is optional dataset-acquisition tooling, not part of the benchmark runtime.**
>
> **Benchmark datasets must be frozen into SecurityCase-compatible artifacts before LineMod evaluation.**

This document is the single source of truth for the scope re-baseline decided on 2026-08-21. It restores the V3 acceptance report (§52 Dataset Integration) as the only roadmap and downgrades all dynamic execution infrastructure to auxiliary status.

## 1. What DemoTest measures

A single question:

> Given a real or credibly-sourced security event placed on its corresponding LLM / Agent interaction boundary, does the LineMod Gateway make the correct security decision?

The only benchmark pipeline is:

```
Dataset / Real Security Evidence
        ↓
DatasetAdapter
        ↓
SecurityCase
        ↓
CaseRenderer
        ↓
GatewayRequest
        ↓
LineMod Gateway (TargetAdapter)
        ↓
GatewayObservation
        ↓
Oracle
        ↓
CaseResult
        ↓
ResultStore / Analyzer / Report
```

No benchmark command may require Docker, SkillsMP, SkillLeakBench, candidate intake, snapshot, or credential binding.

## 2. Repository layout

```
src/demotest/
  core/              # SecurityCase, enums, ids, contracts, SecretRedactor — Core
  datasets/
    base.py, registry.py, source_lock.py, quality.py, dedup.py, manifest_builder.py — Core
    adapters/        # llmail, agentdojo, credential_catalog_synthetic, credential_dynamic_traces, legacy_v2, skillleakbench — Core (adapters)
    traces/          # CredentialTrace model + projection SecurityCase — Core
    dynamic/         # ← Optional acquisition tooling (see §3)
  renderers/         # 7 renderers + registry — Core
  targets/           # LineMod / QwenGuard + http_parser — Core
  runners/           # GatewayRunner, retry — Core
  oracles/           # block_pass, canary, composite — Core
  metrics/           # detection, leakage, grouping — Core
  analysis/          # analyzer, compare — Core
  storage/           # ResultStore — Core
  reporting/         # markdown — Core
  cli/
    validate, render, run, analyze, report, compare, dataset, manifest — Core
    dynamic          — Auxiliary (acquisition only)

config/v3/
  projects.yaml, targets.yaml, datasets.yaml, suites.yaml — Core
  datasets/*.yaml    — per-dataset projection — Core

cache/datasets_v3/
  raw/<dataset>/              — pinned raw mirrors (gitignored, not benchmark identity)
  normalized/<dataset>/       — frozen SecurityCase snapshots (produced by `dataset prepare`)
  metadata/*.lock.json        — benchmark identity (committed)

benchmarks/
  manifests/   — frozen manifests (committed)
  suites/      — suite snapshots (committed)
  frozen/datasets/<dataset_id>/
                 raw/reviews/reviewed_traces.jsonl + review_meta.json  (committed)
                 normalized/cases.jsonl + prepare.json                 (committed)

The P4 Credential Flow's frozen dataset (`credential_dynamic_traces`) lives under
`benchmarks/frozen/datasets/credential_dynamic_traces/` — NOT the gitignored
`cache/datasets_v3/`. That is what lets a fresh clone run
`validate → render → run → analyze → report` on the frozen P4 data with zero
Docker / SkillsMP / SkillLeakBench / candidate / snapshot / credential binding.
```

Rule for every future PR:

> Is this PR Benchmark Core or Dataset Acquisition? The two must not be mixed.

## 3. Auxiliary acquisition boundary

`src/demotest/datasets/dynamic/` and `src/demotest/cli/dynamic.py` are **retained and frozen**. They are not deleted, but they are not expanded.

Retained as auxiliary:

- SkillLeakBench Docker sandbox (`sandbox.py`, `skillleak_collector.py`, `schemas.py`, `parser.py`)
- SkillsMP crawler and `candidates.py` intake
- `runtime_specs` sidecar, `materialize`, `snapshot`
- `credential_bindings` source-bound profile (frozen; no further expansion)
- `review.py`, `split.py`, `agents/` (Host-side AgentDriver — Extended only)

Out of roadmap (do not implement, do not plan):

- TLS MITM / HTTPS decryption
- Node `fetch` transport interception
- Generic dependency auto-installer
- Generic Agent execution engine
- Credential-format DSL
- Full-Skill compatibility / 1000-trace scaling targets
- Automatic vulnerability discovery platform

## 4. Dataset integration roadmap (restored)

Order from the acceptance report §52:

| # | Source | Project | Artifact requirement |
|---|--------|---------|----------------------|
| 1 | LLMail-Inject | P1 | HF `microsoft/llmail-inject-challenge` @ pinned SHA |
| 2 | AgentDojo | P1 (tool_result, Extended) + P2 | github `ethz-spylab/agentdojo` @ pinned SHA |
| 3 | Credential Leakage | P4 | reviewed `DYNAMIC_TRACE` traces → `P4DatasetAdapter` → SecurityCase |
| 4 | AuthBench | P2 | **pending** — official artifact confirmation required |
| 5 | DCI `D_real` | P3 | **pending** — official artifact required; do not copy from PDF |

A dataset is accepted only when: source is real, official artifact location is known, version/revision is pinned, SHA/hash is recorded, ground truth is defined, license permits use. No synthetic/template/LLM expansion to pad counts.

## 5. P4 first-version acceptance

- ≥20 human-reviewed real dynamic traces, ideally 20–100. No hard minimum of 1000.
- Every Core trace must satisfy: `source_real && dynamic_execution_real && fake_credential_confirmed && marker_observed && sink_confirmed && gateway_projection_valid && expected_action_valid` (the 7 review gates, fail-closed).
- Traces become benchmark data only after `review-apply` → `freeze-reviewed` → `P4DatasetAdapter` → `SecurityCase`. A frozen `p4_credential_flow_v1` artifact must run through `validate → render → run → analyze → report` without Docker/SkillsMP/SkillLeakBench/binding.
- The frozen artifact is **committed** (`benchmarks/frozen/datasets/credential_dynamic_traces/`), so the benchmark never depends on the acquisition sidecar.
- Headline gate: until the dataset holds ≥20 real reviewed traces, a P4 manifest stays `benchmark_track=core, headline_eligible=false`. `p4-core-bridge-v1` (1 real trace) is exactly that — core track, not headline. The formal headline P4 suite is created only after the ≥20-trace acceptance.
- The synthetic catalog suite (`credential_catalog_synthetic`, quality C) is **Extended / framework-validation only** — it is never the real P4 headline and does not count toward the ≥20 real-traces target.

## 6. References

- `docs/V3_ACCEPTANCE_REPORT.md` — Phase 0 baseline; §52 is the only roadmap.
- `docs/P1-P5_MAPPING.md` — channel/project/legacy mapping and F8–F13 boundaries.
- `docs/P4_DYNAMIC_DATA_GUIDE.md`, `docs/P4_DYNAMIC_ROADMAP.md` — auxiliary acquisition guides (frozen; not benchmark spec).
