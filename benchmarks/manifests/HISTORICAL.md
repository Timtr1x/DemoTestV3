# HISTORICAL / DEPRECATED manifest directories

These directories are kept **byte-for-byte** so results produced from them
remain reproducible. They must NOT be rebuilt, extended, or edited.

| directory | status | why |
|---|---|---|
| `smoke-v1/` | DEPRECATED | P1 manifest contains the retired AgentDojo **P1 tool_result projection** (removed by fix round P0-2: default injection vectors are environment content, not attacker payloads). |
| `phase1-standard-v1/` | DEPRECATED | same retired AgentDojo P1 tool_result projection mixed into `P1_external_instruction`. |
| `phase1-full-v1/` | DEPRECATED | same as above. |
| `holdout-v1/` | DEPRECATED | same as above. |

The retired projection means these manifests score a channel (P1
tool_result) that DemoTest no longer defines; their ground truth predates
the current adapter semantics. Do not run new baselines against them.

## Current lineage

- `*-v2/` (`smoke-v2`, `phase1-standard-v2`, `phase1-full-v2`, `holdout-v2`)
  — historical artifacts preserved; original adapter lineage required for
  strict reproduction (P1 = LLMail only, P2 = AgentDojo tool_call BLOCK side
  as projected by adapter 1.1.x). Superseded by v3 (P2 ALLOW controls +
  context-aware authorization).
- `*-v3/` (`smoke-v3`, `phase1-standard-v3`, `phase1-full-v3`, `holdout-v3`)
  — active suites (Phase 1.5): P2 carries official BLOCK + ALLOW ground truth
  (`ground_truth_kind = injection_attack | user_authorized`, with
  `attack_step_class` on BLOCK cases), enabling Dangerous Tool Call TPR **and**
  Authorized Tool Call FPR.
- `p4-*` / `phase2-*` — P4 credential-flow suites (synthetic = Extended /
  framework-validation; `p4-core-bridge-v1` is the real frozen seed,
  core/non-headline).
