# P4 投影证明 — Production-Schema Compatibility Proof（Phase 4D Synthetic Gate）

> **日期**：2026-08-25 · **状态**：`P4 Phase 4D Synthetic Projection Gate — COMPLETE`（`scripts/_p4_projection_proof.py` 本地 13 例通过，无 Docker、无 LineMod、无真实 secret）
> **验收定性**：Production-schema compatibility proof — 证明“若未来得到满足真实 `provenance contract` 的 `CredentialTrace`，现有 `Adapter/Renderer` 能正确处理”；**不证明**已拥有 SkillLeakBench 真实 `DIRECT` trace
> **前置**：`docs/P4_VISIBILITY_CONTRACT.md`（映射与三桶）· `docs/P4_SANITIZATION_CONTRACT.md`（`P4CANARY_<sha256(issue_id)[:16]>` 一对一替换）· `docs/P4_FROZEN_BOUNDARY.md`（冻结边界）
> **范围**：`reviewed_traces-like CredentialTrace → SecurityCase → credential_flow/v1` 的**投影保真**与**渲染隔离**，以及 `DIRECT/PROJECTED` 门控；SkillLeakBench 公开 `1,708 issues` 为 `sanitized 7 列`（无 `sink/snippet/span`），本证明的 `13` 例均为**合成 `P4CANARY` 样本**（`DYNAMIC_TRACE / dynamic_confirmed / trace_hash` 为 `fabricated placeholder`），不得解释为真实 `A 级 provenance`；真实 `DIRECT` 样本待 `Phase 4E Real Evidence Recovery` 后进入 Full Core

---

## 1. 证明目标

- `CredentialTrace.payload` 中的 Gateway 可见面内容经 `project_trace_to_case` 到 `SecurityCase` 时**逐字保留**（仅 `span` 替换为 `P4CANARY`，不掺入 `query/risk/paradigm/sink` 等元数据）；
- `credential_flow/v1` 的 `RAW / STRUCTURED / LABELED` 三档中 `STRUCTURED` 为 headline 的**真实传输信封**（见 `src/demotest/renderers/credential_flow.py` 与 `config/projects.yaml#P4_credential_flow primary_fidelity`），`RAW` 亦携带 `secret payload`（`tool_call` 的 `tool_arguments` 需包含 `canary`），不因标签提示网关；
- 仅 `DYNAMIC_TRACE + dynamic_confirmed + trace_hash + quality A/B` 的 `DIRECT/PROJECTED` 可投影，`NOT_VISIBLE/AMBIGUOUS`（`dynamic_confirmed==false / trace_hash 缺失`）被 adapter 硬拒绝。

---

## 2. 样本构成（12 BLOCK + 1 ALLOW = 13 例）

> 因公开产物无 `sink` 列，本证明的 `DIRECT` 样本为**合成 `P4CANARY` 构造**，用于验证投影/渲染链路而非声称 SkillLeakBench 真实 `DIRECT` 计数。

| 组 | 通道 | 可见性 | `flow_class` | 数量 | 说明 |
|---|---|---|---|---|---|
| `STDOUT/TOOL_RESULT` | `TOOL_RESULT` | `DIRECT` | `STDOUT_EXPOSURE` | 8 | `skill-stdout-1..8`，`A/original`，覆盖 `Information Exposure / Hardcoded / Credential Compromise / Defense Evasion / Remote Exploitation / Persistence` 等多 pattern |
| `TOOL_CALL` | `TOOL_CALL` | `DIRECT` | `TOOL_ARG_SECRET` | 3 | `skill-tc-1..3`，`A/original`，`tool_arguments.destination+body` 含 `canary` |
| `NETWORK sinkhole` | `TOOL_CALL` | `PROJECTED` | `NETWORK_EXFIL` | 1 | `skill-net-proj-1`，`B/deterministic_projection`，`destination http://127.0.0.1:8123/collect` 原样保留 |
| `AUTHORIZED` 对照 | `TOOL_CALL` | `DIRECT` | `AUTHORIZED_SECRET_USE` | 1 | `skill-allow-1`，`authorized_sink==true`，`ALLOW` |

每例 `credential_marker = P4CANARY_<sha256(issue_id)[:16].upper()>`（`issue_id` 逐字节 `sha256`），`payload` 首尾上下文不变，仅 `span` 为 `canary`。

---

## 3. 门控

### 3.1 投影保真

- `TOOL_RESULT`：`payload` 与 `case.tool_result / case.content` 一致，`credential_markers[0]` 即 `canary`；
- `TOOL_CALL`：`payload` 的 `canary` 落在 `case.content` 的 JSON（`tool+arguments`）与 `case.tool_arguments` 中；
- `quality/derivation`：`DIRECT → A/original`，`PROJECTED → B/deterministic_projection`，与 `config/v3/datasets/credential_dynamic_traces.yaml` 一致；
- `group_id = skill_id`（同 Skill 不跨 `dev/eval/holdout` 的前置保证）。

### 3.2 渲染隔离

- `credential_flow/v1` 的 `STRUCTURED` 不含 `STDOUT_EXPOSURE / TOOL_ARG_SECRET / scanning_rules / skill_snapshot_sha256` 等内部键；
- `RAW` 仍携带 `canary`（`tool_call` 不丢 `tool_arguments`）；
- `LABELED` 含 `[CREDENTIAL_FLOW_CHECK]` 头；
- `tool_call` / `tool_result` 的 `STRUCTURED` 均为合法 JSON 信封（`tool+arguments` / `tool+result`）。

### 3.3 负例硬拒绝

- `HARDCODE_ONLY + dynamic_confirmed==false + trace_hash 缺失` → `CredentialDynamicTracesAdapter(strict, trace_provider=[neg])` 拒绝；
- `INSECURE_STORAGE 歧义 + trace_hash 缺失` → 同样拒绝；
- `validate_provenance_block` 对 `13` 例正例无问题。

---

## 4. 运行与结果

```bash
python scripts/_p4_projection_proof.py
```

```
proof traces: 13 positives (expect 12 BLOCK + 1 ALLOW = 13)
  BLOCK 12  ALLOW 1
  channels {'TOOL_RESULT': 8, 'TOOL_CALL': 5}  sinks {'stdout': 8, 'network': 5}  skills 13 distinct
PASS: 13 cases (incl 1 ALLOW), 13 groups, 12 BLOCK
PROOF PASS — projection faithful, renderer envelope clean, gates enforced (12+1).
```

---

## 5. 定性收紧（本次评审）

- 本证明为 **production-schema compatibility proof**，不是 `Evidence / provenance proof`；
- 仅证明：`满足真实 provenance contract 的 CredentialTrace → 现有 Adapter/Renderer 能正确处理`；
- 不证明：`已拥有满足该 contract 的 SkillLeakBench trace`；
- 合成 `ALLOW` 仅验证 `Oracle` 分支可达，不作为真实 `FPR` 数据，不得计入后续 Core 的 `ALLOW` 计数。

## 6. 与契约的衔接

- 满足 `P4_VISIBILITY_CONTRACT` 的 `DIRECT/PROJECTED → Core` 与 `NOT_VISIBLE/AMBIGUOUS → 排除`；
- 满足 `P4_SANITIZATION_CONTRACT` 的 `P4CANARY` 一对一替换与“不改上下文、不扩写、真实 secret 零落地”；
- **冻结**：见 `docs/P4_FROZEN_BOUNDARY.md` — Visibility / P4CANARY / Renderer / Target / Oracle / synthetic fixture 本轮后不再改；
- 下一步唯一合法任务：`Phase 4E Real Evidence Recovery`（路径 A `private master File:Line/Snippet/span` 或路径 B 官方 `pinned pipeline` 以 `fake credential` 小范围复现“能跑且能产生 Gateway-visible marker”的 case；`≥50 real DIRECT` 可先真实 Smoke/Dev，`150–300` 足够第一版 Standard；无真实 `safe credential flow` 则保持 `TPR-only / headline_eligible=false`），不按 `issues.csv pattern` 批量生成合成 `DIRECT` 充数。

