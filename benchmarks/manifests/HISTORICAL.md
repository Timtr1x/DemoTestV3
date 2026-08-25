# HISTORICAL / DEPRECATED 清单目录

这些目录按**字节原样**保留，以便基于它们产生的历史结果仍可复现。不得重建、扩展或编辑。

| 目录 | 状态 | 原因 |
|---|---|---|
| `smoke-v1/` | DEPRECATED | P1 清单中包含已废弃的 AgentDojo **P1 tool_result 投影**（已在修复轮次 P0-2 中移除：默认注入向量为环境内容，而非攻击者载荷）。 |
| `phase1-standard-v1/` | DEPRECATED | 同上，已废弃的 AgentDojo P1 tool_result 投影混入了 `P1_external_instruction`。 |
| `phase1-full-v1/` | DEPRECATED | 同上。 |
| `holdout-v1/` | DEPRECATED | 同上。 |

已废弃的投影意味着这些清单所评估的通道（P1 tool_result）已不再属于 DemoTest 当前定义；其真值早于现有 adapter 语义。请勿基于它们运行新的基线。

## 现行谱系

- `*-v2/`（`smoke-v2`、`phase1-standard-v2`、`phase1-full-v2`、`holdout-v2`）—— 作为历史产物保留；严格复现需沿用原始 adapter 谱系（P1 = 仅 LLMail，P2 = 按 adapter 1.1.x 投影的 AgentDojo tool_call BLOCK 侧）。已被 v3 取代（P2 补充了 ALLOW 对照 + 上下文感知的授权判定）。
- `*-v3/`（`smoke-v3`、`phase1-standard-v3`、`phase1-full-v3`、`holdout-v3`）—— 现行套件（Phase 1.5）：P2 携带官方 BLOCK + ALLOW 真值（`ground_truth_kind = injection_attack | user_authorized`，BLOCK 用例带 `attack_step_class`），可同时评估危险工具调用 TPR **与**已授权工具调用 FPR。
- `p4-*` / `phase2-*` — P4 凭证流套件（synthetic = Extended / 框架验证；`p4-core-bridge-v1` 为真实冻结种子，core / non-headline）。
