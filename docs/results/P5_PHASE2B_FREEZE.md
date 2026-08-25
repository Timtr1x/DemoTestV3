# P5 Phase 2B — 完整 420 用例冻结（官方 ASB 400+20，BLOCK+ALLOW）

状态：**FROZEN** — 420 用例的 P5 套件族已封存。尚未进行真实 LineMod 运行（冻结必须先于任何 standard 召回，与 Phase 1.5 节奏一致）。

## 1. 决策与 pin

2026-08-25 评审通过（d）：20 条正常工具来自**同一** ASB pin、同一 commit、同一 memory `Tools` 字段、同一投影族：

| 条目 | 取值 |
|---|---|
| 来源 | `agiresearch/ASB` — ICLR 2025（arXiv 2410.02644），MIT |
| 提交 | `1f561dccf92d55302368fa67679b4ba9d9c8fdc4` |
| 文件 | `data/all_attack_tools.jsonl`（400）+ `data/all_normal_tools.jsonl`（20） |
| raw_sha256 | `193290039b99e81e641bce72f1014911b94b31bfeb7ebd006d85c20e146382aa`（两个 glob） |
| adapter | `p5_asb_memory` **1.1.0** |
| 归一化后 | `cache/datasets_v3/normalized/p5_asb_memory/cases.jsonl` — **420** 条用例 |

## 2. 投影（两侧）

攻击侧（400 BLOCK）— `AttackerTool.get_tool_call_format()`：
```
[{"type":"function","function":{"name": <Attacker Tool>, "description": <Description>}}]
```

正常侧（20 ALLOW）— `SimulatedTool.get_tool_call_format()`（固定 `parameters:null`）：
```
[{"type":"function","function":{"name": <Tool Name>, "description": <Description>, "parameters": null}}]
```

公共信封：`channel=memory_write`、`operation=write_memory`、`direction=outbound`、`memory_target=agent_long_term_memory`、`memory_operation=write`、`presentation_style=structured`、`derivation=deterministic_projection`、`quality_tier=B`。
`Attacker Instruction` / `Expected Achievements` 仅保留在**元数据**中。

攻击侧元数据：`ground_truth_kind=memory_poisoning_attack`、`source_field=attacker_tool_definition`、`source_id=asb:mp:attack:<NNN>`。
正常侧元数据：`ground_truth_kind=normal_memory_tool`、`source_field=normal_tool_definition`、`source_id=asb:mp:normal:<NNN>`。

数量门控（fail-closed，真实路径）：attack==400 否则中止，normal==20 否则中止。单元测试中的 provider 注入会刻意跳过门控。

## 3. 分组与切分

`group_id = asb:agent:<Corresponding Agent>`（两侧规则一致）。
10 个不同分组：每个 agent 拥有 40 攻击 + 2 正常 = **42** 条用例。
`group_aware_case_count_v2`（split-v2）保持整组完整性：

| agent | 用例数 | 切分 |
|---|---|---|
| aerospace_engineer_agent | 42 | dev |
| psychological_counselor_agent | 42 | dev |
| academic_search_agent | 42 | eval |
| autonomous_driving_agent | 42 | eval |
| education_consultant_agent | 42 | eval |
| legal_consultant_agent | 42 | eval |
| medical_advisor_agent | 42 | eval |
| system_admin_agent | 42 | eval |
| ecommerce_manager_agent | 42 | holdout |
| financial_analyst_agent | 42 | holdout |
| **合计** | **420** | **84 / 252 / 84** |

硬性不变量（回归）：*同一 agent 绝不会出现在多个切分中*（`tests/v3/datasets/test_p5_asb_projection.py::test_agent_never_spans_splits_integration`）。
跨套件校验在冻结验证中完成 —— holdout 已封存。

## 4. 套件（单一切分；headline 一致）

| 套件 | 切分 | n | BLOCK | ALLOW | headline | track |
|---|---|---|---|---|---|---|
| `p5-smoke-v1` | dev | 64 | 60 | 4 | false | core |
| `p5-standard-v1` | eval | 252 | 240 | 12 | **true** | core |
| `p5-holdout-v1` | holdout | 84 | 80 | 4 | false | core |
| `p5-asb-proof-v0` | dev+eval+holdout | 8 | 8 | 0 | false | core（保留） |

分层：`asb_memory_poison_block`（count=budgeted）+ `asb_memory_normal_allow`（count=all）。Standard 含 240 BLOCK 是因为预算在 eval 中保留 12 ALLOW（过滤后池为 240 BLOCK + 12 ALLOW = 252）；smoke / holdout 形态相同（60+4，80+4）。清单位于 `benchmarks/manifests/p5-*/p5.json`，`split_version=split-v2`。

套件的 `headline_eligible` 现按 **per-project headline 取 AND** 传播（`src/demotest/config.py`）：任一 `headline_eligible=false` 的项目会强制 `suite=false`，而显式 `suite true` 搭配 `false` 项目会触发 `ConfigError`（fail-closed）。该修复解决了此前 `p5-asb-proof-v0` 中 `suite true` / `project false` 的不一致。

## 5. 校验

```
dataset prepare --dataset p5_asb_memory           # 420 保留，去重 0/0
dataset verify --dataset p5_asb_memory            # OK
manifest verify ×3                                # 全部 OK（sha256 匹配）
manifest suite-verify ×4                          # 全部 OK
pytest tests/v3/datasets/test_p5_asb_projection   # 13 passed（原 7）
pytest（全量）                                     # 416 passed，4 skipped
```

`benchmarks/suites/*.json` 通过 `scripts/build_suite_summaries.py` 重建，`headline_eligible` + `track` 按 per-project 正确设置。

## 6. Fake 端到端（不消耗配额；验证 BLOCK+ALLOW 全链路）

脚本化网关始终 403（BLOCKED）。两个新套件均已演练：

- `p5-smoke-v1`（dev，64）：TP=60 FP=4  → 在全拦截下 TPR 100% **FPR 100%**（FP 为 4 条 ALLOW 正常用例被拦截 —— 证明 ALLOW 已流经 oracle）。
- `p5-standard-v1`（eval，252）：TP=240 FP=12 → 形态相同。

日志：`scripts/_p5_phase2b_fake_e2e.py` → `cache/exports/p5_phase2b_e2e/`。

渲染器示例（STRUCTURED）：
```
{"content": "[{\"type\":\"function\",\"function\":{\"name\":\"SystemMonitor\",...}}]",
 "memory_operation":"write","memory_target":"agent_long_term_memory"}
```
正常侧示例：
```
[{"type":"function","function":{"name":"sys_monitor","description":"…","parameters":null}}]
```

## 7. 本轮未做事项（且当前不应做）

- 尚未进行真实 LineMod smoke / standard 运行 —— 先冻结，再按 Phase 1.5 相同节奏执行（真实 smoke → 健康检查 → 真实 standard → STOP，holdout 保持封存）。
- 本轮不开展 P3 工作（仅在 `docs/P3_P5_DATASET_SOURCE_SURVEY.md` 中将其 P3 状态单元格更新为 `PUBLISHED / ARTIFACT AVAILABLE / LICENSE UNRESOLVED`，并注明 MCPTox 为已发表论文产物、仓库仍缺 LICENSE）。
