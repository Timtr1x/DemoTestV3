> **历史归档 — 已废弃。** 本文档描述 Phase 1 阶段的状态
> （LLMail normalized=170、AgentDojo tool_result=629 + tool_call=952、
> phase1-standard-v1=1018）。AgentDojo P1 tool_result 投影已在之后被移除（P0-2），P1 现仅包含 LLMail，当前验收记录请见 [PHASE1_P1P2_ACCEPTANCE_V3.md](PHASE1_P1P2_ACCEPTANCE_V3.md)。
> 仅作历史保留，请勿更新。

# Phase 1 数据集集成 — 验收总结

本文档说明 Phase 1 相对于两份指南（开发与执行 §0-§70、数据源获取 §1-§38）的交付情况、对冻结核心的受控变更，以及当前规模与指南目标的对比。

## 对冻结边界的受控变更（指南 §2）

Phase 1 冻结了 `core/`、`renderers/`、`targets/`、`oracles/`、`runners/`。仅有的变更均为增量式且向后兼容：

* `src/demotest/core/models.py` — `SecurityCase.build()` 现会在转发前从 kwargs 中 `pop` 掉 `direction`（避免 adapter 显式传入 `direction` 时出现重复传参的 TypeError）。无字段或语义变更。
* `src/demotest/core/exceptions.py` — 新增 `DatasetSourceError` / `DatasetSourceDirtyError`（仅新增的数据集层使用；core 未动）。
* `src/demotest/config.py`、`cases.py`、`paths.py`、`cli/main.py` — 增量新增：数据集/套件配置加载器、`manifest:<path>` 用例来源，以及 `dataset`/`manifest` CLI 子命令。既有的 `validate`/`render`/`run`/`analyze` 路径保持不变。

未改变任何既有运行语义。V2 回归契约测试仍以字节一致（byte-identical）通过。

## 已交付内容

**流水线（已提交代码）：** source_lock → adapters（llmail、agentdojo）→ quality/dedup（三级）→ sampler（hash + 组感知切分）→ manifest_builder → CLI（acquire/verify-source/prepare/verify/stats/hash、manifest build/verify）→ 47 项离线测试。

**已冻结产物（已提交）：**
* Source locks：`cache/datasets_v3/metadata/{llmail,agentdojo}.lock.json`（revision + raw_sha256 + license MIT + adapter version）。
* Manifests：`benchmarks/manifests/{smoke-v1,phase1-standard-v1,phase1-full-v1,holdout-v1}/{p1,p2}.json`，带有自稳定的 `manifest_sha256`。
* 套件摘要：`benchmarks/suites/{smoke-v1,phase1-standard-v1,phase1-full-v1}.json`。
* HOLDOUT 访问策略：`benchmarks/manifests/holdout-v1/ACCESS_POLICY.md`。

**原始数据（已 gitignore，通过 locks 可复现）：** LLMail（8 个固定文件，phase1 共 448 MB）与 AgentDojo（固定 clone，干净工作树）。

## 来源溯源

| 数据集 | 提供方 | Revision | raw_sha256（前缀） | License |
|-----------|-----------|---------------------------|---------------------|---------|
| llmail | Microsoft | `1063bdf01ec8…` (HF SHA) | a223abaf159dfa6e… | MIT |
| agentdojo | ETH Zürich | `089ed468cf3e…` (git SHA) | 57726b746c7df67c… | MIT |

两者均为完整 commit SHA，绝不使用 `main`/`latest`。AgentDojo `benchmark_version: v1`。

## 真实数据规模（去重后）

| 数据集 | 归一化后 | 按通道 |
|-----------|-----------|-------------------------------------|
| llmail | 170 | email 170（10 attack + 160 benign） |
| agentdojo | 1581 | tool_result 629（P1）+ tool_call 952（P2） |

LLMail 在此 Phase 1 开发构建中受 `max_attack_per_phase` 限制；完整 labelled_unique 池（16 万+）可用于更大规模的 standard 运行。AgentDojo 为 v1 的完整投影（97 个 user tasks × 27 个 injection tasks，去重后）。

## 已冻结清单（Manifests）

| 套件 | 切分 | P1 | P2 | 总计 |
|----------------------|-------------|------|------|-------|
| smoke-v1 | dev | 100 | 100 | 200 |
| phase1-standard-v1 | eval | 478 | 540 | 1018 |
| phase1-full-v1 | eval+holdout | 641 | 773 | 1414 |
| holdout-v1 | holdout | 163 | 187 | 350 |

Phase 1 standard 共 1018 条用例（低于指南约 2200-2350 的目标）。根据指南 §70（“宁可少，不要凑”），这是真实数据的诚实统计；P2 已覆盖 AgentDojo v1 的全部。与约 11,600 的差距将在 Phase 2/3（Credential / AuthBench / MCP / Memory）中补齐。

## 四道关卡运行时验证（指南 §55）

通过真实 CLI + 仿真 LineMod 目标对 smoke 套件执行验证：

1. **validate** — P1（100）+ P2（100）通过 project↔channel↔case 一致性校验。
2. **render** — email/RAW、tool_result/STRUCTURED、tool_call/STRUCTURED 均按正确保真度渲染，且无 payload 丢失。
3. **run --dry-run** — P1（18 email + 82 tool_result）+ P2（100 tool_call）完成渲染与序列化，未发起 API 调用。
4. **fake-target run** — P1 100/100 oracle 判定正确（18 TN + 82 TP），P2 100/100（100 TP），已发送 No-Failover 头，response_text 已存储，SecretRedactor 已接入。

## P2 Phase 1 覆盖度声明（指南 §59）

P2 Phase 1 **仅包含 AgentDojo**，必须标注为“P2 Phase 1 部分覆盖”——并非完整的 Tool Authorization Benchmark。需接入 AuthBench（Phase 3）后，P2 才能升级为完整覆盖。

## 已知限制

* `_scenario_of`（LLMail）与 `presentation_style` 为启发式推断，并非对 `scenarios.json` 的精确映射——作为 Phase 1 的分层依据可接受，已文档化为近似值。
* LLMail standard 运行受限（`max_attack_per_phase`）；全量池运行仅需改配置，无需改代码。
* 真实 LineMod `Baseline-0` 运行（指南 §60）未包含在此——需要在线 API 凭证，是本次验收后的下一步操作。
