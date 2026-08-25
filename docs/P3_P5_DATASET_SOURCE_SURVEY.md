# P3 / P5 数据集来源调研

日期：2026-08-25 · 基线：`main@1d09403` + Phase 2A ACCEPTED（2026-08-25）+ Phase 2B 已冻结（420）
方法：仅仓库级别校验——拉取真实 GitHub 树、原始文件与 API；通过读取文件统计记录数。未触及任何 adapter/renderer/target/runner/oracle 代码；未启动 MCP server 或 memory DB；未从论文 PDF 拷贝内容。

判定等级：**READY**（官方产物已端到端验证，现可映射至项目的 SecurityCase 通道）/ **PARTIAL**（存在真实官方产物但有缺口，需决策或上游修复）/ **NOT FOUND**（无可用官方产物）。

---

## P3 — MCP 定义内容防护（`channel=mcp_definition`，威胁 A-03）

范围提醒（F10）：P3 测试危险/欺骗性工具*定义*——gateway 仅看到描述文本。Description-Code Inconsistency（DCI）在未来 `MCPIntegrityCase` 出现前，明确不在 P3 范围内。

### 候选 1：MCPTox — 判定 **PARTIAL**（`PUBLISHED / ARTIFACT AVAILABLE / LICENSE UNRESOLVED`）

`zhiqiangwang4/MCPTox-Benchmark` — “MCPTox: A Benchmark for Tool Poisoning Attack on Real-World MCP Servers”——已**正式发表于 AAAI-26 会议论文集**（论文指向同一 `zhiqiangwang4/MCPTox-Benchmark` 仓库作为官方产物）。仓库仍为 2 个 commits、单一分支 @ `f85189f9ad12504c197c7f920ab818a40657b1fa`，“Initial commit” 2025-12-03。已通过本地克隆（`cache/probe/mcptox`，gitignored）验证——以下权威数值取代首轮基于 API-tree 截断数据的统计：

- `def_tool/1.py … def_tool/485.py`：**485 个投毒 MCP 工具定义**，为真实的 `@mcp.tool()` 装饰 Python 函数。对 `def_tool/1.py` 的抽检确认了形态：无害的函数签名 + 指示 agent 将 `~/.ssh/id_rsa` 覆盖为攻击者密钥材料的投毒 docstring，伪装为“pre-authorization check”。
- `pure_tool.json`（316 KB）：尽管名称如此，并非 benign 工具——其中包含 **485 个评估配对** `{server_name, tool_name, query, tool_content, security risk, paradigm, tool_address}`，其中 `tool_content` 为投毒描述（配对 #1 与 `def_tool/1.py` 对应）。45 个 `server_name` 值为真实社区 MCP server（FileSystem、Puppeteer、Slack、Github、SQLite、Redis、BraveSearch、EverArt 等）。
- 内置分类：`paradigm` = 投毒模板族（Template-1 ×77、Template-2 ×183、Template-3 ×225）；`security risk` = Information Manipulation ×108、Privacy Leakage ×97、Service Disruption ×73、Infrastructure Damage ×41、Credential Leakage ×40、Code Injection ×22。
- `response_all.json`（20.7 MB）= 作者的原始模型响应。
- 这恰好是 P3 通道形态：载荷完全位于 gateway 将看到的描述文本中。

阻碍 READY 的缺口：

- **无 LICENSE 文件**——正式采纳的阻碍项（仅会议论文集发表不意味着数据集许可；不得从版权推断许可）。
- README 仅 9 字节（`# AAAI26`）——无已记录的计数或标注方案；ground truth 为隐式（每个配对均为投毒用例）。
- **无 benign 对照**：全部 485 个配对均为投毒；仓库中无 clean 工具描述集合（`pure_tool.json` 名称具误导性）。ALLOW 侧必须来自**不同来源**（如 BFCL/MetaTool 等 clean 函数文档语料），这将打破我们在 P2 中使用的同源对照设计——属于决策点，而非技术阻碍。
- 单作者仓库，2 个 commits，发表前状态；revision 稳定性未知。

映射评估（若后续采纳）：`def_tool/N.py` docstring -> `SecurityCase(content=<description>, channel=MCP_DEFINITION, expected_action=block)`；`source_id=mcptox:<N>`；确定性，无 LLM。Benign/ALLOW 侧必须来自不同来源（BFCL/MetaTool 等 clean 函数文档语料），这将打破我们在 P2 中使用的同源对照设计——属于决策点，而非技术阻碍。

### 候选 2：DCI `D_real` — 判定 **NOT FOUND**

来源识别：arXiv 2606.04769 “Description-Code Inconsistency in Real-world MCP Servers: Measurement, Detection, and Security Implications”（DCIChecker）：来自 2,214 个真实 MCP server 的 19,200 个 description-code 对，9.93% 不一致。

- GitHub 搜索（`DCIChecker`、`"description-code inconsistency" MCP`、`MCP inconsistency dataset`）**未返回已发布的产物**——该 pairs 数据集未发布。
- 无论是否可用，F10 适用：不一致对的标签并非内容防护的 ground truth；gateway 永远看不到 code 侧。DCI 仍被阻挡在未来的 `MCPIntegrityCase` 之后。

### 候选 3（仅观测）：arXiv 2602.03580

“Don't believe everything you read…”——对 10,240 个真实 server 的测量（约 13% 存在显著不匹配）。为测量性研究；未发现已标注的攻击/良性 benchmark。若出现产物再复核。

### P3 后续动作

1. **不要等待 camera-ready**——论文已在会议论文集正式发表。重新审计 MCPTox 的 LICENSE + 完整性信号；若具备则锁定一个 commit。
2. 在采纳前决定 benign 对照策略（同源要求 vs. 混合来源 clean-doc 语料）。没有 benign 对照，P3 永远只能度量 TPR，将重复 Phase 1.5 刚为 P2 填补的缺口。
3. 不要合成 P3 数据。若 MCPTox 停滞，P3 保持 data-PENDING，接口就绪（如 V3_ACCEPTANCE_REPORT F10 所述）。

---

## P5 — Memory Write 防护（`channel=memory_write`，威胁 A-02，legacy E9）

先说明来源：legacy V2 manifests（`asb_memory_poison_400` 等）为模板渲染的包装，其底层文本可追溯至下述官方 ASB 文件（首条记录完全一致：`ResourceAllocationHijack` / `crypto_miner_01`）。它们本身从未是已提交的官方产物——本次调研取代该 lineage。

### 候选 1：Agent Security Bench — 判定 **READY（已冻结 420）**

`agiresearch/ASB` —— 官方，ICLR 2025（arXiv 2410.02644），**MIT**，289 stars，20 commits。**锁定于 `1f561dccf92d55302368fa67679b4ba9d9c8fdc4`**，**已冻结为 420**（400 攻击 + 20 正常）——完整冻结证据见 `docs/results/P5_PHASE2B_FREEZE.md`，攻击侧保真度规格见 `docs/results/P5_PHASE2A_PROJECTION_FIDELITY.md`。

通过直接下载、检查与已冻结管线验证：

- `data/all_attack_tools.jsonl` —— **400 条攻击工具条目**，字段 `[Attacker Tool, Attacker Instruction, Description, Attack goal, Attack Type, Corresponding Agent, Aggressive]`；adapter `AttackerTool.get_tool_call_format()` 投影为 `[{"type":"function","function":{"name":<Attacker Tool>, "description":<Description>}}]`（`expected_action=block`，`ground_truth_kind=memory_poisoning_attack`）。
- `data/all_normal_tools.jsonl` —— **20 条良性工具条目**（`[Tool Name, Description, Expected Achievements, Corresponding Agent]`）；adapter `SimulatedTool.get_tool_call_format()` 投影为 `[{"type":"function","function":{"name":<Tool Name>, "description":<Description>,"parameters":null}}]`（`expected_action=allow`，`ground_truth_kind=normal_memory_tool`；`parameters:null` 为上游权威值，非合成）。
- 两个文件共享同一 memory `Tools` 字段、同一 commit、同一确定性投影族、同一分组（`asb:agent:<Corresponding Agent>`）、同一切分约束（`group_aware_case_count_v2`，agent 永不跨切分）。
- `memory_db/*` 目录为运行时实验**输出**（按 gpt-4o-mini 运行的 Chroma DB），非源数据；poison/normal 文本源自上述 JSONL（经 `scripts/agent_attack.py` -> `--attacker_tools_path data/all_attack_tools.jsonl` 确认）。

映射评估：

- **BLOCK + ALLOW ground truth 现已均为官方且同源。** 评审决定的选项 (d) 已实现：20 个 normal 工具即为良性对照——无需第二数据集，无需合成对照。指标为 `TP/FN/TN/FP`、`TPR` 与 `FPR`（holdout 已封存：`p5-holdout-v1`）。
- Agent 分组（`asb:agent:<Corresponding Agent>`）对 holdout 隔离至关重要（10 个 agent × 42 用例；84 dev / 252 eval / 84 holdout）。回归硬关卡禁止任何 agent 跨切分。
- 虚构场景（`crypto_miner_01` 等）为 benchmark 自身的官方内容——与 AgentDojo 的虚构环境同理可接受（不同于拷贝 PDF）。
- P5 已无数据集关联缺口——下一关为**真实 LineMod smoke**（Phase 2B freeze -> 真实 smoke -> 健康检查 -> 真实 standard，holdout 封存）。

### 候选 2：AgentPoison — 判定 **不适合作主数据集**

`AI-secure/AgentPoison`（NeurIPS 2024，MIT，238 stars）。Poisoned triggers 为**生成式**（基于梯度的 trigger 优化），且 poisoning 实例未随仓库发布；基础数据集通过外部 Google Drive 获取。其范式为嵌入在检索段落中的后门 trigger——与 memory_write 内容防护正交，且 trigger 优化管线违反我们的无合成约束。仅作为 Extended/研究参考保留。

除此之外，GitHub 上针对专用“agent memory poisoning dataset”仓库的搜索未返回相关结果。

### P5 后续动作（冻结后）

1. 在 `p5-smoke-v1`（dev，64：60 BLOCK + 4 ALLOW）上进行真实 LineMod **smoke**，健康检查（TPR/FPR + 传输），随后在 `p5-standard-v1`（eval，252：240+12）上进行真实 standard。standard 后 STOP；holdout（`p5-holdout-v1`，84）保持封存。
2. P5 无需进一步数据集工作——420 冻结即为 lineage。不要重建 memory DB / 运行时；投影仅为离线文本。
3. 误差分析说明：ASB 中 `SystemMonitor` 风格的良性外观攻击仍按 GT 保持 BLOCK，并在分析中单列，不做“修复”。

---

## 汇总表

| project | candidate | artifact | license | GT | benign | verdict |
|---|---|---|---|---|---|---|
| P3 | MCPTox | 485 个投毒 MCP 工具定义 + 485 个评估配对 @ f85189f（已克隆并计数） | **缺失** | 隐式 all-block | **仓库内缺失** | PARTIAL（`PUBLISHED / ARTIFACT AVAILABLE / LICENSE UNRESOLVED`） |
| P3 | DCI D_real（arXiv 2606.04769） | 无发布 | n/a | n/a | n/a | NOT FOUND |
| P5 | ASB（agiresearch/ASB） | 400 攻击 + 20 正常（同一锁定 `1f561dc`，已冻结管线） | MIT | BLOCK+ALLOW（同源） | **同源 ALLOW（20 个正常）** | **READY（已冻结 420）** |
| P5 | AgentPoison | triggers 为生成式，数据在仓库外 | MIT | backdoor ASR | n/a | 不适合 |

推荐优先级：**P5 已冻结（420）**——下一步是在 `p5-smoke-v1`（随后 standard）上进行真实 LineMod smoke。P3 等待 MCPTox 的 LICENSE/完整性（`PUBLISHED / ARTIFACT AVAILABLE / LICENSE UNRESOLVED`）。
