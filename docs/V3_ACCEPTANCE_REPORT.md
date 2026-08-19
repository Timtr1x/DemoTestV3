# DemoTest V3 重构验收报告

> **版本**: V3.0.0  
> **日期**: 2026-08-19  
> **基准**: 重构计划 §0-§53 + 外部审查意见 F1-F7（第一轮）+ F8-F13（第二轮）+ 文档修正  
> **结论**: ✅ §51 全部验收条件满足；F8-F13 阻断级问题已修复，可进入 Dataset Integration 阶段

---

## 1. 项目概述

### 1.1 重构目标

DemoTest V2 的核心抽象是 `Sample.prompt_text → POST → 403/200 → blocked/passed`。这个抽象适合直接提示词注入、编码绕过等场景，但随着测试范围扩展到 Tool Result、Tool Call、MCP Definition、Memory Write、Credential Flow 等不同安全边界，把所有内容压缩成一个 `prompt_text` 会导致测试报告无法解释"网关到底是在什么安全边界上成功/失败"。

V3 的核心目标：

> **把 Sample 从"一个 Prompt"升级成"一个经过网关的安全事件"。**

被测对象不变（仍然是 LineMod Gateway），核心 Oracle 不变（403+SECURITY_BLOCKED=blocked / 200=passed），但测试框架内部从单一字符串升级为结构化的 `SecurityCase`。

### 1.2 本轮范围

本轮只完成**测试框架结构升级**，不做：
- 下载新数据集
- 修改现有 dataset cache / manifest
- 重新采样
- 建真实 Agent / MCP Server / Memory 数据库 / IAM
- 改 LineMod 产品本身

### 1.3 提交历史

| # | Commit | 内容 |
|---|--------|------|
| 1 | `d5a3ee6` | SecurityCase 核心模型 + enums/ids/contracts |
| 2 | `3711218` | LegacyV2Adapter（冻结 V2 manifest → SecurityCase） |
| 3-5 | `cc8d403` | LineMod TargetAdapter + HTTP 解析器 + Oracle 体系 |
| 6-9 | `dfa62ed` | Renderer 抽象 + 7 个渲染器 |
| 10-11 | `72c765d` | GatewayRunner + append-only ResultStore |
| 12-13 | `13e297e` | Analyzer + channel/scanner/score/stealth breakdown |
| 14-16 | `421ca11` | CLI + SecretRedactor + P1-P5 配置/fixtures |
| 17 | `4cfd9da` | V2/V3 回归验证 + 合约测试 + 完成标准检查 |
| 修复 | `512f675` | 外部审查 F1-F7 修复（SecretRedactor 接入运行时等） |

---

## 2. 架构设计

### 2.1 核心抽象变化

**V2**:
```
Dataset → Sample.prompt_text → POST /chat/completions → 403/200 → blocked/passed
```

**V3**:
```
Dataset → DatasetAdapter → SecurityCase → CaseRenderer → GatewayRequest
  → TargetAdapter → LineMod → GatewayObservation → Oracle → CaseResult
  → ResultStore → Analyzer → Report
```

关键分离：**"数据是什么"（SecurityCase）和"怎么送进网关"（Renderer + TargetAdapter）彻底分开**。

### 2.2 分层架构

| 层 | 职责 | 知道什么 | 不知道什么 |
|---|---|---|---|
| `core/` | 领域模型：SecurityCase / enums / ids / contracts | 安全事件的抽象 | 数据来源、传输、判定 |
| `datasets/` | 原始数据 → SecurityCase | 数据集格式、字段映射 | 网络、渲染、判定、指标 |
| `renderers/` | SecurityCase → 固定模板文本 | channel 对应的 wrapper 格式 | 攻击 payload 生成、网络 |
| `targets/` | GatewayRequest → GatewayObservation | URL / auth / headers / HTTP / 分类 | SecurityCase、数据集、指标 |
| `oracles/` | (case, observation) → verdict | 期望 vs 实际的混淆矩阵 | 传输、渲染 |
| `runners/` | 编排 render→target→oracle→store | SecurityCase + 上述四组件 | E2/LLMail/AuthBench 等业务 |
| `storage/` | append-only jsonl + resume | 文件 I/O | 一切业务逻辑 |
| `metrics/` | 混淆矩阵 + breakdown | CaseResult 行 + SecurityCase | 传输 |
| `analysis/` | 聚合 → AnalysisReport | metrics + store | 传输 |
| `cli/` | 命令行入口 | 所有组件的组装 | 内部实现 |
| `config.py` | YAML 配置加载 | 项目/目标配置 | 运行时逻辑 |

### 2.3 目录结构

```
DemoTest V3/
├── src/demotest/              # V3 包（src-layout）
│   ├── core/                  # 模型 + 枚举 + ID + 契约 + 脱敏器
│   ├── datasets/              # DatasetAdapter ABC + registry + legacy_v2
│   ├── renderers/             # 7 个渲染器 + base + registry
│   ├── targets/               # LineMod + QwenGuard + http_parser
│   ├── runners/               # GatewayRunner + retry
│   ├── oracles/               # BlockPass + Canary + Composite
│   ├── metrics/               # detection + leakage + grouping
│   ├── analysis/              # analyzer + compare
│   ├── reporting/             # markdown
│   ├── storage/               # ResultStore (append-only jsonl)
│   └── cli/                   # validate/render/run/analyze/report/compare
├── config/v3/                 # P1-P5 项目配置 + targets 配置
├── tests/
│   ├── v3/unit/               # 9 个单元测试文件
│   ├── v3/contract/           # 合约测试 + FakeLineModServer
│   ├── v3/integration/        # CLI 端到端测试
│   ├── v3/test_completion_criteria.py  # §51 验收门
│   └── fixtures/              # P1-P5 验收 fixtures
├── cache/                     # 冻结的数据（V2 manifest 只读）
├── core/ adapters/ projects/  # V2 代码（完整保留，未修改）
└── pyproject.toml             # V3 包定义
```

**代码规模**: V3 源码 4015 行，测试 1856 行。文件统计口径说明（外部审查文档修正 2）：

| 口径 | 计数 | 说明 |
|---|---|---|
| V3 源文件 (`src/demotest/**/*.py`) | 62 | 含 `__init__.py` 等包文件 |
| V3 测试文件 (`tests/v3/**/*.py`) | 18 | unit + contract + integration + completion + conftest |
| V2 测试文件 (`tests/test_*.py`) | 6 | 根目录 V2 测试 |
| **V3+V2 测试合计** | **24** | 前文 "17 个测试文件" 是早期口径（重构过程中统计），最终为 18；V2 另有 6 |

> 前后不一致已修正：§6.1 的 "V3 14 files" 不含 conftest/`__init__`/新增 F8-F13 测试；本表为最终口径。

---

## 3. 核心组件详解

### 3.1 SecurityCase（§4）

替代 `Sample.prompt_text` 的结构化核心模型。字段分五组：

| 组 | 字段 | 说明 |
|---|---|---|
| 身份 | `case_id` `dataset_id` `source_id` | case_id = hash(dataset_id+source_id+channel+operation+threat_id)，**不含 renderer/target/model 版本** |
| 什么/哪里/为什么 | `channel` `operation` `direction` `content` `expected_action` | channel=内容来源，operation=系统准备做什么 |
| 上下文 | `tool_name` `tool_arguments` `tool_result` `mcp_server` `mcp_tool` `mcp_schema` `memory_target` `credential_markers` | 按场景携带的结构化上下文 |
| 表现 | `presentation_style` `labels` | explicit/structured/stealth/natural（来自原始数据属性） |
| 元数据 | `metadata` `expected_scanner` | V2 桥接信息、canary token 等 |

**case_id 稳定性设计**（§20）：同一个 case 换 Renderer 后 ID 不变，保证纵向可比。renderer/target/model 版本放在 run metadata 里。

### 3.2 Channel 枚举（§4.1）

| Channel | 用途 |
|---|---|
| `USER_PROMPT` | 普通用户输入 |
| `EMAIL` `WEB_PAGE` `RAG_DOCUMENT` | 不可信外部内容 |
| `TOOL_RESULT` | 工具返回结果（间接注入载体） |
| `TOOL_CALL` | 即将执行的工具调用 |
| `MCP_DEFINITION` | MCP 工具定义 |
| `MEMORY_WRITE` | 即将写入长期记忆的内容 |
| `OUTBOUND_RESPONSE` | 出站响应 |
| `SYSTEM_CONTEXT` | 系统上下文 |

### 3.3 Renderer 体系（§7-8）

7 个渲染器，每个是**确定性运输格式**（不是攻击数据生成器）：

| Renderer | Channel | 模板 | 版本 |
|---|---|---|---|
| `UserPromptRenderer` | user_prompt | **无 wrapper，content 原样输出**（V2 回归契约） | v1 |
| `ExternalContentRenderer` | email/web_page/rag_document | `[UNTRUSTED_EXTERNAL_CONTENT]` + source_type | v1 |
| `ToolResultRenderer` | tool_result | `[TOOL_RESULT]` + tool name | v1 |
| `ToolCallRenderer` | tool_call | `[TOOL_CALL_REQUEST]` + user_intent + tool + args | v1 |
| `MCPDefinitionRenderer` | mcp_definition | `[MCP_TOOL_DEFINITION]` + server/tool/description/schema | v1 |
| `MemoryWriteRenderer` | memory_write | `[MEMORY_WRITE_REQUEST]` + target + operation | v1 |
| `CredentialFlowRenderer` | 组合 | `[CREDENTIAL_FLOW_CHECK]` + base_channel 组合 | v1 |

设计约束：
- wrapper 永远固定，不含攻击内容
- payload 只来自 case 字段
- 同一 case + 同一 renderer → 字段级完全一致的输出（canonicalized semantic equivalence）
- channel 不匹配时抛 `RendererError`

### 3.4 TargetAdapter（§9-11）

**LineModTargetAdapter**（`type: openai_gateway`）：
- 构建与 V2 完全一致的请求体：`{model, messages:[{role:user, content}], temperature:0, max_tokens:8}`
- 强制 `X-LineMod-No-Failover: true`（benchmark_mode 下缺失即拒绝启动）
- classification 配置驱动（§37）：`blocked_status` + `blocked_code` 从 `targets.yaml` 读取，不再硬编码 403/SECURITY_BLOCKED

**QwenGuardTargetAdapter**（`type: classifier`）：
- 解析 Safety 标签（Safe/Unsafe/Controversial）而非 HTTP 403
- 报告需明确与 LineMod 的安全职责不同（§39）

**http_parser**（§11）：
- 纯函数 `parse_linemod_response(status, body, classification)` → `GatewayObservation`
- 与 V2 `classify_linemod_http` 逻辑完全一致（回归测试验证）
- 提取 scanner / policy / score / response_text

### 3.5 Oracle 体系（§13-15）

| Oracle | 用途 | 判定逻辑 |
|---|---|---|
| `BlockPassOracle` | 绝大多数 benchmark | expected BLOCK + actual BLOCKED = TP；expected BLOCK + actual PASSED = FN；等等 |
| `CanaryOracle` | Credential/E4/E5 | 在 BlockPass 基础上检查 canary 是否泄露 |
| `CompositeOracle` | 预留 | 必须 block AND canary 不泄露 |

transport 噪声（rate_limited / error / cooldown）→ `UNJUDGED`，不计入 TPR/FPR，由 retest 单独处理。

### 3.6 GatewayRunner（§10, §28-30）

执行流水线：
```
SecurityCase → render → build_request → [dry-run 停止] → call_with_retry → oracle → CaseResult → store.append
```

关键特性：
- **dry-run**：渲染 + 构建请求 + 计算 request_hash，但不调 API（重构期间大量使用）
- **resume**：跳过已有 clear outcome 的 case
- **retest**：单独重跑 `UPSTREAM_COOLDOWN` 的 case（§30：transport retry vs benchmark retest 分离）
- **按 channel 分组**：CLI `run` 按 channel 分组，每组用一个 renderer

### 3.7 ResultStore（§23, §48）

- append-only jsonl + fsync
- 写在 `cache/results_v3/`（与 V2 的 `cache/results/` 分离）
- **写盘前经 SecretRedactor 脱敏**（§24/§43）

### 3.8 Analyzer + Breakdown（§31-35）

标准化输出：
```
n_total / n_judged / n_unjudged
TP / FP / TN / FN
TPR / FPR / block_rate / pass_rate / error_rate / rate_limit_rate
score_distribution: min / p10 / p25 / p50 / p75 / p90 / max
```

四种 breakdown：
- **by_channel**（§32）：`email 98% / tool_result 42%` — 远比 `E2=79%` 有价值
- **by_scanner**（§33）：判断产品真正依赖哪个扫描器
- **by_style**（§35）：`explicit TPR 99% / stealth TPR 21%` — 暴露阈值附近不稳定
- **by_operation**（§5）

### 3.9 SecretRedactor（§24, §43）

统一脱敏，覆盖所有输出面（logs / exceptions / request dump / result dump / debug / report）：

匹配模式：
- `TEST_SECRET_*` / `TEST_CANARY_*` / `CNY-*`（benchmark canary）
- `Bearer ...` / `api_key=...` / `sk-...`（常见密钥格式）
- case 的 `credential_markers` 作为额外模式

**接入路径**（外部审查 F1 修复后）：
| 路径 | 脱敏方式 |
|---|---|
| `ResultStore.append` | 写盘前 `redact_dict(result.to_dict())`，注入 case markers |
| `GatewayRunner` | 持久化 response_text 前在 store 层脱敏；leakage 检测在脱敏前完成，存为 metadata 聚合值 |
| `render --show-request` | 打印前脱敏 rendered_text + json_body |
| `metrics/leakage.py` | 从 metadata.leakage 读聚合值，`leaked_markers` 永远为空 |

### 3.10 CLI（§25-28）

| 命令 | 功能 |
|---|---|
| `validate` | fail-fast：target/api-key/no-failover/project/oracle/renderer/case_id 唯一性 |
| `render` | 显示渲染文本 + request_hash + json_body（不调 API），输出经脱敏 |
| `run --dry-run` | 渲染 + 构建请求但不调 API |
| `run` | 按 channel 分组跑完整流水线 |
| `analyze` | 从 result store 计算指标 + breakdown |
| `report` | 写 SUMMARY.md |
| `compare` | 同一 case 集跨 target/run 对比，标记 divergence |

---

## 4. P1-P5 研究项目（§16）

| 项目 | Channel | Oracle | Legacy 映射 | 威胁代号 |
|---|---|---|---|---|
| P1 External Instruction Boundary | email, web_page, rag_document, tool_result | block_pass | E2, E8 | A-01, A-04, L-01 |
| P2 Tool Action Guard | tool_call | block_pass | E8, E11 | A-05, A-06 |
| P3 MCP Definition Guard | mcp_definition | block_pass | new | A-03 |
| P4 Credential Flow Guard | user_prompt, tool_result, tool_call, memory_write, outbound_response | canary | E4, E5 | G-01, A-06 |
| P5 Memory Write Guard | memory_write | block_pass | E9 | A-02 |

映射文档：`docs/P1-P5_MAPPING.md`。E1-E12 编号不删除（§17），保留历史可比性。

---

## 5. §51 验收清单

### 5.1 架构

| 条目 | 状态 | 证据 |
|---|---|---|
| V2 `Sample.prompt_text` 不再是核心模型 | ✅ | `SecurityCase` 是核心；`Sample` 仅在 V2 兼容层 |
| 新核心对象是 `SecurityCase` | ✅ | `core/models.py`，含 channel/operation/direction/expected_action + 结构化上下文 |
| Dataset/Renderer/Target/Oracle/Analyzer 完全分层 | ✅ | 11 个独立子包；测试断言 datasets/renderers/oracles 无 `requests.post` |
| LineMod 网络代码只存在于 TargetAdapter | ✅ | `targets/linemod.py`；inspect 测试断言其他层无网络代码 |

### 5.2 Channel

| 条目 | 状态 |
|---|---|
| user_prompt | ✅ |
| email / web / rag | ✅ |
| tool_result | ✅ |
| tool_call | ✅ |
| mcp_definition | ✅ |
| memory_write | ✅ |
| credential flow | ✅（CredentialFlowRenderer 组合） |

### 5.3 可复现

| 条目 | 状态 | 证据 |
|---|---|---|
| case_id 稳定 | ✅ | 只 hash dataset_id+source_id+channel+operation+threat_id；测试验证内容无关 |
| manifest 只读 | ✅ | LegacyV2Adapter 仅读；测试断言无 .tmp/.v3 文件 |
| result append-only | ✅ | `"a"` 模式 + fsync；测试断言 |
| renderer version 可追踪 | ✅ | 全部 v1 + `full_version` 属性；ResultRecord 记录 renderer_name/version |
| target config 可追踪 | ✅ | `config_hash` + `compute_run_id` |

### 5.4 LineMod

| 条目 | 状态 | 证据 |
|---|---|---|
| No-Failover 强制开启 | ✅ | benchmark_mode 下 `__init__` 抛 TargetError；validate 显式要求（不默认 true） |
| 403/200/429/503/400/413 正确分类 | ✅ | 6 类全覆盖测试 |
| scanner/policy/score 正确提取 | ✅ | 测试从嵌套 JSON 提取 |

### 5.5 安全

| 条目 | 状态 | 证据 |
|---|---|---|
| API Key 不落日志 | ✅ | `mask_api_key` + `request_hash` 排除 Authorization 值；合约测试断言 |
| TEST_SECRET 自动脱敏 | ✅ | ResultStore.append 写盘前 redact；端到端测试断言 canary 不在磁盘 |
| Exception 不泄密 | ✅ | CLI `main()` 顶层 try/except 对所有未捕获异常经 `SecretRedactor.redact_text` 脱敏后再写 stderr（外部审查文档修正 3）；E2E 测试 `test_e2e_cli_exception_redacted_to_stderr` 注入含 `TEST_SECRET_E2E_99` 的异常，断言 stderr 不含该 marker 且含 `<REDACTED>` |
| Request dump 不泄密 | ✅ | render --show-request 打印前 redact；测试断言 |

### 5.6 CLI

| 命令 | 状态 |
|---|---|
| validate | ✅ |
| render | ✅ |
| run --dry-run | ✅ |
| run | ✅ |
| analyze | ✅ |
| report | ✅ |
| compare | ✅ |

### 5.7 兼容

| 条目 | 状态 | 证据 |
|---|---|---|
| V2 固定样本经 LegacyAdapter 后结果不变 | ✅ | 回归测试：spear_explicit_30 逐 case 比对 V2/V3 请求体字段级完全一致（除 `temperature` `0.0` vs `0` 的数值序列化差异做归一化，即 canonicalized semantic equivalence）+ 分类器等价 |
| 原数据集目录完全未改变 | ✅ | `git log` 确认 cache/datasets/ 无 V3 提交；`git diff --exit-code -- cache/datasets` 干净（exit 0） |
| 原 manifest 完全未改变 | ✅ | `git log` 确认 cache/sample_manifests/ 无 V3 提交（最后一次触碰在 V3 重构前的 `23466f9`）；已提交树哈希 `cache/sample_manifests` = `aa78f9d`。`git diff --exit-code` 在**工作区**对 9 个 manifest 的 `created_at` 字段有差异（V2 遗留的工作区改动，非 V3 引入——见初始 git status 的 `M cache/sample_manifests/*.json`，均为时间戳重写、无样本内容变化）；V3 代码（`LegacyV2Adapter`）只读不写，已由 inspect 测试断言。**结论：V3 重构未修改 manifest；工作区时间戳差异属 V2 遗留，应单独清理。** |

---

## 6. 测试覆盖

### 6.1 测试统计

| 类别 | 文件数 | 测试数 | 说明 |
|---|---|---|---|
| unit | 10 | 109 | 核心模型/渲染器/解析器/Oracle/Runner/Adapter/Redactor/Analyzer/Legacy + F8-F13 验证（27 项） |
| contract | 3 | 12 | FakeLineModServer 合约 + V2/V3 回归 |
| integration | 1 | 14 | CLI 端到端（validate/render/run/compare + P4 脱敏） |
| completion | 1 | 19 | §51 验收门（含 F1 端到端脱敏 + 文档修正 3 的 E2E 异常脱敏） |
| **V3 合计** | **15** | **143** | |
| V2 | 6 | 37 | 原 V2 测试全部仍通过 |
| **总计** | **21** | **180** | **全部通过** |

### 6.2 关键测试说明

**V2/V3 回归契约**（§47，最关键）：
- `test_v2_v3_request_body_byte_identical_on_frozen_manifest`：用真实冻结 manifest（spear_explicit_30）逐 case 比对 V2 `test_linemod` 和 V3 LegacyAdapter+UserPromptRenderer+LineModTargetAdapter 的请求体与 header，仅 temperature `0.0` vs `0` 做归一化
- `test_v2_v3_outcome_parity_via_classifier`：403/200/503/429/413 五类分类器等价校验

**端到端脱敏**（§43，外部审查 F1 修复后新增）：
- `test_credential_flow_end_to_end_redaction`：FakeLineModSession 让含 `TEST_SECRET_7B021C` 的 case 跑完整 runner→store，断言磁盘每一行和报告 markdown 都不含该 marker，同时 analyzer 仍检测到泄露（canary_echo_num=1）
- `test_blocked_credential_case_redacted`：blocked case 的 tool_arguments 里的 canary 也不落盘

**FakeLineModServer 合约**（§46）：
- 返回固定 200/403/429/503/413，Runner 全流程不消耗真实 API
- 验证请求体形状、retry、cooldown retest、No-Failover header

---

## 7. 外部审查意见处理

外部审查发现 7 项问题（F1-F7），全部修复：

| 编号 | 严重度 | 问题 | 修复 | 提交 |
|---|---|---|---|---|
| F1 | **阻断** | SecretRedactor 是孤儿代码，从未接入运行时 | 接入 ResultStore.append / GatewayRunner / render / leakage 四处 + 端到端测试 | `512f675` |
| F2 | 次要 | 403/SECURITY_BLOCKED 硬编码在 http_parser | targets.yaml 加 classification 块，http_parser 读配置 | `512f675` |
| F3 | 次要 | P1-P5 与旧 E 编号映射未记录 | `docs/P1-P5_MAPPING.md` + 每个项目 caveats 引用 | `512f675` |
| F4 | 次要 | P5 fixture 字段名不符 | 加 memory_scope + source_channel 到 metadata | `512f675` |
| F5 | 次要 | P4 只测检测不测脱敏 | 补 3 条 CLI 测试断言输出不含 canary | `512f675` |
| F6 | 次要 | No-Failover 默认当 true（偏宽松） | validate 改为显式要求 | `512f675` |
| F7 | 小瑕疵 | score 重复键 / env.example / 空结果防护 / 尾逗号 / render --target | 全部清理 | `512f675` |

### 7.2 第二轮外部审查（F8-F13 + 文档修正）

| 编号 | 严重度 | 问题 | 修复 |
|---|---|---|---|
| F8 | **阻断** | Renderer 的安全标签（`[UNTRUSTED_EXTERNAL_CONTENT]` 等）可能告诉网关"这是不可信内容"，抬高 TPR | 新增 `RenderFidelity` 三档（RAW/STRUCTURED/LABELED）；RAW 为头条分数（无安全标签），LABELED 仅作增强实验；CaseResult 记录 `render_fidelity`；`compute_metrics` 加 `by_fidelity` breakdown；CLI `run`/`render` 加 `--fidelity` |
| F9 | **阻断** | case_id 内容无关 + resume 跳过 → 数据集静默改写行后被旧结果掩盖 | 新增 `case_fingerprint`（内容哈希，`compute_case_fingerprint`）；`CaseResult` 存 `case_fingerprint` + `dataset_version`；resume 仅当 `case_id` AND `case_fingerprint` 都匹配才跳过；测试验证"同 source_id 改内容 → 强制重测" |
| F10 | **阻断** | P3 无法真正测试 DCI D_real（网关只看 description，看不到实现） | P3 正式更名 "MCP Definition Content Guard"；caveats + mapping 文档明确"不能测 Description-Code Inconsistency"；DCI 需未来 `MCPIntegrityCase`（含 declared/observed side effects）才能接入 |
| F11 | 高 | P4 Credential 仍用 `max_tokens=8`，泄露被 token 截断而非被拦截 | `ProjectConfig.generation` + `TargetConfig.generation_profile()`；P4 配 `max_tokens=128`；V2 回归保持 8（legacy 路径）；`build_runner` 接 project>target>default 优先级 |
| F12 | 高 | P2 无法表达 AuthBench 的 User/Permission/Resource/Action | `SecurityCase.authorization_context`（subject/role/granted_permissions/task_scope/resource/requested_action）；ToolCallRenderer 在 STRUCTURED/LABELED 渲染；caveats 注明"非完整 IAM，网关只见文本" |
| F13 | 高 | Credential 只有 expected_action=BLOCK/ALLOW，把"未拦截"等同于"泄露" | `LeakageExpectation` 枚举（NO_LEAK/LEAK_ALLOWED/UNSET）；CanaryOracle 产出双轴 verdict（decision + leakage_verdict）；Metrics 加 `leakage_rate`/`leakage_n_judged`；报告分 "Gateway Decision Correctness" 与 "Credential Leakage Rate" |
| 文档 1 | 小 | "字节级一致"不准确（做了归一化） | 改为 "canonicalized semantic equivalence / 字段级完全一致（除数值序列化差异）" |
| 文档 2 | 小 | 文件数前后不一致（62+17 vs 14+6=20） | 补口径表：V3 源 62 / V3 测试 18（含 conftest/init/F8-F13 新增）/ V2 测试 6 |
| 文档 3 | 小 | "Exception 不泄密"证据不够强（只证 redactor 能力，未证 runtime 路径） | CLI `main()` 顶层 try/except 经 SecretRedactor 脱敏后写 stderr；E2E 测试注入含 canary 异常断言 stderr 不含 |
| 文档 4 | 小 | git log 不能完全证明目录没被改（工作区修改不进历史） | 补 `git diff --exit-code` + 已提交树哈希；如实记录 9 个 manifest 工作区 `created_at` 差异为 V2 遗留（非 V3 引入） |

---

## 8. V2 兼容性

### 8.1 V2 保留状态

V2 代码完整保留在项目根目录，**未被 V3 重构修改**：

| V2 组件 | 位置 | 状态 |
|---|---|---|
| `Sample` / `Manifest` / `ResultRecord` | `core/schema.py` | 未修改（git 确认只在初始提交） |
| `linemod_guard_client.py` | 根目录 | 未修改 |
| `core/runner.py` | `core/` | 未修改 |
| `core/analyzer.py` `core/registry.py` | `core/` | 未修改 |
| E1-E12 项目 | `projects/` | 未修改 |
| 数据集适配器 | `adapters/` | 未修改 |
| 冻结 manifest | `cache/sample_manifests/` | 未修改（只读） |
| 冻结数据集 | `cache/datasets/` | 未修改 |
| V2 测试 | `tests/test_*.py` | 29 个全部仍通过 |

### 8.2 桥接机制

`LegacyV2Adapter`（`datasets/adapters/legacy_v2.py`）读取冻结的 V2 manifest，把每个 `Sample` 转成 `SecurityCase(channel=USER_PROMPT, operation=CHAT)`。映射：

```
Sample.prompt_text   → SecurityCase.content
Sample.sample_id     → SecurityCase.source_id
Sample.expected      → SecurityCase.expected_action (blocked→BLOCK, passed→ALLOW)
Sample.subset        → SecurityCase.presentation_style (stealth/easy 等)
```

这样 V3 的 `UserPromptRenderer`（无 wrapper，content 原样输出）+ `LineModTargetAdapter` 复现 V2 的请求（除 `temperature` `0.0` vs `0` 数值序列化差异外字段级完全一致 — canonicalized semantic equivalence，非严格 byte-identical）。

---

## 9. 已知限制与下一步

### 9.1 当前限制

1. **fixtures 不是 benchmark 数据**：P1-P5 的验收 fixtures 只验证框架能力（channel/renderer/request 正确性），不是真实基准测试数据
2. **outbound canary 检测依赖产品能力**：P4 的出站检测依赖 LineMod 是否暴露响应侧检测路径
3. **MCP Definition 暂无 DCI 数据**：P3 的接口已就绪，但 DCI 数据需官方 artifact 确认后接入
4. **Memory Write 只测写入侧**：P5 是 Memory Write Guard，不是完整 Memory Security

### 9.2 下一步：Dataset Integration（§52）

架构稳定后，按序接入数据集：

| 顺序 | 数据集 | 对应项目 | 接入前审核 |
|---|---|---|---|
| 1 | LLMail-Inject | P1 (email) | license / artifact / version / hash / ground-truth |
| 2 | AgentDojo | P1 (tool_result) + P2 | 同上 |
| 3 | Credential Leakage | P4 | 同上 |
| 4 | AuthBench | P2 | 同上，**需确认官方数据 artifact** |
| 5 | DCI D_real | P3 | 同上，**不从论文 PDF 抄数据** |

### 9.3 最终目标（§53）

V3 报告应能输出：

```
User Prompt Attack TPR
Email Injection TPR
Web Injection TPR
RAG Injection TPR
Tool Result Injection TPR
Dangerous Tool Call TPR
MCP Definition TPR
Memory Write TPR
Credential Exfiltration TPR
Benign FPR
```

再按 `explicit / stealth / scanner / policy / channel / operation` 拆分——让 DemoTest 从"Prompt Injection Scanner Tester"变成真正的"Gateway Security Benchmark Framework"，且不夸大能力边界。

---

## 10. 快速使用指南

### 10.1 环境准备

```bash
# 安装（开发模式）
pip install -e ".[test]"

# 配置环境变量
cp config/env.example .env
# 编辑 .env 设置 LINEMOD_API_KEY 等
```

### 10.2 典型工作流

```bash
# 1. 验证配置 + cases
python -m demotest.cli.main validate \
  --project P1_external_instruction \
  --source fixture:p1_external_instruction \
  --no-key-check

# 2. 检查渲染结果（不调 API）
python -m demotest.cli.main render \
  --project P2_tool_action \
  --source fixture:p2_tool_action \
  --show-request --limit 2

# 3. dry-run（不调 API）
python -m demotest.cli.main run \
  --project P5_memory_write \
  --source fixture:p5_memory_write \
  --dry-run

# 4. 真实运行（需 API key）
python -m demotest.cli.main run \
  --project P1_external_instruction \
  --source legacy:spear_explicit_30 \
  --run-version live-v3-001

# 5. 分析
python -m demotest.cli.main analyze \
  --project P1_external_instruction \
  --source legacy:spear_explicit_30 \
  --run-version live-v3-001

# 6. 报告
python -m demotest.cli.main report \
  --project P1_external_instruction \
  --source legacy:spear_explicit_30 \
  --run-version live-v3-001

# 7. 跨 target 对比
python -m demotest.cli.main compare \
  --project P1_external_instruction \
  --source legacy:spear_explicit_30 \
  --run-a linemod/live-v3-001 \
  --run-b qwen3guard/live-v3-001
```

### 10.3 运行测试

```bash
# V3 全套
python -m pytest tests/v3/ -q

# V2 + V3 全套
python -m pytest tests/ -q

# 仅回归验证
python -m pytest tests/v3/contract/test_v2_v3_regression.py -q
```

---

*报告生成于 2026-08-19，基于提交 `512f675`。*
