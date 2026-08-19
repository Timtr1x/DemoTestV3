# DemoTest V3 — Gateway Security Benchmark Framework

DemoTest 从一个 **Prompt Injection Scanner Tester** 升级为真正针对中转站产品的 **Gateway Security Benchmark Framework**。

V2 的核心抽象是 `Sample.prompt_text → POST → 403/200 → blocked/passed`——适合直接注入，但无法解释"网关在什么安全边界上成功/失败"。V3 把核心抽象升级为 **SecurityCase**：一个结构化的安全事件，携带 trust channel、operation、上下文（tool args / MCP schema / memory target / credential markers），经过 Renderer → TargetAdapter → Oracle 的分层流水线。

> **被测对象不变**（仍然是 LineMod Gateway），**核心 Oracle 不变**（403+SECURITY_BLOCKED=blocked / 200=passed），但测试框架内部从单一字符串升级为结构化事件。

## 文档

| 文档 | 内容 |
|------|------|
| **[docs/V3_ACCEPTANCE_REPORT.md](docs/V3_ACCEPTANCE_REPORT.md)** | **V3 验收报告**（§51 逐项 + 架构 + 测试覆盖） |
| **[docs/P1-P5_MAPPING.md](docs/P1-P5_MAPPING.md)** | P1-P5 ↔ 旧 E1-E12 / 威胁代号映射 |
| [docs/E1-E12_CATALOG.md](docs/E1-E12_CATALOG.md) | V2 E1-E12 全部子项、入站/出站、T8/T15 |
| [docs/STANDARD_DATASET.md](docs/STANDARD_DATASET.md) | 标准数据集 standard-v1 与可复测说明 |
| [docs/SURVEY_REPORT_live-real-v1.md](docs/SURVEY_REPORT_live-real-v1.md) | V2 完整实测调查报告 |

## V3 架构

```
Dataset → DatasetAdapter → SecurityCase → CaseRenderer → GatewayRequest
  → TargetAdapter → LineMod → GatewayObservation → Oracle → CaseResult
  → ResultStore → Analyzer → Report
```

**关键分离**："数据是什么"（SecurityCase）和"怎么送进网关"（Renderer + TargetAdapter）彻底分开。Runner 只认识 SecurityCase / Renderer / TargetAdapter / Oracle，不知道 E2 / LLMail / AuthBench。

### 目录结构

```
src/demotest/
├── core/         # SecurityCase / enums / ids / contracts / SecretRedactor
├── datasets/     # DatasetAdapter ABC + LegacyV2Adapter
├── renderers/    # 7 个渲染器 (UserPrompt / ExternalContent / ToolResult / ...)
├── targets/      # LineMod TargetAdapter + QwenGuard + HTTP parser
├── runners/      # GatewayRunner + retry (transport vs benchmark retest)
├── oracles/      # BlockPass / Canary / Composite
├── metrics/      # detection / leakage / grouping
├── analysis/    # analyzer + compare
├── reporting/   # markdown
├── storage/     # append-only ResultStore (写盘前脱敏)
└── cli/         # validate / render / run / analyze / report / compare
```

V2 代码（`core/` `adapters/` `projects/` `linemod_guard_client.py`）完整保留在项目根目录，通过 `LegacyV2Adapter` 桥接。

### 核心模型：SecurityCase

替代 `Sample.prompt_text` 的结构化安全事件。字段分五组：

- **身份**：`case_id`（hash of dataset_id+source_id+channel+operation+threat_id，**不含 renderer/target 版本**，跨版本稳定）
- **什么/哪里/为什么**：`channel` / `operation` / `direction` / `content` / `expected_action`
- **上下文**：`tool_name` / `tool_arguments` / `mcp_schema` / `memory_target` / `credential_markers` / `authorization_context`
- **表现**：`presentation_style`（explicit / structured / stealth / natural）
- **指纹**：`fingerprint()`（内容哈希，resume 时与 case_id 一起检查，防止数据集悄悄改内容）

### Channel 枚举

`USER_PROMPT` / `EMAIL` / `WEB_PAGE` / `RAG_DOCUMENT` / `TOOL_RESULT` / `TOOL_CALL` / `MCP_DEFINITION` / `MEMORY_WRITE` / `OUTBOUND_RESPONSE` / `SYSTEM_CONTEXT`

### Renderer（7 个）

每个是**确定性运输格式**（不是攻击生成器），支持三档 fidelity：

| Fidelity | 含义 | 用途 |
|-----------|------|------|
| `raw` | payload 原样，无安全标签 | headline 分数（最接近真实生产请求） |
| `structured` | 真实传输信封（tool args JSON、email header），无安全标签 | 结构信号但不提示网关 |
| `labeled` | 加 `[UNTRUSTED_EXTERNAL_CONTENT]` 等安全标签 | enhancement 实验（可能虚高 TPR） |

CLI `--fidelity auto` 按 channel 自动选主 fidelity（tool_call 用 structured，email 用 raw）。

### Oracle 体系

- **BlockPassOracle**：混淆矩阵（TP/FP/TN/FN），transport 噪声 → UNJUDGED
- **CanaryOracle**：双轴——决策正确性 + credential 泄露（独立报告）
- **CompositeOracle**：预留（block AND no-leak）

### SecretRedactor

统一脱敏，覆盖所有输出面（result store / render / exception / request dump）。写盘前对每行 `redact_dict`，注入 case 的 `credential_markers`。敏感键（api_key/token/password/...）下的值整体替换。

## P1-P5 研究项目

| 项目 | Channel | Oracle | Legacy 映射 |
|------|---------|--------|-------------|
| P1 External Instruction Boundary | email, web_page, rag_document, tool_result | block_pass | E2, E8 |
| P2 Tool Action Guard | tool_call | block_pass | E8, E11 |
| P3 MCP Definition Content Guard | mcp_definition | block_pass | new |
| P4 Credential Flow Guard | user_prompt, tool_result, tool_call, memory_write, outbound_response | canary | E4, E5 |
| P5 Memory Write Guard | memory_write | block_pass | E9 |

E1-E12 编号不删除，保留历史可比性。

## 快速开始

```bash
# 安装
pip install -e ".[test]"

# 环境变量
cp config/env.example .env
# 设置 LINEMOD_API_KEY 等

# 验证配置 + cases
python -m demotest.cli.main validate \
  --project P1_external_instruction \
  --source fixture:p1_external_instruction \
  --no-key-check

# 检查渲染结果（不调 API）
python -m demotest.cli.main render \
  --project P2_tool_action \
  --source fixture:p2_tool_action \
  --show-request --limit 2

# dry-run（不调 API）
python -m demotest.cli.main run \
  --project P5_memory_write \
  --source fixture:p5_memory_write \
  --dry-run

# 真实运行
python -m demotest.cli.main run \
  --project P1_external_instruction \
  --source legacy:spear_explicit_30 \
  --run-version live-v3-001

# 分析 + 报告
python -m demotest.cli.main analyze \
  --project P1_external_instruction \
  --source legacy:spear_explicit_30 \
  --run-version live-v3-001

python -m demotest.cli.main report \
  --project P1_external_instruction \
  --source legacy:spear_explicit_30 \
  --run-version live-v3-001

# 跨 target 对比
python -m demotest.cli.main compare \
  --project P1_external_instruction \
  --source legacy:spear_explicit_30 \
  --run-a linemod/live-v3-001 \
  --run-b qwen3guard/live-v3-001
```

## 测试

```bash
# V3 + V2 全套
pytest tests/ -q

# 仅 V3
pytest tests/v3/ -q

# 仅回归验证（V2/V3 字节级一致性）
pytest tests/v3/contract/test_v2_v3_regression.py -q
```

152 个测试全部通过（V3 123 + V2 29），含 FakeLineModServer 合约测试、V2/V3 字节级回归验证、端到端脱敏测试、§51 验收门。

## 判定口径（不可违反）

| HTTP | outcome |
|------|---------|
| 403 + `SECURITY_BLOCKED` | `blocked` |
| 200 | `passed` |
| 503 cooldown / no upstream | `upstream_cooldown` |
| 429 | `rate_limited`（runner 退避重试） |
| 400/413 超长 | `payload_too_large` |

- `classification` 配置驱动（`config/v3/targets.yaml`），不硬编码
- benchmark_mode 强制 `X-LineMod-No-Failover: true`（缺失即拒绝启动）
- result append-only jsonl + fsync；resume 跳过 clear outcome
- `n_judged` 只计 security verdict（TP/FP/TN/FN），cooldown 不计入

## 数据政策

- 冻结的 V2 manifest 只读（`cache/sample_manifests/`），V3 不改写
- V3 结果写在 `cache/results_v3/`（与 V2 `cache/results/` 分离）
- `case_id` 稳定（跨 renderer/target 版本不变）；`fingerprint()` 防 data drift
- `run_id` 含真实 provenance（target config + project config + dataset snapshot hash + fidelity）
