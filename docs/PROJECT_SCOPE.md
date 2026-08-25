# DemoTest V3 — 项目范围边界

> **DemoTest V3 是一个网关安全基准（gateway security benchmark）。**
>
> **动态 Agent / Skill 执行是可选的数据集采集合规工具，不属于基准运行时的一部分。**
>
> **基准数据集必须在 LineMod 评估前冻结为 SecurityCase 兼容产物。**

本文档是 2026-08-21 决议的范围重基线（scope re-baseline）的唯一可信来源（single source of truth）。它将 V3 验收报告（§52 Dataset Integration）恢复为唯一路线图，并将所有动态执行基础设施降级为辅助地位。

## 1. DemoTest 度量什么

单一问题：

> 给定一个真实或可信来源的安全事件，并将其置于对应的 LLM / Agent 交互边界上，LineMod Gateway 是否做出了正确的安全决策？

唯一的基准管线为：

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

任何 benchmark 命令均不得要求 Docker、SkillsMP、SkillLeakBench、candidate intake、snapshot 或 credential binding。

## 2. 仓库布局

```
src/demotest/
  core/              # SecurityCase、枚举、ID、契约、SecretRedactor — Core
  datasets/
    base.py, registry.py, source_lock.py, quality.py, dedup.py, manifest_builder.py — Core
    adapters/        # llmail、agentdojo、credential_catalog_synthetic、credential_dynamic_traces、legacy_v2、skillleakbench — Core（adapters）
    traces/          # CredentialTrace 模型 + 投影至 SecurityCase — Core
    dynamic/         # ← 可选采集合规工具（见 §3）
  renderers/         # 7 个 renderers + registry — Core
  targets/           # LineMod / QwenGuard + http_parser — Core
  runners/           # GatewayRunner、retry — Core
  oracles/           # block_pass、canary、composite — Core
  metrics/           # detection、leakage、grouping — Core
  analysis/          # analyzer、compare — Core
  storage/           # ResultStore — Core
  reporting/         # markdown — Core
  cli/
    validate, render, run, analyze, report, compare, dataset, manifest — Core
    dynamic          — Auxiliary（仅采集）

config/v3/
  projects.yaml, targets.yaml, datasets.yaml, suites.yaml — Core
  datasets/*.yaml    — 按数据集的投影配置 — Core

cache/datasets_v3/
  raw/<dataset>/              — 已锁定的原始镜像（gitignored，非 benchmark 身份）
  normalized/<dataset>/       — 已冻结的 SecurityCase 快照（由 `dataset prepare` 产生）
  metadata/*.lock.json        — 基准身份（已提交）

benchmarks/
  manifests/   — 已冻结 manifests（已提交）
  suites/      — 套件快照（已提交）
  frozen/datasets/<dataset_id>/
                 raw/reviews/reviewed_traces.jsonl + review_meta.json （已提交）
                 normalized/cases.jsonl + prepare.json                 （已提交）

P4 Credential Flow 的已冻结数据集（`credential_dynamic_traces`）位于
`benchmarks/frozen/datasets/credential_dynamic_traces/` —— 而非 gitignored 的
`cache/datasets_v3/`。这使得全新克隆即可在零依赖 Docker / SkillsMP / SkillLeakBench / candidate / snapshot / credential binding 的情况下，对已冻结的 P4 数据执行
`validate → render → run → analyze → report`。
```

对每个未来 PR 的规则：

> 这个 PR 属于 Benchmark Core 还是 Dataset Acquisition？两者不得混淆。

## 3. 辅助采集边界

`src/demotest/datasets/dynamic/` 与 `src/demotest/cli/dynamic.py` **予以保留并冻结**。不删除，但不再扩展。

作为辅助保留：

- SkillLeakBench Docker 沙箱（`sandbox.py`、`skillleak_collector.py`、`schemas.py`、`parser.py`）
- SkillsMP 爬虫与 `candidates.py` intake
- `runtime_specs` sidecar、`materialize`、`snapshot`
- `credential_bindings` 源码绑定配置（source-bound profile，已冻结；不再扩展）
- `review.py`、`split.py`、`agents/`（Host 侧 AgentDriver —— 仅 Extended）

不在路线图内（不实现、不规划）：

- TLS MITM / HTTPS 解密
- Node `fetch` 传输拦截
- 通用依赖自动安装器
- 通用 Agent 执行引擎
- Credential-format DSL
- Full-Skill 兼容 / 1000-trace 规模目标
- 自动漏洞发现平台

## 4. 数据集集成路线图（已恢复）

来自验收报告 §52 的顺序：

| # | 来源 | 项目 | 产物要求 |
|---|--------|---------|----------------------|
| 1 | LLMail-Inject | P1 | HF `microsoft/llmail-inject-challenge` @ 已锁定 SHA |
| 2 | AgentDojo | P1（tool_result，Extended）+ P2 | github `ethz-spylab/agentdojo` @ 已锁定 SHA |
| 3 | Credential Leakage | P4 | 已复核的 `DYNAMIC_TRACE` traces → `P4DatasetAdapter` → SecurityCase |
| 4 | AuthBench | P2 | **待定** — 需确认官方产物 |
| 5 | DCI `D_real` | P3 | **待定** — 需官方产物；不得从 PDF 拷贝 |

数据集仅在以下条件全部满足时被接受：来源真实、官方产物位置已知、版本/revision 已锁定、SHA/hash 已记录、ground truth 已定义、许可允许使用。不得通过合成/模板/LLM 扩展来填充数量。

## 5. P4 首版验收

- ≥20 条经人工复核的真实动态 traces，理想区间 20–100。无 1000 的硬性下限。
- 每条 Core trace 必须满足：`source_real && dynamic_execution_real && fake_credential_confirmed && marker_observed && sink_confirmed && gateway_projection_valid && expected_action_valid`（7 项复核关卡，fail-closed）。
- Traces 仅在 `review-apply` → `freeze-reviewed` → `P4DatasetAdapter` → `SecurityCase` 之后才成为基准数据。已冻结的 `p4_credential_flow_v1` 产物必须能在无 Docker/SkillsMP/SkillLeakBench/binding 的情况下完整走通 `validate → render → run → analyze → report`。
- 已冻结产物为**已提交**状态（`benchmarks/frozen/datasets/credential_dynamic_traces/`），因此 benchmark 永不依赖采集 sidecar。
- Headline 门槛：在数据集持有 ≥20 条真实已复核 traces 之前，P4 manifest 保持 `benchmark_track=core, headline_eligible=false`。`p4-core-bridge-v1`（1 条真实 trace）正是如此——属于 core track，而非 headline。正式的 headline P4 套件仅在满足 ≥20-trace 验收后创建。
- 合成 catalog 套件（`credential_catalog_synthetic`，quality C）仅为 **Extended / 框架验证**——永不作为真实 P4 headline，也不计入 ≥20 真实 traces 目标。

## 6. 参考

- `docs/V3_ACCEPTANCE_REPORT.md` —— Phase 0 基线；§52 为唯一路线图。
- `docs/P1-P5_MAPPING.md` —— 通道/项目/legacy 映射及 F8–F13 边界。
- `docs/P4_DYNAMIC_DATA_GUIDE.md`、`docs/P4_DYNAMIC_ROADMAP.md` —— 辅助采集合规指南（已冻结；非基准规范）。
