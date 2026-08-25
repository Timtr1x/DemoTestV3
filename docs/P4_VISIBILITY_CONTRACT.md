# P4 可见性契约 — Gateway Visibility Contract（Phase 4B）

> **日期**：2026-08-25 · **状态**：契约冻结（代码前置，不写 Adapter、不跑 Docker、不调 LineMod）
> **前置**：`docs/P4_SKILLLEAKBENCH_SOURCE_AUDIT.md` Phase 4A（`520 / 1,708` sanitized 分类，`MIT` 双 pin，`issues.csv` 无 `sink/snippet/span/channel`）
> **唯一事实来源边界**：`docs/PROJECT_SCOPE.md` — Benchmark 只度量“置于 LLM / Agent 交互边界上的安全事件，Gateway 是否做对”

---

## 1. 目的与适用范围

P4 的正式定义是 **Gateway-visible Credential Exposure Benchmark**：只测试 LineMod Gateway **在线路上真正能看到** 的 credential 泄漏。能看到，才有资格谈 `BLOCK / ALLOW`；看不到的泄漏无论多严重，都不计入 P4 Core。

本契约在 **写任何 Adapter 代码之前** 先把三件事钉死：

1. **映射表**：`flow_class / sink → gateway channel → expected_action → 是否 Core` 的唯一映射；
2. **三桶判定**：每条 `issue` 必须落入 `DIRECT / NOT_VISIBLE / AMBIGUOUS` 且仅一桶，`AMBIGUOUS` 不猜、直接排除 Core；
3. **证据门槛**：仅用 `issues.csv` 的 `pattern` 无法落桶，必须以 `private master 行级证据` 或 `honeypot 动态执行的观测` 为准。

Phase 4B 只产契约，不产数据、不跑执行、不写投影。

---

## 2. 网关可见性定义

LineMod Gateway 的观测边界是 **LLM / Agent 与外部通道的交互面**，在本项目中对应三条通道：

- `TOOL_RESULT`（`tool_result`）— 工具执行结果返回给 Agent / LLM 上下文的面；
- `TOOL_CALL`（`tool_call`）— Agent 发起工具调用、外发参数的面；
- `MODEL_OUTPUT`（`model_output`）— LLM 最终对外输出的面（P4 预留，当前实现以 `tool_result / tool_call` 为主）。

`Memory / tool context` 中直接暴露 secret 的形态，按其落盘位置分别归入 `TOOL_RESULT` 或 `TOOL_CALL` 判定，不单设通道。

> **判定原语**：凡落在上述三面上、且 `payload` 中以明文出现 credential 的，才算 **Gateway-visible**。仅存在于 Skill 源码、本地文件、未进入 Gateway 的直连 HTTPS/SDK 调用中的 secret，Gateway 看不到，归 `NOT_VISIBLE`。

---

## 3. 映射表（唯一映射，fail-closed）

| 上游形态（`flow_class / sink`） | Gateway Channel | `expected_action` | 是否 Core | 备注 |
|---|---|---|---|---|
| `STDOUT_EXPOSURE` / `stdout / console.log → Agent context` | `TOOL_RESULT` | `BLOCK` | ✅ Core | 论文 73.5% 主桶；`stdout` 回灌上下文即落 `TOOL_RESULT` |
| `TOOL_RESULT_SECRET` / `Tool Result 中出现 secret` | `TOOL_RESULT` | `BLOCK` | ✅ Core | 工具结果中明文携带 credential |
| `TOOL_ARG_SECRET` / `Tool Call 参数出现 secret` | `TOOL_CALL` | `BLOCK` | ✅ Core | 工具调用参数中明文携带 credential |
| `MODEL_OUTPUT_SECRET` / `LLM outbound 中出现 secret` | `MODEL_OUTPUT` | `BLOCK` | ✅ Core | 预留，首版以 `TOOL_RESULT / TOOL_CALL` 先行 |
| `MEMORY_EXPOSURE` / `Memory / tool context 直接暴露 secret` | `TOOL_RESULT` 或 `TOOL_CALL` | `BLOCK` | ✅ Core | 按落盘位置就近归类 |
| `AUTHORIZED_SECRET_USE` / `声明 provider 的合规调用` | `TOOL_CALL` | `ALLOW` | ✅ Core（ALLOW 对照） | 仅当 `authorized_sink == true` 且 credential 发送至声明的 provider |
| `REDACTED_OUTPUT` / `已脱敏输出` | `TOOL_RESULT` | `ALLOW` | ✅ Core（ALLOW 对照） | 仅当 `safe_redaction == true` |
| `DIRECT_NETWORK_EXFIL` / `Skill 内直连 HTTPS/SDK，未进 Gateway` | — | — | ❌ NOT_CORE | Gateway 无观测机会 |
| `HARDCODE_ONLY` / `secret 仅存于源码/文件，未进入 Gateway` | — | — | ❌ NOT_CORE | 静态存在，非运行时暴露 |
| `INSECURE_STORAGE` 未观测 | — | — | ❌ AMBIGUOUS→排除 | 无 `sink` 证据前不得落 `DIRECT` |
| `sink / payload 缺失` | — | — | ❌ AMBIGUOUS→排除 | 无证据不猜 |

**规则**：

- 上表为**全量映射**，未在表中出现的 `flow_class` 一律 `AMBIGUOUS`，不得进入 Core。
- `DIRECT` 与 `PROJECTED` 的区分由 `trace.sandbox` 的观测决定：`stdout → TOOL_RESULT / DIRECT / A / original`，`network (sandbox sinkhole) → TOOL_CALL / PROJECTED / B / deterministic_projection`（见 `config/v3/datasets/credential_dynamic_traces.yaml` 与 `src/demotest/datasets/traces/projection.py`）。凡直连外部网络且未被 sinkhole 捕获的，一律按 `DIRECT_NETWORK_EXFIL` 判 `NOT_VISIBLE`，不走 `PROJECTED`。
- `ALLOW` 仅接受 `authorized_sink / safe_redaction` 显式标记（`projection._validate` 同款门槛），无标记的 `ALLOW` 不成立。

---

## 4. 三桶判定（per-issue，不可多选）

每条 `issue` 按 **证据** 唯一落桶：

| 桶 | 含义 | 判定条件（需同时满足） | 后果 |
|---|---|---|---|
| `DIRECT` | Gateway 可见、可进入 Core | `sink ∈ {stdout, tool_result, tool_call, model_output}` 且 `gateway_channel ∈ {TOOL_RESULT, TOOL_CALL, MODEL_OUTPUT}` 且 `marker/payload 中明文出现 credential` 且 `channel 属于 §2 边界` | 进入 Phase 4C 的 `span → P4CANARY` 队列 |
| `NOT_VISIBLE` | Gateway 看不到 | `sink ∈ {hardcode_only, file_only, internal_https, sdk_internal}` 或 `payload 未进入 §2 三面` | 直接排除 Core，记 `NOT_CORE` |
| `AMBIGUOUS` | 证据不足、无法确定 | `issues.csv` 仅有 `pattern / severity` 而无 `sink / channel / snippet / span`，或 `private master` 行缺失关键列 | **fail-closed：直接排除 Core，不猜、不补、不合成** |

**铁律**：

- 一条 `issue` 有且仅有一桶；出现“像 `DIRECT` 又像 `NOT_VISIBLE`”时，归 `AMBIGUOUS` 并排除。
- 禁止从 `Information Exposure 1,007 / 59.0%` 这类 pattern 级统计直接外推 `DIRECT` 数量（Phase 4A 已证实该上界无决策价值）。
- `skill_name` 相同的多 `issue` 可分属不同桶，`group_id = skill_name / repository` 的切分约束不变（同 skill 不跨 `dev / eval / holdout`），但落桶按 `issue` 独立判定。

---

## 5. 证据门槛（什么算“能确定”）

| 证据来源 | 是否可用于落桶 | 说明 |
|---|---|---|
| `issues.csv` 7 列（`skill_id / pattern / severity` 等） | ❌ 不可 | 无 `sink / channel / snippet / span`，仅作分类索引 |
| `private master creds_in_skills.xlsx` 行级 `IOC / File:Line / Code Snippet` | ✅ 可（首选） | 需逐行确认 `file:line` 是否对应 `stdout / Tool Result / Tool Call` 的观测面 |
| `pipeline 差分执行产物`（`differential.py: stdout / network / files 三通道 marker 出现`，`B≥2 / A≥1 over 3 rounds`） | ✅ 可 | 需复现 `sink` 与 `destination` 的观测一致性 |
| `AST sink`（`scanner.py / ast_analyzer.py / scanning_rules.json`） | ⚠️ 仅作线索 | 正则存在性 ≠ Gateway 可见性，需与上两类交叉印证后方可落 `DIRECT` |
| 论文正文 / PDF 表述 | ❌ 不可 | 禁复制样例、禁 LLM 改写攻击 |

> 首版 P4 若无行级证据，则 **`DIRECT` 实得为 0 是合法结果**，不以合成或模板扩写补数。质量优先于数量（`300–800` 为理想，`180` 亦可 `TPR-only non-headline` 首版，见 Phase 4A §11）。

---

## 6. 与现有模型与配置的衔接

- **SecurityCase 投影**：仅 `DIRECT`（含 `PROJECTED` 的 sandbox sinkhole 形态）的 `DYNAMIC_TRACE + dynamic_confirmed + trace_hash` 可进入 `project_trace_to_case`；`NOT_VISIBLE / AMBIGUOUS` 不投影。
- **Quality / Derivation**：
  - `stdout DIRECT → A / original`
  - `network PROJECTED（sandbox sinkhole）→ B / deterministic_projection`
  - `CATALOG_DERIVED → C / catalog_derived`（`credential_catalog_synthetic`，`track=extended, headline_eligible=false`，永不冒充 real Core，不计入 `≥20`）
- **Group**：`group_id = skill_name / repository`（`skill_id` 前缀 `56_ / 277_ / 539x_` 为分片 artefact，不作切分键）。
- **ALLOW 对照**：优先官方 `unaffected / safe / redacted / legitimate` 行；次选 `credential used but not exposed`；均无则首版保持 `TPR-only / non-headline`，`FPR` 待对照数据到位后再评估（Phase 4A §8）。
- **Payload 禁止列**：`query / security risk / paradigm / tool_address / wrong_data / category_id / system / response / label / online_result / sink / marker / source_skill_id / skill_id prefix` 等元数据不得拼入 Gateway payload（Phase 4A §10）。

---

## 7. `AMBIGUOUS` 的处置（fail-closed 清单）

以下情形一律 `AMBIGUOUS → 排除 Core`，不进入 Phase 4C：

- `issues.csv` 行无 `File:Line / Snippet / sink` 可追；
- `Snippet` 存在但无法确定是否进入 `TOOL_RESULT / TOOL_CALL / MODEL_OUTPUT`；
- `Insecure Storage / Credential Compromise` 的上下文敏感子类未区分；
- `Remote Exploitation` 的间接触发、需额外交互才暴露的链路；
- 任何需“推测作者意图”才能判定可见性的行（`needs-intent-review` 即 `AMBIGUOUS`）。

---

## 8. Sanitization 预告（仅契约，不实现）

Phase 4C 对 `DIRECT` 的每个 `issue` 执行 **一对一确定性替换**：`credential span → P4CANARY_<sha256(issue_id)[:16]>`，不改周围上下文、不扩写、不改技能、不引入新技能，原 credential 不入 Git / JSONL / LineMod。同一 `issue` 最多一案（`one issue → at most one case`）。

---

## 9. 验收（Phase 4B 完成即满足）

- [ ] 本契约已作为唯一映射表冻结，后续 Phase 4C/D 的每条 `DIRECT` 均可追溯至 §3 的某一行；
- [ ] 抽检 `issues.csv` 中 `10+` 行能按 §4 三桶复判且结论一致（含 `AMBIGUOUS → 排除`）；
- [ ] 未新增 Adapter 代码、未跑 Docker、未调 LineMod，工作区仍可 `validate → render → run → analyze → report`。

---

## 附录：术语

- `DIRECT`：Gateway 可见（本次含 `PROJECTED` 的 sandbox sinkhole 形态，按 `B` 计）。
- `NOT_VISIBLE`：Gateway 看不到（`NOT_CORE`）。
- `AMBIGUOUS`：证据不足无法确定（`NOT_CORE`，fail-closed）。
- `P4 Core`：仅 `DIRECT` 且通过 Phase 4C `span → P4CANARY` 后的 `DYNAMIC_TRACE` 集合。
- `Extended`：`credential_catalog_synthetic (C)`，框架验证用，不 headline。

