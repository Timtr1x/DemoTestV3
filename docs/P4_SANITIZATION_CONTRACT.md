# P4 脱敏契约 — Credential Sanitization Contract（Phase 4C）

> **日期**：2026-08-25 · **状态**：契约冻结（代码前置，不写 Adapter、不跑 Docker、不调 LineMod）
> **前置**：`docs/P4_VISIBILITY_CONTRACT.md` Phase 4B（`DIRECT/PROJECTED` 唯一可进入 Core 的映射已冻结，`issues.csv` 7 列不可落桶）
> **范围**：本契约仅定义“已判定为 `DIRECT` 的每个 `issue` 如何在**不改上下文、不扩写、不引新技能**的前提下完成一对一脱敏替换”；不定义可见性（见 Phase 4B），不等同于发布桥的数据准备流程。

---

## 1. 目标

- 对 `DIRECT`（含 `PROJECTED/sandbox sinkhole`）集合中的每个 `issue`，将**落在 Gateway 可见面上的原始 `credential span`** 精确替换为**确定性假 canary**，使该 `issue` 可作为 `BLOCK` 样本进入 Core，同时满足：
  - 不在任何可提交产物（`Git / JSONL / LineMod 请求 / 日志 / 报告`）中留下真实 `secret`；
  - 同一 `issue` 最多一案（one-issue-at-most-one-case），不通过模板/改写扩充数量；
  - 替换是**可验证、可复现**的（给定同一 `issue_id` 可独立重算同一 canary）。

---

## 2. 输入与输出

- **输入**：Phase 4B 已判定为 `DIRECT` 或 `PROJECTED` 的 `issue`，且满足证据门槛（`private master 行级 File:Line/Snippet` 或 `差分三通道观测` 之一可定位 `span`）。
- **输出**：该 `issue` 的 `payload`（`stdout / Tool Result / Tool Call arguments` 中暴露面）经脱敏后的版本，用于构建 `DYNAMIC_TRACE` 的 `CredentialTrace.payload`，再经 `project_trace_to_case` 投影为 `SecurityCase`。
- **不输入**：`NOT_VISIBLE / AMBIGUOUS` 的 `issue` 不进入本契约；`synthetic/catalog_derived` 链路的样本不适用本契约（其 `canary` 由 `builder.py` 另行管理）。

---

## 3. Canary 命名与推导（唯一规则）

### 3.1 命名

- **格式**：`P4CANARY_<HEX16>`
- **推导**：`HEX16 = sha256(issue_id)[:16].upper()`
  - `issue_id` 为该 `issue` 在来源中的稳定标识（如 `skillleakbench` 的行级 `issue` 标识或 `private master` 的 `issue` 主键），逐字节取原始字符串，不做大小写归一、不截断前缀。
  - `sha256` 为十六进制小写 `hexdigest`，取前 16 字符后转大写。
  - 示例：`P4CANARY_3F7A9C1E5B2D8046`。

> 注：现存动态链路另有一套 `TEST_SECRET_<HEX16>`（`canary.py: canonical_canary(source_revision|skill_id|issue_id|trace_channel)`）与 `leakbench-sourcebound-*` 的 `source-bound` canary，已冻结且继续有效。本契约的 `P4CANARY_` 仅适用于 **SkillLeakBench 来源的 `DIRECT` issue 脱敏**，与上两套**不混用**；三者均满足“假 canary、不含真实 secret、跨产物一致”的不变式。

### 3.2 不变式

- **确定性**：同一 `issue_id` 在任何机器、任何时间重算得同一 `P4CANARY`；
- **唯一性**：不同 `issue_id` 以高概率得不同 canary（`HEX16` 碰撞概率可忽略；不要求全局去重，仅要求一对一）；
- **不可逆**：`P4CANARY` 不泄露原始 `secret` 的任何子串、长度或字符类信息；
- **可识别性**：`P4CANARY_` 前缀与现有 `TEST_SECRET_` / `leakbench-sourcebound-*` 可区分，便于审计与 `SecretRedactor` 覆盖（需纳入 `redactor` 可识别家族）。

---

## 4. 替换规则（逐字执行）

### 4.1 仅替换 span，不重写上下文

- 仅替换**已定位的 `credential span`**（`Snippet` 中经 `private master` 或差分观测确认为 credential 的连续子串，或 `Tool Call` 参数值中与 `credential` 等价的子串）；
- **不改** `span` 前后的任何字符、空白、标点、大小写、换行；
- **不扩写** 句子、不补全上下文、不引入新字段、不改技能源码或描述；
- `span` 的边界以**来源证据的字符区间**为准，不做正则二次猜测。

### 4.2 一条 issue 最多一条 case

- 一个 `DIRECT issue` 经脱敏后**至多**产 `1` 个 `CredentialTrace` / `SecurityCase`；
- 同一 `skill` 的多 `issue` 可各自产一案，但**不**对单 `issue` 内部的同一 `span` 做多变体；
- 不以改写、同义替换、模板展开等方式从一条 `issue` 衍生多案。

### 4.3 真实 secret 零落地

- 任何产物（`Git 历史 / JSONL / normalized 快照 / manifest / LineMod 请求体 / 日志 / 报告 / 评审材料`）**不得**包含原始 `secret` 的明文或可还原形态；
- 定位 `span` 的**中间证据**（如临时 `snippet` 摘录）仅可在本地内存中处理，落盘前必须已完成替换；
- `secret` 的**长度、字符类**等侧信道亦不得以注释、元数据或调试字段形式落地。

### 4.4 Channel 保持

- 脱敏前后 `gateway_channel` 不变（`TOOL_RESULT` 仍 `TOOL_RESULT`，`TOOL_CALL` 仍 `TOOL_CALL`），`sink` 不变；
- `Tool Call` 形态下，`credential` 仅替换 `arguments` 中对应参数的 `span`，不新增参数、不改 `tool_name`、`destination` 等。

---

## 5. 与可见性契约的衔接

- 仅 `DIRECT`（含 `PROJECTED/sandbox sinkhole`）可进入本契约；`NOT_VISIBLE / AMBIGUOUS` 不脱敏、不投影。
- 脱敏后进入 `DYNAMIC_TRACE` 链路时，仍需满足：
  - `evidence_type == DYNAMIC_TRACE`、`dynamic_confirmed == true`、`trace_hash` 非空、`quality ∈ {A, B}`（`stdout DIRECT→A/original`、`network PROJECTED→B/deterministic_projection`）；
  - `ALLOW` 样本（`authorized_sink / safe_redaction`）不适用 `P4CANARY` 替换（其本身即为 `ALLOW` 的“合规使用/已脱敏”对照，替换会改变语义）。

---

## 6. 与现有实现的边界

- 本契约**不**要求修改 `src/demotest/datasets/traces/canary.py` 的 `TEST_SECRET_` 体系与 `credential_bindings` 的 `source-bound` 体系；`P4CANARY_` 作为 SkillLeakBench `DIRECT` 脱敏的**独立家族**并存，仅需在 `SecretRedactor` 的可识别模式中覆盖。
- 冻结的动态发布桥产物 `benchmarks/frozen/datasets/credential_dynamic_traces/` 保持不动，不因本契约回写或重建。

---

## 7. 验收（Phase 4C 契约级）

- [ ] 给定任意 `issue_id` 可独立重算 `P4CANARY_<sha256(issue_id)[:16]>` 且与产物一致；
- [ ] 抽检 `DIRECT` 样本：脱敏前后仅 `span` 变化、上下文逐字一致，且同一 `issue` 不多于一案；
- [ ] 全量产物 `git log -p / JSONL / 报告` 中无原始 `secret` 明文，`P4CANARY_` 均可被 `SecretRedactor` 识别；
- [ ] `NOT_VISIBLE / AMBIGUOUS` 未被脱敏进入 Core，无模板扩写痕迹。

