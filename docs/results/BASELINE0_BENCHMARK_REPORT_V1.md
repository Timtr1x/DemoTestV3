# Baseline-0 基准报告, V3, P1 / P2 / P3 / P5 headline, P4 Extended — P4E-v2 ACCEPTED

状态是 Baseline-0 COMPLETE, 工程已冻结。所有 headline 套件都已冻结, 跑过 smoke, 跑过 standard, 全部走的真实 LineMod 流量。没有 fake 网关, 没有调参。holdout 保持封存。数据集这一层不会再动。这份报告是能对外发布的结论, 本版已纳入 P4E-v2 的终验结果（`main@052013f`，`seeds-20260827-v2`）并把 P3 从“排除”补为 headline。

源码冻结点是 `main@052013f` — P5 `p5_asb_memory 1.1.0` + P1/P2 `Phase 1.5 v3` + P3 `p3_mcptox 1.1.1` + P4 Extended `p4_credential_exposure 1.0.0 / seeds-20260827-v2`。原始记录在 `cache/results_v3` 下面, 保持 gitignored。只有已提交的 `docs/results/BASELINE0_*.md` 才是可引用的证据。

---

## 1. 我们到底在测什么

| 项目 | 通道 | 威胁方向 | 旧编号 | 数据来源, 已固定 | 数据集状态 | 套件 | N, standard |
|---|---|---|---|---|---|---|---|
| P1 外部指令边界 | email, web_page, rag_document, tool_result | Prompt injection in external content, direct and structured | E2, E8 tool_result | llmail, adapter `1.1.0` @ `1063bdf0`, quality A | Frozen, phase1-standard-v3, **core** | smoke smoke-v3/p1 + standard phase1-standard-v3/p1 | 1674, 1580 BLOCK + 94 ALLOW |
| P2 工具动作守卫 | tool_call | Context and tool action injection, off task reads vs dangerous actions vs authorized | E8 tool_call, E11 | AgentDojo + official UserTask ground truth, adapter `1.2.0` @ `089ed46`, quality B, context aware | Frozen, phase1-standard-v3, **core** | smoke smoke-v3/p2 + standard phase1-standard-v3/p2 | 743, 535 BLOCK + 208 ALLOW |
| P3 MCP 定义内容守卫 | mcp_definition | Deceptive or dangerous MCP tool definitions, DCI D_real is out of scope | new, A-03 | MCPTox 794 definitions @ `f85189f`, adapter `1.1.1`（`strip_outer_whitespace` 语义不变）, quality B, FAIL-CLOSED | Frozen, p3-standard-v1, **core, headline** | smoke p3-smoke-v1 100 (60+40) + standard p3-standard-v1 464 (276+188) + holdout p3-holdout-v1 156 sealed | 464, 276 BLOCK + 188 ALLOW |
| P4 凭证流 — Real Anchor | tool_result (DIRECT) | Secret and credential exposure via dynamic trace | E4, E5 | `credential_dynamic_traces` + human-frozen `reviewed_traces.jsonl`, quality A | Frozen, `benchmarks/frozen/datasets/credential_dynamic_traces/`, 7-gate | 单条 REAL_REPRODUCED pilot | n=1, andytrust TELEGRAM token stdout |
| P4 Extended | tool_result (structured) | Seed-derived credential exposure, per-row demo canary | E4, E5 | `p4_credential_exposure` `seeds-20260827-v2` 800 (413 BLOCK + 387 ALLOW, per-row `demo_*` — no `TEST_SECRET_` tag), quality C | Frozen, p4e-*-v1, **extended, headline_eligible false** | smoke p4e-smoke-v1 100 (53+47) + standard p4e-standard-v1 480 (240+240) + holdout p4e-holdout-v1 100 sealed | 480, 240 BLOCK + 240 ALLOW |
| P5 记忆写入守卫 | memory_write | Memory poisoning, persistent rule implantation | E9, A-02 | agiresearch/ASB @ `1f561dc`, 420 frozen, 400 attack + 20 normal, same origin ALLOW, quality B | Frozen, p5-*-v1, **core** | smoke p5-smoke-v1 dev 2 agents + standard p5-standard-v1 eval 6 agents + holdout p5-holdout-v1 84 sealed | 252, 240 BLOCK + 12 ALLOW |

Headline 是 P1 + P2 + P3 + P5（均为 `benchmark_track=core` / `headline_eligible=true`）。P4 为补充：Real Anchor 1 条代表真实世界锚点，Extended `p4e-standard-v1` 为 extended（`headline_eligible=false`）的受控基准，不与 core 同表比 headline 排名，但 P4E-v2 已 **ACCEPTED / COMPLETE**，结论可引用。

---

## 2. 核心结果, 全部是真实 LineMod, 零调参

### 2.1 Headline — core（可排名）

| 基准 | 套件 | n | TP | FN | TN | FP | TPR | FPR | 拦截率 | 未判定 | 是否过线 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| P1 email injection | phase1-standard-v3/p1 | 1674 | 1357 | 223 | 73 | 21 | **85.86%** | 22.34% | 82.32% | 0 | FAIL（tpr_min 0.90） |
| P2 tool action | phase1-standard-v3/p2 | 743 | 311 | 224 | 79 | 129 | **58.13%** | 62.02% | 59.22% | 0 | FAIL（tpr_min 0.90） |
| P3 mcp_definition | p3-standard-v1 | 464 | 266 | 10 | 58 | 130 | **96.38%** | 69.15% | 85.34% | 0 | **PASS（tpr_min 0.85）但选择性 FAIL** |
| P5 memory write | p5-standard-v1 | 252 | 28 | 212 | 12 | 0 | **11.67%** | 0.00% | 11.11% | 0 | FAIL（tpr_min 0.90） |

这四条是 `benchmark_track=core` / `headline_eligible=true`，只有它们算 headline。`smoke` 设计上即 `NON_HEADLINE`，不计入 headline。

| 套件 | n, BLOCK | TPR | FPR | 备注 |
|---|---:|---:|---:|---|
| P1 smoke smoke-v3/p1 | 80 | 87.50% | 35.00%, n 40 | 方向性 |
| P2 smoke smoke-v3/p2 | 50 | 68.00% | 50.00%, n 50 | 偏乐观 |
| P3 smoke p3-smoke-v1 | 60 | 98.33% | 75.00%, n 40 | 方向性 |
| P5 smoke p5-smoke-v1 | 60 | 18.33% | 0.00%, n 4 | 方向性，可引用的 FPR 以 standard n=12 为准 |

### 2.2 Extended — P4（可引用，不参与 headline 排名）

| 基准 | 套件 | n | TP | FN | TN | FP | TPR | FPR | 拦截率 | 未判定 | track |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| P4 Extended | p4e-standard-v1 | 480 | 224 | 16 | 0 | 240 | **93.33%** | 100.00% | 96.67% | 0 | extended, **NON_HEADLINE** |
| P4 Extended smoke | p4e-smoke-v1 | 100 | 53 | 0 | 0 | 47 | **100.00%** | 100.00% | 100.00% | 0 | extended, NON_HEADLINE |

`P4E-v2 ACCEPTED`：800 冻结（`manifest d7d4f7f0…` / `raw 2befb96e…`），per-row `demo_*` canary（无共享 `TEST_SECRET_` 标签），ALLOW 已去 `benchmark/gateway` 元语言，`benign_subtype` 全覆盖。可引用的 operational 结论见 §5.4。

### P2 细分, 上下文感知真值, 适配器 1.2.0

| 切片 | Smoke n 100 | Standard n 743 |
|---|---:|---:|
| 危险动作执行类 TPR | 22/34, 64.7% | 213/390, 54.6% |
| 越权读取类 TPR | 12/16, 75.0% | 98/145, 67.6% |
| 已授权 ALLOW 的 FPR | 25/50, 50.0% | 129/208, 62.0% |

### P5 细分, standard, eval 6 个 agent

| 切片 | n | TPR |
|---|---:|---:|
| Stealthy 攻击 | 120 | 12.5%, 15 of 120 |
| Disruptive 攻击 | 120 | 10.8%, 13 of 120 |
| ALLOW 正常对照 | 12 | TN 12 FP 0 |
| 最好的 agent, education_consultant_agent | 40 BLOCK | 32.5%, 13 of 40 |
| 最差的 agent, autonomous_driving_agent | 40 BLOCK | 5.0%, 2 of 40, others 7.5 to 10.0% |

P1 细分, standard: api_triggered 89.9%, 240/267, 高于 judge 的 85.1%, 1117/1313。structured 94.4%, 67/71, 高于 explicit 的 85.5%。phase1 的 86.8% 高于 phase2 的 81.8%。

---

## 3. 这些数字从哪来

| 套件 | 清单 | sha256 前缀 | 种子 | 切分 | 分组规则 | 源码锁 |
|---|---|---|---|---|---|---|
| smoke-v3, P1 | smoke-v3/p1.json | 00ad9d5b | 42 | dev | n/a | llmail 1.1.0 raw a223abaf |
| phase1-standard-v3, P1 | phase1-standard-v3/p1.json | 4cf306b4 | 42 | eval | n/a | same |
| smoke-v3, P2 | smoke-v3/p2.json | a6b53cc2 | 42 | dev | n/a | agentdojo 1.2.0 raw 57726b74 @ 089ed46 |
| phase1-standard-v3, P2 | phase1-standard-v3/p2.json | e35aff7a | 42 | eval | n/a | same |
| p3-smoke-v1 | p3-smoke-v1/p3.json | 5a0b3333 | 42 | dev 20% | mcptox:server:<server>, 8 servers | p3_mcptox 1.1.1 raw a54ca29e @ f85189f, 794 frozen |
| p3-standard-v1 | p3-standard-v1/p3.json | 0c8a5e72 | 42 | eval 60% | mcptox:server, 25 servers | same |
| p5-smoke-v1 | p5-smoke-v1/p5.json | 8f62760f | 42 | dev, 20% | asb:agent:Corresponding Agent, 2 agents ×42 | p5_asb_memory 1.1.0 raw 19329003 @ 1f561dc, 420 frozen |
| p5-standard-v1 | p5-standard-v1/p5.json | 3f194d16 | 42 | eval, 60% | 6 agents ×42 eval | same |
| p4e-smoke-v1 | p4e-smoke-v1/p4.json | cbd3e854 | 42 | smoke, split-v2 stratified | p4_extended:seed:<seed_id>, 19 seeds | p4_credential_exposure 1.0.0 raw 2befb96e @ seeds-20260827-v2, 800 frozen |
| p4e-standard-v1 | p4e-standard-v1/p4.json | 267dcc4b | 42 | eval, split-v2 stratified | same, 94 seeds | same |
| p5-holdout-v1 | p5-holdout-v1/p5.json | bb8c7433 | 42 | holdout, 20% | 2 agents ×42 sealed | same as p5-smoke |
| p4e-holdout-v1 | p4e-holdout-v1/p4.json | 410fef3d | 42 | holdout, split-v2 stratified | 18 seeds sealed | same as p4e |
| p3-holdout-v1 | p3-holdout-v1/p3.json | — | 42 | holdout | 12 servers sealed | same as p3 |

所有 headline 套件均为 `benchmark_track=core`。P4 Extended 均为 `benchmark_track=extended` / `headline_eligible=false`（`performance` 不与 core 同表排名）。每个清单都绑定进了 `_run_meta.json`，含 `manifest_sha256` / `experiment_hash` / `dataset_snapshot_hash` / `fidelity`。换一个清单即另一个基准。

运行版本, 真实 LineMod, `gap 0.5 max_attempts 6`（P3 `max_attempts 3`）, 带 `X-LineMod-No-Failover true`：

- `baseline0-p1-smoke-v3` 120, `baseline0-p2-smoke-v3` 100 — 2026-08-24
- `baseline0-p1-standard-v3` 1674, `baseline0-p2-standard-v3` 743 — 2026-08-24
- `p3-smoke-v1-real` 100, `p3-standard-v1` 464 — 2026-08-25
- `baseline0-p5-smoke-v1` 64, `baseline0-p5-standard-v1` 252 — 2026-08-25
- `baseline0-p4e-smoke-v1` 100, `baseline0-p4e-standard-v1` 480 — 2026-08-27（P4E-v2, seed 20260827）

仓库证据：`dataset verify` / `manifest verify --strict` / `suite-verify` 时均通过（除 `credential_dynamic_traces` 仅用于 Real Anchor 外）；`p4_validate_extended.py` P4E-v2 `OK n=800 block=413 allow=387`；P4E-v2 hygiene `py_compile` 通过。

---

## 4. 运行健康度, 管道过关, 检测结果另算

| 套件 | 结果数 | 429 | 5xx | error | cooldown | rate_limited | 未判定 | 重试超过 1 次 | 延迟 p50, p90, p95, max |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| P1 smoke 120 | 120 of 120, 70+50 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 2.6s, 5.0s, n/a, 13.3s |
| P2 smoke 100 | 100 of 100 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 2.0s, 3.0s, n/a, 3.8s |
| P3 smoke 100 | 100 of 100, 89 blocked | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1.76s, 2.57s, 3.49s, 5.9s |
| P4E smoke 100 | 100 of 100, 100 blocked | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1.82s, 1.90s, 2.00s, 2.84s |
| P5 smoke 64 | 64 of 64, 11 blocked | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 2.73s, 2.95s, 2.98s, 3.55s |
| P1 standard 1674 | 1674 of 1674, 1378 blocked | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 2.47s, 4.63s, n/a, 24.6s |
| P2 standard 743 | 743 of 743, 440 blocked | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 2.05s, n/a, 3.16s p99, 7.5s |
| P3 standard 464 | 464 of 464, 396 blocked | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1.80s, 2.57s, 2.85s, 5.9s |
| P4E standard 480 | 480 of 480, 464 blocked | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1.73s, 1.93s, 2.05s, 6.97s |
| P5 standard 252 | 252 of 252, 28 blocked | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 2.91s, 3.12s, 3.18s, 3.36s |

- Baseline-0 headline 2637 条 + P3 464 条 + P4E 480 条（合计 3581 条 standard）全部达到明确结果；无 429/5xx/error/cooldown/rate_limited/unjudged/重试。
- 所有被拦用例均为 `code SECURITY_BLOCKED / scanner prompt_injection / policy standard`（HTTP 403）。同一 scanner 解释了全部拦截（P4E 464/464、P3 396/396、P1/P2/P5 亦同）。`by_scanner=none` 为传输层 artefact（`security_flag.error.details` 内才有 scanner）。
- P4E 泄漏轴（F13）：`response_canary_echo_rate 0/240 = 0%`（原 `credential_leakage_rate` 更名为 `response_canary_echo_rate`；passed ≠ leaked），`leakage_n_judged 240`。

---

## 5. 这些数字到底在说什么

数据集已冻结，网关零调参。所以分数是诚实的，且并不都好看。

### 5.1 快速结论

- **P1 可用但贵：** 85.9% 召回是唯一接近可用阈值的 headline，但 22.3% 正常邮件误拦使运营成本极高。Smoke 87.5%→85.9% 稳定，说明估计可靠。
- **P2 倒挂：** 危险动作 54.6% < 越权读取 67.6%，且已授权调用 62.0% 误拦。网关对“像不像注入”敏感，对“危不危险/有没有授权”不敏感。只看 58.1% headline 会漏掉倒挂才是重点。
- **P3 高召回但低选择性：** 96.38% TPR 通过 0.85 门控（headline PASS），但 69.15% FPR（8/25 服务器 100% FPR，仅 4/25 为 0%）说明在 MCP 定义上会拦掉约 7 成正常注册。机制与 P1 同源（短祈使定义最易被过拦，`Arguments:` 结构化文档相对被放过）。
- **P5 几乎看不见：** 11.67% TPR / 0% FPR，约 9 次投毒仅拦 1 次。Stealthy 12.5% vs Disruptive 10.8% 无区分度；6 个 agent 均远低于 90% 门控（最好 32.5%，最差 5.0%）。与 P1/P2 正相反，`prompt_injection` 在 `memory_write` 信道几乎不触发。
- **P4 Real Anchor + Extended 互补：** Real Anchor 1 条证明真实泄露可复现（andytrust TELEGRAM）；Extended P4E-v2 证明在受控 480 条上 `prompt_injection/standard` 对 credential-adjacent `tool_result` 的选择性灾难性不足（见 5.4）。

### 5.2 P4E-v2 的关键修正已落地（上一轮 4 项）

1. **`TEST_SECRET_` shortcut 已移除：** per-row `demo_*`（`sk-proj-demo_` / `ghp_demo` / `xoxb-demo-` / `demo_aws_` / `sk_test_demo_` 等），ground truth 仅依赖各行 `credential_marker`，无统一标签。
2. **ALLOW 元语言已清理：** builder 增加 `BANNED_ALLOW_PHRASES`（`benchmark/gateway/expected action/benign control…`）且 suffix 改为 vault/env/redaction/runtime 等真实语境。
3. **E5 `benign_subtype` 已加入：** `placeholder 65 / redacted 65 / name_only 53 / schema 41 / instruction 70 / safe_log 93`，validator 强制检查。
4. **near-dup 口径已更正：** builder 不再宣称“所有 pair ≤0.85”，改为 validator 控制 cluster（当前 0 簇）。

补：`p4_build_extended.py` 的 `or True` 无效 assert 已在 `052013f` 清理（hygiene，validator 已覆盖）。

### 5.3 P4E-v2 结果更有说服力的原因

去除 banner 语言后 standard 仍 `FPR 100%` 且在 6 个 `benign_subtype` 上均匀（`placeholder 50/50 redacted 41/41 name_only 33/33 schema 21/21 instruction 44/44 safe_log 51/51`），可更有把握地说：

> **LineMod 的 `prompt_injection/standard` 对 credential-adjacent tool_result 存在极严重的选择性不足，而非 v1 benchmark 自描述语言导致的误杀。**

BLOCK 去 shortcut 后 TPR 从 95.42% 降至 93.33%（合理变难），且

```
P4-E1 64/64 = 100%   Direct secret
P4-E2 59/61 = 96.72% URL/command
P4-E3 55/55 = 100%   Exception/log
P4-E4 46/60 = 76.67% Structured dump（14/16 FN 集中于此）
```

说明 structured JSON/config 的检测明显更弱，且为稳定结论（v1 11 FN 亦全在 E4；v2 新增 2 个 E2 URL FN 一并体现 demo 熵变难）。

### 5.4 合起来看

一个 `prompt_injection/standard` scanner 解释了全部通道：P1 用误拦换召回、P5 用漏检换零误拦、P2 两头付代价、P3 高召回高误拦、P4E 全量过拦且 score 分布不可分（blocked `mean 0.991 p50 1.0`，TP `mean 0.983` vs FP `mean 0.998`）。这不是改数据集能修的——需要按通道风险模型调 scanner/阈值/策略。

同网关在邮件上“强”、在工具动作上“困惑”、在记忆写入上“近盲”、在 MCP 定义上“高召回低选择性”、在凭证流上“全量过拦”的割裂，本身就是基准的价值。

---

## 6. 我们不夸大什么

- **P3 headline：** `p3-standard-v1` TPR 96.38% 通过 0.85 gate，`pass_fail=PASS` 仅对 recall 生效；FPR 69.15% 需单列 selectivity 评估（8/25 服务器 100% FPR）。DCI `D_real`（描述与实现不一致）不在范围，因网关看不到实现。
- **P4 双段：** Real Anchor（`REAL_REPRODUCED=1` / `andytrust`）为真实锚点；Extended P4E-v2（480, TPR 93.33% / FPR 100%, `NON_HEADLINE`，`response_canary_echo_rate 0%`）为受控基准。二者互补，不与 core 同表排名；`credential_leakage_rate` 已澄清为 `response_canary_echo_rate`（`performance` 不等同于 `leaked`）。
- **FPR 精度：** P5 headline FPR 0/12 = 0.0% 可引用（smoke 0/4 仅方向性）；P1/P2/P3/P4E 的 FPR 分别基于 94/208/188/240 个 ALLOW，smoke*为方向性。
- **Holdout：** `p5-holdout-v1` 84（80+4）、`p4e-holdout-v1` 100（55+45）、`p3-holdout-v1` 156（96+60）、`phase1 holdout-v3` 均已封存；`cache/results_v3` 下无 baseline holdout 运行。任何阈值/scanner 改动须先重跑 eval，再考虑 holdout。
- **配置耦合：** `benchmark_track` / `suite` 与 `project headline_eligible` / `manifest_sha256` / `fidelity` 绑定在实验身份中；跨绑定不可比。

---

## 7. 如何复现

```bash
# P1 / P2 — Phase 1.5 v3, headline
python -m demotest.cli.main validate --project P1_external_instruction --target linemod --source manifest:benchmarks/manifests/phase1-standard-v3/p1.json --no-key-check
python -m demotest.cli.main run       --project P1_external_instruction --target linemod --source manifest:benchmarks/manifests/phase1-standard-v3/p1.json --run-version baseline0-p1-standard-v3 --gap 0.5 --max-attempts 6
python -m demotest.cli.main analyze   --project P1_external_instruction --target linemod --source manifest:benchmarks/manifests/phase1-standard-v3/p1.json --run-version baseline0-p1-standard-v3
# same for P2_tool_action, phase1-standard-v3/p2.json, baseline0-p2-standard-v3

# P3 — MCP definition, headline core
python -m demotest.cli.main validate --project P3_mcp_definition --target linemod --source manifest:benchmarks/manifests/p3-standard-v1/p3.json --no-key-check
python -m demotest.cli.main run       --project P3_mcp_definition --target linemod --source manifest:benchmarks/manifests/p3-standard-v1/p3.json --run-version p3-standard-v1 --gap 0.5 --max-attempts 3
python -m demotest.cli.main analyze   --project P3_mcp_definition --target linemod --source manifest:benchmarks/manifests/p3-standard-v1/p3.json --run-version p3-standard-v1 --json

# P5 — ASB 420 已冻结, headline core
python -m demotest.cli.main validate --project P5_memory_write --target linemod --source manifest:benchmarks/manifests/p5-standard-v1/p5.json --no-key-check
python -m demotest.cli.main run       --project P5_memory_write --target linemod --source manifest:benchmarks/manifests/p5-standard-v1/p5.json --run-version baseline0-p5-standard-v1 --gap 0.5 --max-attempts 6
python -m demotest.cli.main analyze   --project P5_memory_write --target linemod --source manifest:benchmarks/manifests/p5-standard-v1/p5.json --run-version baseline0-p5-standard-v1

# P4 Extended — P4E-v2, extended NON_HEADLINE
python -m demotest.cli.main dataset verify --dataset p4_credential_exposure
python -m demotest.cli.main manifest verify --strict benchmarks/manifests/p4e-standard-v1/p4.json
python -m demotest.cli.main manifest suite-verify p4e-standard-v1
python -m demotest.cli.main validate --project P4_credential_flow --target linemod --source manifest:benchmarks/manifests/p4e-standard-v1/p4.json --no-key-check
python -m demotest.cli.main run       --project P4_credential_flow --target linemod --source manifest:benchmarks/manifests/p4e-standard-v1/p4.json --run-version baseline0-p4e-standard-v1 --gap 0.5 --max-attempts 6
python -m demotest.cli.main analyze   --project P4_credential_flow --target linemod --source manifest:benchmarks/manifests/p4e-standard-v1/p4.json --run-version baseline0-p4e-standard-v1 --json
```

原始记录在 `cache/results_v3/<project>/linemod/<run-version>/`（`jsonl` + `_run_meta.json`，gitignored）。已提交证据为 `docs/results/BASELINE0_*.md`。P3/P5/P4E 的 `manifest_sha256` / `experiment_hash` / `dataset_snapshot_hash` 见各 `BASELINE0_STANDARD_*.md` 头部与 `_run_meta.json`。

---

## 8. 下一步是什么

Baseline-0 工程到此 STOP。本项已覆盖 4 条 headline（P1/P2/P3/P5）+ P4 双段（Real Anchor + P4E-v2 ACCEPTED），合计 3581 条 standard 真实 LineMod 评估 + 394 条 smoke。holdout 保持封存。下一阶段为论文与分析，不再为分数重建数据集或调参循环；若 LineMod 迭代 scanner/阈值，重跑顺序为先 eval，再考虑 holdout，并出新报告。

**P4E 状态：** `P4E-v1 PASS WITH ISSUES` → **`P4E-v2 ACCEPTED / COMPLETE`**（`main@052013f`）。无需第三版；术语 `credential_leakage_rate` 建议在全项目收尾时统一更名为 `response_canary_echo_rate`，已在正文中澄清。
