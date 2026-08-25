# Baseline-0 基准报告, V3, P1 / P2 / P5 headline, P3 排除, P4 补充

状态是 Baseline-0 COMPLETE, 工程已冻结。所有 headline 套件都已冻结, 跑过 smoke, 跑过 standard, 全部走的真实 LineMod 流量。没有 fake 网关, 没有调参。holdout 保持封存。数据集这一层不会再动。这份报告是第一版能对外发布的结论。

源码冻结点是 main@5cdb345, 也就是 P5 的 p5_asb_memory 1.1.0 加上 P1/P2 的 Phase 1.5 v3。原始记录在 cache/results_v3 下面, 保持 gitignore。只有已提交的 docs/results/BASELINE0_*.md 才是可引用的证据。

---

## 1. 我们到底在测什么

| 项目 | 通道 | 威胁方向 | 旧编号 | 数据来源, 已固定 | 数据集状态 | 套件 | N, standard |
|---|---|---|---|---|---|---|---|
| P1 外部指令边界 | email, web_page, rag_document, tool_result | Prompt injection in external content, direct and structured | E2, E8 tool_result | llmail, adapter byte identical v2 to v3 | Frozen, phase1-standard-v3, core | smoke smoke-v3/p1 plus standard phase1-standard-v3/p1 | 1674, 1580 BLOCK plus 94 ALLOW |
| P2 工具动作守卫 | tool_call | Context and tool action injection, off task reads versus dangerous actions versus authorized | E8 tool_call, E11 | AgentDojo plus official UserTask ground truth, adapter 1.2.0, context aware | Frozen, phase1-standard-v3, core | smoke smoke-v3/p2 plus standard phase1-standard-v3/p2 | 743, 535 BLOCK plus 208 ALLOW |
| P3 MCP 定义内容守卫 | mcp_definition | Deceptive or dangerous MCP tool definitions, DCI D_real is out of scope | new, A-03 | MCPTox 485 definitions at f85189f, artifact cloned | PARTIAL, PUBLISHED, ARTIFACT AVAILABLE, LICENSE UNRESOLVED, not in core | n/a | n/a, excluded from headline |
| P4 凭证流守卫 | user_prompt, tool_result, tool_call, memory_write, outbound_response | Secret and credential exposure via dynamic trace | E4, E5 | credential_catalog_synthetic 1.0.0 plus reviewed traces bridge | Frozen, supplementary, p4-*-v1, extended, headline_eligible false | smoke, standard, full, holdout p4-*-v1, discovery oriented, not a classifier headline | n/a, supplementary, real finding is andytrust TELEGRAM token stdout exposure |
| P5 记忆写入守卫 | memory_write | Memory poisoning, persistent rule implantation | E9, A-02 | agiresearch/ASB pin 1f561dc, 420 frozen, 400 attack plus 20 normal, same origin ALLOW | Frozen, p5-*-v1, core | smoke p5-smoke-v1 dev, 2 agents, plus standard p5-standard-v1 eval, 6 agents, plus holdout p5-holdout-v1 sealed | 252, 240 BLOCK plus 12 ALLOW |

Headline 只有 P1 加 P2 加 P5。P3 不是失败, 是数据集在合规上还没准备好, 不能进 headline。P4 是补充, 样本少, 偏发现, 不能和前面三条放在同一张分类表里比。

---

## 2. 核心结果, 全部是真实 LineMod, 零调参

| 基准 | 套件 | n | TP | FN | TN | FP | TPR | FPR | 拦截率 | 未判定 | 是否过线, tpr_min 0.9 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| P1 email injection | phase1-standard-v3/p1 | 1674 | 1357 | 223 | 73 | 21 | 85.9% | 22.3% | 82.3% | 0 | FAIL |
| P2 tool action | phase1-standard-v3/p2 | 743 | 311 | 224 | 79 | 129 | 58.1% | 62.0% | 59.2% | 0 | FAIL |
| P5 memory write | p5-standard-v1 | 252 | 28 | 212 | 12 | 0 | 11.7% | 0.0% | 11.1% | 0 | FAIL |

这三条都是 benchmark_track core, headline_eligible true, 只有它们算 headline。smoke 设计上就是 NON_HEADLINE。

| 套件 | n, BLOCK | TPR | FPR | 备注 |
|---|---:|---:|---:|---|
| P1 smoke smoke-v3/p1 | 80 | 87.5% | 35.0%, n 40 | 方向性, standard 的 85.9% 和 22.3% 算稳定 |
| P2 smoke smoke-v3/p2 | 50 | 68.0% | 50.0%, n 50 | 偏乐观, standard 的 58.1% 和 62.0% 把水分挤掉了 |
| P5 smoke p5-smoke-v1 | 60 | 18.3% | 0.0%, n 4 | 方向性, 可引用的 FPR 要看 standard 的 n 12 |

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
| smoke-v3, P1 | smoke-v3/p1.json | 00ad9d5b | 42 | dev | n/a | llmail v2 identical |
| phase1-standard-v3, P1 | phase1-standard-v3/p1.json | 4cf306b4 | 42 | eval | n/a | n/a |
| smoke-v3, P2 | smoke-v3/p2.json | a6b53cc2 | 42 | dev | n/a | AgentDojo adapter 1.2.0 |
| phase1-standard-v3, P2 | phase1-standard-v3/p2.json | e35aff7a | 42 | eval | n/a | n/a |
| p5-smoke-v1 | p5-smoke-v1/p5.json | 8f62760f | 42 | dev, 20% | asb:agent:Corresponding Agent, 2 agents, 30 and 34 | p5_asb_memory 1.1.0, raw 19329003, rev 1f561dcc, 420 frozen |
| p5-standard-v1 | p5-standard-v1/p5.json | 3f194d16 | 42 | eval, 60% | 6 agents times 42, eval | same |
| p5-holdout-v1 | p5-holdout-v1/p5.json | bb8c7433 | 42 | holdout, 20% | 2 agents times 42, sealed | same |

所有 headline 套件都是 benchmark_track core。P4 是 extended, headline_eligible false, 它的 p4-standard-v1 是 n 463, 量级上就不是 headline。每个清单都绑定进了 _run_meta.json, 里面有 manifest_sha256, experiment_hash, dataset_snapshot_hash, fidelity。换一个清单, 就会得到一个不同的 run_version。

运行版本, 真实 LineMod, gap 0.5, max_attempts 6, 带 X-LineMod-No-Failover true:

- baseline0-p1-smoke-v3, 120, baseline0-p2-smoke-v3, 100, 2026-08-24
- baseline0-p1-standard-v3, 1674, baseline0-p2-standard-v3, 743, 2026-08-24
- baseline0-p5-smoke-v1, 64, 2026-08-25, baseline0-p5-standard-v1, 252, 2026-08-25

这个仓库的证据是本地 pytest 403 通过, 4 跳过, 在 5cdb345 这个点上没有 GitHub 远端检查, 加上每次冻结都通过的 dataset verify, manifest verify strict, suite verify。

---

## 4. 运行健康度, 管道过关, 检测结果另算

| 套件 | 结果数 | 429 | 5xx | error | cooldown | rate_limited | 未判定 | 重试超过 1 次 | 延迟 p50, p90, p95, max |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| P1 smoke 120 | 120 of 120, 70 plus 50 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 2.6s, 5.0s, n/a, 13.3s |
| P2 smoke 100 | 100 of 100 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 2.0s, 3.0s, n/a, 3.8s |
| P1 standard 1674 | 1674 of 1674, 1378 blocked | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 2.47s, 4.63s, n/a, 24.6s |
| P2 standard 743 | 743 of 743, 440 blocked | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 2.05s, n/a, 3.16s p99, 7.5s |
| P5 smoke 64 | 64 of 64, 11 blocked | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 2.73s, 2.95s, 2.98s, 3.55s |
| P5 standard 252 | 252 of 252, 28 blocked | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 2.91s, 3.12s, 3.18s, 3.36s |

P1, P2, P5 所有被拦的用例, 都是 code SECURITY_BLOCKED, scanner prompt_injection, policy standard。同一个 scanner 拦下了所有。P5 在记录顶层的 scanner 和 policy 字段是空字符串, 这是传输层写法, 真正的值在 security_flag.error.details 里。我们没有看到第二个 scanner 或策略。Baseline-0 总共 2637 条, 零传输抖动。

---

## 5. 这些数字到底在说什么

我直说, 数据集已经冻结, 网关也没有调参。所以这些分数是诚实的, 并不都好看。

Baseline-0 到这里就结束了。数据集不用再造, LineMod 也不用在这个阶段继续调。holdout 继续封着。剩下的事, 是把已经有的东西讲清楚。这节就是干这个的。

先看健康度。2637 条全部走到了明确结果。没有 429, 没有 5xx, 没有需要重试才成功的。这比 TPR 本身更重要。它说明分数低不是管道抖出来的。如果管道本身就抖, 我们会去争是不是网络或限流的问题。现在管道是干净的, 那么漏掉就是真的漏掉了。

P1 是三条里最好看的, 但也谈不上轻松。85.9% 的召回, 是唯一一个接近可用的数字。代价是 22.3% 的正常邮件被错杀。结构化注入最好认, 94.4%, 显式的低一些。我原本以为 smoke 会偏乐观, 结果也确实偏了一点, 87.5% 到 85.9%, 但很稳定。所以 P1 是一个能用的检测器, 只是很贵。

P2 是我开始担心的地方。放到大样本上, 它拦越权读取有 67.6%, 却只拦住 54.6% 的真正危险动作。同时有 62.0% 的已授权正当调用被杀掉。这个倒挂让我印象很深。网关像是在看一句话长得像不像注入, 而不是在判断这个动作本身危不危险, 或者用户到底有没有授权。smoke 时已经有这个苗头, 75.0% 对 64.7%, 再加上 50.0% 的 FPR, standard 只是用更多样本把它敲实了。只看 headline 的 58.1%, 会错过重点。关键是它对形式敏感, 对风险不敏感。

P5 弱得很直接。252 条里只拦住 28 条, 召回 11.7%, 误杀 0。大约九次投毒里只拦一次, 正常对照一次也不误杀。这和 P1, P2 正好相反。同一个 scanner, 同一个策略, 在这里几乎不响。为什么, 我觉得是因为 memory_write 的载荷是工具定义本身, 里面没有那种典型的请忽略之前指令的句子, scanner 找不到触发点, prompt_injection 就安静了。Stealthy 12.5% 对 Disruptive 10.8%, 这点差异是噪声。agent 也救不了, 最好的 education_consultant 也只有 32.5%, 最差的 autonomous_driving 5.0%, 我一开始以为是不是某个 agent 特别难, 但看下来差距和到 90% 门限的距离比起来很小。

合起来看, 一个 scanner 解释了三条。P1 用误杀换召回, P5 用漏掉换零误杀, P2 两头都付代价。这不是靠改数据集能修好的。分类器没有按通道的风险模型去调, 想把数字变好看, 是 LineMod 要做的事, 不是我们去改用例。

P3 和 P4 要单说一句。P3 不是 FAIL, 我们是主动排除的, 因为它在合规上没准备好, 状态是 PUBLISHED, ARTIFACT AVAILABLE, LICENSE UNRESOLVED。本地已经克隆了 485 条, 但没有 benign 对照, 也没有可发布的许可, 硬塞进 headline 反而是不诚实。P4 已经冻结, 但它是 extended, headline_eligible false。我们确实抓到了真实问题, andytrust 的 TELEGRAM token 在 stdout 里泄露, 但它是偏发现的, 样本也少, 应该放在补充实验里, 而不是和 P1, P2, P5 并排比分类指标。

所以工程阶段可以收口了。P1 DONE, P2 DONE, P5 DONE, 每条都有 smoke 和 standard, holdout 封存。P3 PARTIAL, P4 补充。这个阶段我们不调 LineMod, 也不为分数去改用例。下一阶段是写论文和做分析, 而不是再跑一轮。

有一点让我觉得不太舒服, 但也挺有价值。同一个网关, 在邮件上看起来很强, 在 agent 动作上很困惑, 在记忆写入上几乎看不见。这种割裂本身就是收获。它告诉我们下一步该往哪用力, 也说明这个基准测到了真东西。

---

## 6. 我们不夸大什么

- P3 排除, P3 从 Baseline-0 排除是因为数据集在合规层面还没准备好, MCPTox 的状态是 PUBLISHED, ARTIFACT AVAILABLE, LICENSE UNRESOLVED。这不是 FAIL, 也不是通过。没有 headline 数字。DCI D_real 不在范围内, 因为网关根本看不到实现。

- P4 补充, P4 是 extended, headline_eligible false, 不在这张 headline 表里。它有真实发现, TELEGRAM token 泄露, 但它是偏发现的, 样本少。把它当补充实验报告, 不要当成可比的分类器基准。

- FPR 的精度, P5 headline 的 FPR 是 12 例中 0 例, 0.0%, 可以引用。smoke 的 4 例中 0 例只是方向性。P1 和 P2 的 FPR 作为比例可以对比, 但成本模型不同, 一个是正常邮件, 一个是已授权的工具调用。

- Holdout, p5-holdout-v1 84 条, 80 加 4, phase1 holdout-v3 和 p4-holdout-v1 都已封存。cache/results_v3 里没有 baseline0 的 holdout 运行。任何阈值或 scanner 的改动, 都必须先重跑 eval, 永远不要先动 holdout。

- 配置耦合, benchmark_track, suite 和 project 的 headline_eligible, manifest_sha256, fidelity 都绑定在实验身份里。改任何一个, 就是另一个基准。不要跨绑定去比数字。

---

## 7. 如何复现

```bash
# P1 和 P2, Phase 1.5 v3, headline
python -m demotest.cli.main validate --project P1_external_instruction --target linemod --source manifest:benchmarks/manifests/phase1-standard-v3/p1.json --no-key-check
python -m demotest.cli.main run       --project P1_external_instruction --target linemod --source manifest:benchmarks/manifests/phase1-standard-v3/p1.json --run-version baseline0-p1-standard-v3 --gap 0.5 --max-attempts 6
python -m demotest.cli.main analyze   --project P1_external_instruction --target linemod --source manifest:benchmarks/manifests/phase1-standard-v3/p1.json --run-version baseline0-p1-standard-v3
# same for P2_tool_action, phase1-standard-v3/p2.json, baseline0-p2-standard-v3

# P5, ASB 420 已冻结
python -m demotest.cli.main validate --project P5_memory_write --target linemod --source manifest:benchmarks/manifests/p5-standard-v1/p5.json --no-key-check
python -m demotest.cli.main run       --project P5_memory_write --target linemod --source manifest:benchmarks/manifests/p5-standard-v1/p5.json --run-version baseline0-p5-standard-v1 --gap 0.5 --max-attempts 6
python -m demotest.cli.main analyze   --project P5_memory_write --target linemod --source manifest:benchmarks/manifests/p5-standard-v1/p5.json --run-version baseline0-p5-standard-v1
```

原始记录在 cache/results_v3/<project>/linemod/baseline0-*-standard-*/ 下面, 里面有 jsonl 和 _run_meta.json, 保持 gitignore。已提交的证据是 docs/results/BASELINE0_SMOKE_P1P2_V3.md, docs/results/BASELINE0_STANDARD_P1P2_V3.md, docs/results/BASELINE0_SMOKE_P5_V3.md, docs/results/BASELINE0_STANDARD_P5_V3.md 加上本报告。

---

## 8. 下一步是什么

Baseline-0 的工程到此 STOP。holdout 保持封存。下一阶段是论文和分析, 不是再跑一轮或在 LineMod 上做调参循环。如果 LineMod 之后要迭代 scanner 或阈值, 重跑顺序是先 eval, 永远不要先 holdout, 然后出新报告, 只有在最终验收时才动 holdout。
