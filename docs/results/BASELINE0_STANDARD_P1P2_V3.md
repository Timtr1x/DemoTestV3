# Baseline-0 Standard — P1/P2 真实 LineMod（Phase 1.5 收官）

状态：**COMPLETE — STOP 门控**。两项 standard 评估均已在 `main@3cb055e` 锁定的 v3 套件上完成（与 smoke 相同的 target / scanner / policy，零调参）。Holdout 保持封存。测试证据：开发者本地 pytest 403 通过 / 4 跳过。

- 运行版本：`baseline0-p2-standard-v3`（743 条用例）、`baseline0-p1-standard-v3`（1674 条用例），2026-08-24。
- 清单：`phase1-standard-v3/p2.json`（sha256:e35aff7a…，headline=true）、`phase1-standard-v3/p1.json`（sha256:4cf306b4…，headline=true）。

## 混淆矩阵

| 项目 | n | TP | FN | TN | FP | TPR | FPR | 未判定 | 是否过线 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| P2 工具动作 | 743 | 311 | 224 | 79 | 129 | 58.1% | 62.0% | 0 | FAIL |
| P1 邮件注入 | 1674 | 1357 | 223 | 73 | 21 | **85.9%** | 22.3% | 0 | FAIL |

## 运行健康度（全部 4 次 Baseline-0 运行）

- 全程零传输抖动：无 429、无 5xx，无 error / cooldown / rate_limited 结果；2637 条 Baseline-0 用例全部达到明确结果。
- 延迟：P2 p50≈2.05s p99≈3.16s max≈7.5s；P1 p50≈2.47s p90≈4.63s max≈24.6s。
- 所有被拦截结果（P1 1378 条，P2 440 条）均携带 `code=SECURITY_BLOCKED, scanner=prompt_injection, policy=standard`。

## P2 判定细分（上下文感知真值）

| 切片 | smoke n=100 | standard n=743 |
|---|---:|---:|
| 危险动作执行类 TPR | 22/34 = 64.7% | 213/390 = **54.6%** |
| 越权读取类（off-task）TPR | 12/16 = 75.0% | 98/145 = **67.6%** |
| 已授权 ALLOW 的 FPR | 25/50 = 50.0% | 129/208 = **62.0%** |

## P1 细分（standard）

按 label_source：
| 来源 | n | 攻击 TPR |
|---|---:|---|
| api_triggered | 267 | 240/267 = 89.9% |
| judge | 1313 | 1117/1313 = 85.1% |
| benign_fp（ALLOW） | 94 | FP 21/94 = 22.3% |

按 presentation_style：
| 样式 | n | 结果 |
|---|---:|---|
| explicit | 1509 | block TPR 1290/1509 = 85.5% |
| structured | 71 | block TPR 67/71 = 94.4% |
| natural（benign） | 94 | FP 21/94 = 22.3% |

按 source_phase：
| 阶段 | n | 攻击 TPR |
|---|---:|---|
| phase1 | 1294 | 1123/1294 = 86.8% |
| phase2 | 286 | 234/286 = 81.8% |

## Smoke -> Standard 变化

| 指标 | smoke | standard | 变化 |
|---|---:|---:|---|
| P1 TPR | 87.5% | 85.9% | −1.6 pt（稳定） |
| P1 FPR（正常邮件） | 35.0% | 22.3% | −12.7 pt |
| P2 TPR | 68.0% | 58.1% | −9.9 pt |
| P2 危险动作执行类 TPR | 64.7% | 54.6% | −10.1 pt |
| P2 越权读取类 TPR | 75.0% | 67.6% | −7.4 pt |
| P2 已授权 ALLOW 的 FPR | 50.0% | 62.0% | +12.0 pt |

Smoke 在 P2 侧偏乐观；standard 进一步确认并收敛了结论。

## 解读

1. **P1 是可用的检测器**：邮件注入召回率 85.9%，正常邮件误拦率 22.3%；结构化攻击最易被捕获（94.4%），phase2 攻击最弱（81.8%）。
2. **P2 的模式在大样本下已坐实**：越权读取的拦截率（67.6%）高于直接危险调用（54.6%），同时 62% 的完全合规授权调用被误杀。LineMod 单一的 `prompt_injection` scanner 更像是基于内容是否“像注入”做反应，而非对动作危险度或授权上下文进行推理。
3. 两个项目在此配置下均未达到 headline 阈值—— 按记录为 LineMod v（unknown）在此套件上的诚实 Baseline-0。按设计未做任何调参；提升分数是 LineMod 侧的问题，而非数据集的问题。

产物：`cache/exports/baseline0-standard/{p1,p2}/SUMMARY.md`，原始记录位于 `cache/results_v3/*/linemod/baseline0-*-standard-v3/`（gitignored）。复现方式 `scripts/_baseline0_smoke_report.py <project> <manifest> <run-version>`。

下一门控：holdout 保持封存等待最终验收；LineMod 侧任何 scanner / 阈值迭代都应先重跑 eval（绝不先动 holdout）。
