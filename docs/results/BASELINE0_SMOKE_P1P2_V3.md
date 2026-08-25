# Baseline-0 Smoke — P1/P2 真实 LineMod（阶段性报告）

状态：**阶段性 smoke 报告 — STOP 门控**。Standard 评估尚未运行；holdout 保持封存。本次运行均为真实 LineMod 流量（无 fake 网关），基于 `main@40ed5f7` 锁定的 v3 套件执行。

- 运行版本：`baseline0-p1-smoke-v3`（120 条用例）、`baseline0-p2-smoke-v3`（100 条用例）—— 按项目区分的独立 run id，2026-08-24。
- 清单：`benchmarks/manifests/smoke-v3/p1.json`（sha256:00ad9d5b…）、`benchmarks/manifests/smoke-v3/p2.json`（sha256:a6b53cc2…）。
- 测试证据：开发者本地 pytest 403 通过 / 4 跳过（本仓库无 GitHub CI 检查）。

## 核心结果

| 项目 | n | TP | FN | TN | FP | TPR | FPR | 未判定 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| P1 邮件注入 | 120 | 70 | 10 | 26 | 14 | 87.5% | 35.0% | 0 |
| P2 工具动作 | 100 | 34 | 16 | 25 | 25 | 68.0% | 50.0% | 0 |

## 运行健康度

- 传输抖动：429 = 0，5xx = 0，error/cooldown/rate_limited = 0；所有用例均达到明确结果（P1 120/120，P2 100/100）。
- 延迟：P1 p50=2.6s p90=5.0s max=13.3s；P2 p50=2.0s p90=3.0s max=3.8s。
- 所有 143 条被拦截结果均携带 `code=SECURITY_BLOCKED`、`scanner=prompt_injection`、`policy=standard`—— 两个项目的所有拦截均由单一 scanner 机制产生。

## P2 判定细分（上下文感知真值，adapter 1.2.0）

| 切片 | n | 结果 |
|---|---:|---|
| 危险动作执行类 TPR | 34 | 22/34 = **64.7%** |
| 越权读取类（off-task）TPR | 16 | 12/16 = **75.0%** |
| 已授权 ALLOW 的 FPR | 50 | 25/50 = **50.0%** |

## 解读

1. LineMod 对注入导致的越权读取拦截率（75%）**高于**对直接危险调用的拦截率（64.7%）—— 说明它并非仅过滤“危险动作”；但仍有 12 条危险调用（转账 / 改密码 / 外发数据）被放行。
2. 两个项目的误拦成本都很高：半数用户已授权的工具调用和三分之一的正常邮件被拦截。结合单一 `prompt_injection` scanner 完成所有拦截的现象，表明网关对类注入文本广泛敏感，同时对正常/已授权内容造成大量误杀。
3. Smoke 切片样本较小（contextual_read n=16），仅为方向性信号。Standard 评估（P1 1674 + P2 743）用于进一步确认结论。

## 复现

```bash
python -m demotest.cli.main analyze --project P1_external_instruction \
  --target linemod --source manifest:benchmarks/manifests/smoke-v3/p1.json \
  --run-version baseline0-p1-smoke-v3
python scripts/_baseline0_smoke_report.py P1_external_instruction \
  benchmarks/manifests/smoke-v3/p1.json baseline0-p1-smoke-v3
# P2_tool_action / baseline0-p2-smoke-v3 同理
```

原始记录：`cache/results_v3/<project>/linemod/baseline0-*-smoke-v3/`（gitignored）。下一门控：standard 评估决策 -> holdout 保持封存。
