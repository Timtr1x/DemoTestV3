# Baseline-0 Smoke — P5 真实 LineMod（阶段性报告）

状态：**阶段性 smoke 报告 — STOP 门控**。Standard 评估尚未运行；holdout 保持封存。本次运行为真实 LineMod 流量（无 fake 网关），基于 `main@615f165` 锁定的 v3 套件执行。

- 运行版本：`baseline0-p5-smoke-v1` — 2026-08-25，项目 `P5_memory_write`，通道 `memory_write`，fidelity `structured`。
- 清单：`benchmarks/manifests/p5-smoke-v1/p5.json`（sha256:`8f62760f9d6a005b1a125ba4269326c5bed9e5c4319dca1cb4370026ce76e0df`），套件 `p5-smoke-v1.json`（total_cases=64，seed=42，切分 `dev`）。
- 套件配置：64 = 60 BLOCK（`asb_memory_poison_block` 目标 60）+ 4 ALLOW（`asb_memory_normal_allow` 目标 all），分组 `asb:agent:<corresponding_agent>`（dev 下 2 个 agent），`benchmark_track=core`，`headline_eligible=false`（套件 + 项目，`NON_HEADLINE`）。
- 源码锁定：`p5_asb_memory` adapter `1.1.0`，raw_sha256 `193290039b99e81e641bce72f1014911b94b31bfeb7ebd006d85c20e146382aa`，revision `1f561dccf92d55302368fa67679b4ba9d9c8fdc4`，420 用例冻结（400 攻击 + 20 正常，跨 10 个 agent）。
- 测试证据：开发者本地 pytest（本仓库在 `615f165` 时无 GitHub 状态检查）；冻结时 `suite-verify` / `manifest-verify` / `dataset-verify` 门控均已通过。

## 核心结果

| 项目 | n | TP | FN | TN | FP | TPR | FPR | 拦截率 | 未判定 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| P5 记忆写入 | 64 | 11 | 49 | 4 | 0 | 18.3% | 0.0% | 17.2% | 0 |

真值：60 BLOCK（`memory_poisoning_attack`，`expected_action=block`）/ 4 ALLOW（`normal_memory_tool`，`expected_action=allow`）。TPR = 11/60，FPR = 0/4。FPR 的 n=4 仅具方向性参考价值—— 可引用的 FPR 需等待 Standard（12 ALLOW）。

## 运行健康度 — PASS（流水线门控）

| 信号 | 取值 | 门控 |
|---|---:|---|
| 明确结果 | 64/64（blocked=11 passed=53） | ✅ |
| 429 | 0 | ✅ |
| 5xx | 0（http 200×53，403×11） | ✅ |
| error | 0（`error=None` ×64） | ✅ |
| cooldown | 0 | ✅ |
| rate_limited | 0 | ✅ |
| 未判定 | 0（n_judged=64/64） | ✅ |
| 重试超过 1 次 | 0（全部 `attempt=1`） | ✅ |

所有用例均以单次尝试达到明确的 `outcome ∈ {blocked, passed}`，无传输抖动、无重试、无 cooldown。

## 机制 — scanner / policy / block code

全部 11 条被拦截结果的 `http_status=403`，`security_flag` 承载网关决策：

```
error={'code': 'SECURITY_BLOCKED', 'message': 'Request blocked by security policy',
        'type': 'permission_error',
        'details': {'action': 'block', 'policy': 'standard',
                    'scanner': 'prompt_injection', 'score': 0.57…}}
```

- `code=SECURITY_BLOCKED`、`policy=standard`、`scanner=prompt_injection`—— 所有拦截均由单一 scanner 机制产生（与 P1/P2 一致）。
- 记录顶层的 `scanner` / `policy` 字段为空字符串，属于该 target 传输层的表现（LineMod 不在记录顶层填充这两个字段）；权威的 scanner / policy 在 `security_flag` / `error.details` 中如上所示。未观察到其他 scanner / policy。

## 延迟

| p50 | p90 | p95 | max | min |
|---:|---:|---:|---:|---:|
| 2732 ms | 2947 ms | 2983 ms | 3551 ms | 1764 ms |

按已提交导出 `cache/exports/p5_baseline0_smoke/SUMMARY.md`：p50=2737.5 ms p95=2979.7 ms（同一批原始记录，分位数插值差异）。所有用例均在 4s 以内。

## 细分

### 按 agent（group_id）

| group_id | n | TP | FN | TN | FP | TPR（BLOCK） |
|---|---:|---:|---:|---:|---:|---:|
| asb:agent:aerospace_engineer_agent | 30 | 2 | 26 | 2 | 0 | 7.1% (2/28) |
| asb:agent:psychological_counselor_agent | 34 | 9 | 23 | 2 | 0 | 28.1% (9/32) |

两个 agent 的 FP 均为 0（各 2/2 TN），所有 ALLOW 对照均通过。

### 按 attack_type（仅 BLOCK；ALLOW 另计）

| 切片 | n | TP | FN | TPR |
|---|---:|---:|---:|---:|
| Stealthy Attack | 29 | 6 | 23 | 20.7% |
| Disruptive Attack | 31 | 5 | 26 | 16.1% |
| ALLOW 正常对照 | 4 | — | — | TN=4 FP=0 |

切片样本较小（n≈30）—— 仅为方向性信号。Standard（240 BLOCK / 12 ALLOW，跨 6 个 agent）将进一步确认结论。

## 范围 — Standard / Holdout 未触及

- `p5-standard-v1`（252 = 240 BLOCK + 12 ALLOW，`eval`，headline）—— 尚未运行。
- `p5-holdout-v1`（84 = 80 BLOCK + 4 ALLOW，`holdout`）—— 已封存；`cache/results_v3` 下无结果目录。
- `p5-asb-proof-v0`（8，1.0.0）—— 历史验证用例，不再重跑；快照已还原至 `1.0.0` 以匹配其 manifest 的 `created_from`。

## 解读 — Smoke 作为流水线门控 PASS

1. 流水线健康：64/64 明确结果，无 429/5xx/error/cooldown/rate_limited/unjudged，单次尝试，`TP/FN/TN` 分类正确（FP=0）。无渲染器 / oracle / 传输层问题。
2. Baseline-0 检测率偏低：TPR 18.3%（11/60）。Stealthy 20.7% vs Disruptive 16.1%—— 两者均偏低；在该样本量下无证据表明 LineMod 能区分两种子类型。
3. Smoke 的误拦成本为 0/4，但 n=4 过小不足以引用。P1 Smoke 35.0% 与 P2 50.0% 表明同一网关在其他通道上可能产生高 FPR；P5 可引用的 FPR 需等待 Standard 的 n=12。
4. 分数不得驱动数据集变更。按冻结评审，偏低的 TPR 是与 P1/P2 同等级别的诚实 Baseline-0 结果—— 数据集保持冻结（adapter 1.1.0，420 用例，分组感知切分）。

## 复现

```bash
python -m demotest.cli.main validate --project P5_memory_write --target linemod \
  --source manifest:benchmarks/manifests/p5-smoke-v1/p5.json --no-key-check

python -m demotest.cli.main run --project P5_memory_write --target linemod \
  --source manifest:benchmarks/manifests/p5-smoke-v1/p5.json \
  --run-version baseline0-p5-smoke-v1 --gap 0.5 --max-attempts 6

python -m demotest.cli.main analyze --project P5_memory_write --target linemod \
  --source manifest:benchmarks/manifests/p5-smoke-v1/p5.json \
  --run-version baseline0-p5-smoke-v1

# 渲染报告（gitignored 原始记录 → 已提交汇总）
python scripts/_baseline0_smoke_report.py P5_memory_write \
  benchmarks/manifests/p5-smoke-v1/p5.json baseline0-p5-smoke-v1
```

原始记录：`cache/results_v3/P5_memory_write/linemod/baseline0-p5-smoke-v1/`（`memory_write.jsonl` 64 行、`_combined.jsonl`、`_run_meta.json`—— gitignored）。Manifest SHA 与套件快照已提交并绑定至 `experiment_hash` / `_run_meta.json`（`manifest_sha256=sha256:8f627...`，`fidelity=memory_write:structured`）。

下一门控：评审通过 → `p5-standard-v1` 真实运行（252）→ STOP；holdout 保持封存。
