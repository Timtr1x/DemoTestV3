# LineMod 网关护栏测试框架（E1–E12）

在 `DemoTest V2` 落地的纯护栏评测工程：canonical `Sample` → 分层抽样 manifest → 串行 runner → TPR/FPR analyze → SUMMARY 报告。

## 架构

- `linemod_guard_client.py` — 唯一 HTTP 出口（403+SECURITY_BLOCKED / 200 / 503 cooldown / 429 / 400·413）
- `core/` — schema、sampler、runner、analyzer、report、registry
- `adapters/` — 数据集 → Sample（含 legacy DemoTest manifest 桥接）
- `generators/` — 确定性 encoding、promptfoo/garak 静态转换
- `projects/` — E1–E12 + ex 薄入口（`sample|run|retest-cooldown|analyze|report`）
- `config/` — `projects.yaml`、`templates.yaml`、`env.example`

## 快速开始

```powershell
cd "D:\KMG\Coding\DemoTest V2"
pip install -r requirements.txt
$env:LINEMOD_API_KEY="sr-gl-xxx"
$env:LINEMOD_REQUEST_GAP="3.5"
$env:SAMPLE_SEED="42"

# 自建静态集
python -m adapters.download --source selfbuild

# 示例：E2
python -m projects.e2_indirect_injection sample
python -m projects.e2_indirect_injection run --run-version rules-v2.1.0
python -m projects.e2_indirect_injection retest-cooldown --run-version rules-v2.1.0
python -m projects.e2_indirect_injection analyze --run-version rules-v2.1.0
python -m projects.e2_indirect_injection report --run-version rules-v2.1.0

# 跨项目 sample_id 查重
python -m core.analyzer --cross-check
```

## 判定口径（不可违反）

| HTTP | outcome |
|------|---------|
| 403 + `SECURITY_BLOCKED` | `blocked` |
| 200 | `passed` |
| 503 cooldown / no upstream | `passed_upstream_cooldown` |
| 429 | `rate_limited`（runner 退避重试） |
| 400/413 超长 | `payload_too_large` |

- 串行、单 key、默认 `REQUEST_GAP=3.5s`
- manifest 只读运行；同名拒绝覆盖
- 结果 jsonl 只追加；retest-cooldown 追加新记录

## 遗留资产

默认从 `D:\KMG\Coding\DemoTest\cache\sample_manifests\` 桥接 `mitre_400`、`interpreter_500` 等，**不改写**历史 id（如 `mitre:0`）。

## 测试

```powershell
pytest tests -q
```

框架单元测试使用假 client，不调用真实 LineMod。
