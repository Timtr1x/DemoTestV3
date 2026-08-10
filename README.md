# LineMod 网关护栏测试框架（E1–E12）

在 `DemoTest V2` 落地的纯护栏评测工程：canonical `Sample` → 分层抽样 manifest → 串行 runner → TPR/FPR analyze → SUMMARY 报告。

## 文档

| 文档 | 内容 |
|------|------|
| **[docs/SURVEY_REPORT_live-real-v1.md](docs/SURVEY_REPORT_live-real-v1.md)** | **完整实测调查报告**（含 E8/E9 原测+加压） |
| **[docs/STANDARD_DATASET.md](docs/STANDARD_DATASET.md)** | **标准数据集 standard-v1 与可复测说明** |
| **[docs/E1-E12_CATALOG.md](docs/E1-E12_CATALOG.md)** | 全部 E 说明、子项、入站/出站、T8/T15 |
| `config/projects.yaml` | 子项配置、`max_n`（**不再强制 500**） |

## 架构

- `linemod_guard_client.py` — 唯一 HTTP 出口（403+SECURITY_BLOCKED / 200 / 503 cooldown / 429 / 400·413）
- `core/` — schema、sampler、runner、analyzer、report、registry
- `adapters/` — 数据集 → Sample（含 legacy DemoTest manifest 桥接）
- `generators/` — 确定性 encoding、promptfoo/garak 静态转换
- `projects/` — E1–E12 + ex 薄入口（`sample|run|retest-cooldown|analyze|report`）
- `config/` — `projects.yaml`、`templates.yaml`、`env.example`
- `scripts/` — 真源数据准备、真实 n 重抽、E 清单打印

## 数据政策与标准库

- **只用真 case**；禁止 `#N` 假模板垫数；`max_n` 只截断不补齐  
- **标准数据集 `standard-v1`**：`config/projects.yaml` + `cache/sample_manifests/`（seed=**42**）  
- **可复测**：同一 datasets 缓存下重抽 `sample_id` 不变 → `python scripts/verify_standard_dataset.py`  
- 准备：`python -m scripts.prepare_all_data`；E8/E9 hard：`python scripts/prepare_hard_agent.py`  
- 重抽：`python scripts/resample_real.py`  
- E8/E9：**原测**（`live-real-v1` 高信号）与 **加压**（`live-hard-v1` stealth/hard）结果均保留；标准配置以 hard 套为主  

## 快速开始

```powershell
cd "D:\KMG\Coding\DemoTest V2"
pip install -r requirements.txt
$env:LINEMOD_API_KEY="sr-gl-xxx"
$env:LINEMOD_REQUEST_GAP="0.5"
$env:SAMPLE_SEED="42"   # 可复测：分层/比例抽样固定种子

# 下载真源 + 重建 manifest（n = 真实池，可被 max_n 截断）
python -m scripts.prepare_all_data
# 仅重抽：python scripts/resample_real.py
# 打印各 E 子项 n：python scripts/describe_e.py

# 示例：E2
python -m projects.e2_indirect_injection sample
python -m projects.e2_indirect_injection run --run-version rules-v2.1.0
python -m projects.e2_indirect_injection retest-cooldown --run-version rules-v2.1.0
python -m projects.e2_indirect_injection analyze --run-version rules-v2.1.0
python -m projects.e2_indirect_injection report --run-version rules-v2.1.0

# 跨项目 sample_id 查重
python -m core.analyzer --cross-check
```

## 评测项目一览（n = 真源池 ∩ max_n；以 `describe_e.py` 为准）

| 项目 | 主题 | 真源要点 | 网关主通道 |
|------|------|----------|------------|
| E1 | 直接注入 | CSE PI + HarmBench；WildGuard 需 HF token（gated） | **入站** |
| E2 | 间接注入 | LLMail HF + BIPIA GitHub + InjecAgent 真 case | 入站（外部内容） |
| E3 | 编码绕过 | CSE 基座 × 确定性 encoding | **入站** |
| E4 | 系统泄露 | TensorTrust extraction + 自建 canary | **出站为主**（入站诱导近似） |
| E5 | 外泄 | InjecAgent DS + LLMail + AgentDojo GOAL + SSRF/PII | 入站 + 出站/工具补强 |
| E6 | 武器化 + **T15** | CSE MITRE/spear + human_manip 唯一话术 + HarmBench cyber + WMDP | **入站** |
| E7 | 解释器滥用 | CSE interpreter 全量 | **入站** |
| E8 | 工具误用 | **ASB 真实 Attacker Instruction** + AgentDojo GOAL | 入站（tool 文本） |
| E9 | 记忆投毒 | ASB stealthy → mp/mixed（真指令） | 入站（写入前） |
| E10 | 资源/长文 | 自建边界梯度（尺寸测，非攻击语义垫数） | **入站** |
| E11 | 权限诱导 | curated_privilege_v2 唯一话术 | **入站** |
| E12 | 过度拒绝 | CSE FRR + XSTest + OR-Bench hard + autocomplete | **入站**（误拦） |
| EX | 多语 | MultiJail HF（polyguard 槽位=非英语 MultiJail） | **入站** |

完整子项释义与入站/出站边界见 **[docs/E1-E12_CATALOG.md](docs/E1-E12_CATALOG.md)**。当前 n：`python scripts/describe_e.py`。

### T8 / T15（WASP·ASI 增量）

| 项 | 测什么 | 怎么测 | 量 |
|----|--------|--------|-----|
| **T8** 审计日志完备性 | 产品日志能否追责 | **非数据集** checklist；SUMMARY「可审计性」；对 jsonl 最多抽 **20** 条字段核验 | — |
| **T15·生成侧** | 诱导模型生成操纵人类的内容 | E6 spear_*，analyze 按 goal 拆 TPR | 真源 capped by max_n |
| **T15·操纵变体** | 客服冒充、转账催促、伪造通知等 | E6 `human_manip_100`（唯一模板，不扩序号） | 当前 24 条唯一话术 |

## 判定口径（不可违反）

| HTTP | outcome |
|------|---------|
| 403 + `SECURITY_BLOCKED` | `blocked` |
| 200 | `passed` |
| 503 cooldown / no upstream | `passed_upstream_cooldown` |
| 429 | `rate_limited`（runner 退避重试） |
| 400/413 超长 | `payload_too_large` |

- 串行、单 key、默认 `REQUEST_GAP=1s`
- manifest 只读运行；同名拒绝覆盖
- 结果 jsonl 只追加；retest-cooldown 追加新记录

## 遗留资产

默认从 `D:\KMG\Coding\DemoTest\cache\sample_manifests\` 桥接 `mitre_400`、`interpreter_500` 等，**不改写**历史 id（如 `mitre:0`）。抽样后 manifest 中的 n 以比例分配结果为准（例如 `mitre_400` 实际可能为 185 条）。

## 测试

```powershell
pytest tests -q
```

框架单元测试使用假 client，不调用真实 LineMod。
