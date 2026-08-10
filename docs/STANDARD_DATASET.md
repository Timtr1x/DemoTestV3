# 标准数据集说明（可复测）

| 项 | 值 |
|----|-----|
| 版本标签 | **`standard-v1`**（与 `config/projects.yaml` + `cache/sample_manifests/` 对齐） |
| 抽样种子 | **`SAMPLE_SEED=42`** / `defaults.seed: 42` |
| 强制凑数 | **否**（`samples_per_project: null`） |
| 真源策略 | 仅公开/自建唯一 case；禁止 `#N` 假模板垫数 |

## 可复测性（是）

在同一代码版本 + 同一上游缓存 + `seed=42` 下：

1. **`sample(force=True)` 再次执行 → `sample_id` 列表不变**（已用 `scripts/verify_standard_dataset.py` 校验 e8/e9）。  
2. **Live 重跑**：对已有 manifest **只读**，不重抽 → 同一批提示词可对比不同网关版本。  
3. 上游 cache 若被 `prepare_all_data --force-download` 更新，池子变化可能导致 n 变化；**冻结标准库时勿 force 覆盖 datasets**，或对 `cache/datasets` + `cache/sample_manifests` 做版本备份。

## 重建标准库

```powershell
cd "D:\KMG\Coding\DemoTest V2"
$env:SAMPLE_SEED="42"
$env:LEGACY_DEMOTEST_ROOT=(Get-Location).Path
$env:ENABLE_WMDP="1"
# 可选：ENABLE_WILDGUARD=1 + HF token

python -m scripts.prepare_all_data      # 真源下载（已有 cache 可跳过已存在文件）
python scripts/prepare_hard_agent.py    # E8/E9 hard/stealth + InjecAgent enhanced
python scripts/resample_real.py         # 按 projects.yaml 重抽全部 manifest
python scripts/verify_standard_dataset.py
python scripts/describe_e.py
```

## 标准 live 跑法

| 范围 | run-version 建议 | 说明 |
|------|------------------|------|
| E1–E7, E10–E12, EX | `live-real-v1` | 全库主测（已完成） |
| E8–E9 标准（含 easy 对照 + hard 主测） | `live-hard-v1` | 当前标准 E8/E9 配置 |

```powershell
$env:LINEMOD_REQUEST_GAP="0.5"
python -m projects.e8_tool_misuse run --run-version live-hard-v1
python -m projects.e9_memory_poison run --run-version live-hard-v1
```

## E8 / E9 标准子集（当前 projects.yaml）

| 项目 | 子项 | n（max） | 角色 |
|------|------|----------|------|
| E8 | asb_dpi_opi_easy | 30 | 标签体对照 |
| E8 | agentdojo_misuse_easy | 8 | SYSTEM NOTICE 对照 |
| E8 | asb_stealth_tooljson | 80 | **主测** 去标签 JSON |
| E8 | agentdojo_hard_inject | 120 | **主测** 官方模板 |
| E8 | injecagent_enhanced | 100 | **主测** Tool Response 埋入 |
| E9 | asb_memory_poison_easy | 20 | 对照 |
| E9 | asb_mixed_easy | 20 | 对照 |
| E9 | asb_stealth_memory | 50 | **主测** |
| E9 | asb_stealth_mixed | 50 | **主测** |

历史全量 easy（E8 n=208、E9 n=200，`live-real-v1`）仍保留结果目录，用于对比「高信号形态」；**标准库配置已改为上表**。

## 冻结清单路径

```
config/projects.yaml
cache/sample_manifests/*.json
cache/datasets/                 # 真源离线缓存
scripts/prepare_all_data.py
scripts/prepare_hard_agent.py
scripts/resample_real.py
scripts/verify_standard_dataset.py
docs/SURVEY_REPORT_live-real-v1.md
```
