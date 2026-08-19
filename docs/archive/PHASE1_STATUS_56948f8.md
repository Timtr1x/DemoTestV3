# DemoTest Phase 1 — 当前状态报告（截至 2026-08-19，已提交 `c77ba03`）

> 本文档承接两份 Phase 1 指南（《开发与执行指南》§0–§70、《数据源获取与开发指南》§1–§38）的最新复检结论  
> 验收基准：`LLMail` 完整 SHA `1063bdf01ec8…`、`AgentDojo` 完整 SHA `089ed468cf3e…`、清单 `自哈希`、`DEV/EVAL/HOLDOUT 20/60/20`

---

## 1. 概览结论（TL;DR）

- **代码与配置已冻结**：`config/v3/*`、`cache/datasets_v3/metadata/*.lock.json`、`benchmarks/{manifests,suites}`、`src/demotest/datasets/*` 已入库 `593d14d`、`802f6d4`、`c77ba03`，`git ls-files` 可验证；`.gitignore` 仅忽略 `cache/datasets_v3/{raw,normalized}` 超大镜像
- **确定性与隔离已验证**：`hash_rank_v1 seed 42`、`split-v1 group-aware 20/60/20`、`manifest 构建-删除-重建字节一致`、`group_id=parent_source_id/near_dup_cluster_id` 均有离线测试覆盖（`tests/v3/datasets 47 例 + tests/v3 215 例` 全绿）
- **数量门已达标（默认 A）**：默认有界池 `LLMail 3,700 攻击 + 160 良性 ≈ 3,860（~13M）`，`--full` 才落 `148,545 攻击 + 160` 全量（`483M`）；以此构建 `standard P1 1,740/1,740 EVAL`、`full P1 2,900/2,900 EVAL+HOLDOUT`、`smoke 100/100 DEV`、`holdout P1 820 / P2 187`
- **遗留 P1**：`scenario/team_id/presentation_style` 为启发式近似（`labelled_unique` 不含精确 `team_id/scenario`，需 `raw_submissions` 回联；已在验收报告中按 P1 标注）

> 因此本轮默认不再占 `483M`，同时保留了全量 `148K` 的可信性证据与 `6838659a98334729c61de8bfba281f89097fe74b35e5b/` 锁的可复现路径

---

## 2. 本轮 A 方案落地（你的选择）

上一轮复检的 P0-2（`LLMail` 缺口致 `standard/full P1` 未达 `target`）曾以 **全量 148,545 / 483M** 通过，但作为**默认**过重。你选定的 **A 方案（推荐）** 已生效：

| 模式 | 命令 | 候选池 | 归一化体积 | 覆盖标准清单 |
|------|------|--------|------------|--------------|
| **默认** | `demotest dataset prepare --dataset llmail` | `phase1 ~3,145 + phase2 ~555 攻击（等配额 hash-rank）+ 160 良性 = 3,860` | `~13M` | `standard 1,740 / full 2,900` 均为 `verify OK` |
| **全量** | `demotest dataset prepare --dataset llmail --full` | `phase1 127k + phase2 21k + 160 = 148,545`（流式 `ijson`） | `~483M` | 同上（`full-pool holdout 29,835` 证据可复现） |

底层流式修复仍固化在管线：`ijson.kvitems` 流式 428M、`jsonl_dumps` 转义 `U+2028/U+2029` 免断行、`iter_normalized_lines` 流式 `verify/stats`、`hash_raw_snapshot` 排除 `__pycache__ + .git`（`AgentDojo` 锁回 `57726b… OK`）

`AgentDojo` 归一化 `1,581（tool_result 629 / tool_call 952）` 与 `AgentDojo prepare` 的 `exact 153` 去重仍有效，`P2 standard 540/540、full 773/800、holdout 187` 均为真实 `v1` 投影，不依赖全量 LLMail

---

## 3. 源、锁与体积取证

```text
# verify-source（2026-08-19 实测）
OK: llmail source verified (revision + snapshot hash + clean tree)      # 1063bdf01ec8…, 8 files, 428M/66M/203
OK: agentdojo source verified (revision + snapshot hash + clean tree)   # 089ed468cf3e…, 65 files, hash_globs + __pycache__ excluded

datasets.yaml
  llmail: type=huggingface_dataset, repo_id=microsoft/llmail-inject-challenge, revision=1063bdf01ec8762b812d5e06ee768a06faa5a6f7, license=MIT, allow_patterns=…json*
  agentdojo: type=github, repository=ethz-spylab/agentdojo, revision=089ed468cf3ed0322acc66b0211f26d9d90dbf60, benchmark_version=v1, hash_globs=src/agentdojo/{default_suites,task_suite}/** + base_tasks.py
```

| 数据集 | 锁 | 归一化（默认） | 通道/阶段 |
|--------|----|---------------|-----------|
| `LLMail` | `a223abaf159dfa…` | `3,860（default A）/ 148,545（--full，全池 127378+21007+160）` | `email 3,860；benign 160 / phase1 3145 / phase2 555；scenario email_exfil 3240 / calendar 427 / banking 33` |
| `AgentDojo` | `57726b746c7df…` | `1,581（tool_result 629 + tool_call 952；workspace 400 / travel 200 / banking 176 / slack 273）` | `P1 tool_result / P2 tool_call`，`group_id=parent_source_id` 同亲代共组 |

---

## 4. 清单与套件取证（2026-08-19，重验）

```text
# verify --strict（本轮复检，流式头采样 + 选样后 hydrates，指纹解析）
OK: llmail normalized snapshot verified         # 3,860 流式 Verify
OK: agentdojo normalized snapshot verified      # 1,581 Verify
OK: benchmarks/manifests/smoke-v1/p1.json           n=100  sha256:… (dev)
OK: benchmarks/manifests/phase1-standard-v1/p1.json n=1740 sha256:4f9e8… (eval)
OK: benchmarks/manifests/phase1-full-v1/p1.json     n=2900 sha256:ad622… (eval+holdout)
OK: benchmarks/manifests/holdout-v1/p1.json         n=820  sha256:50ca7… (holdout)
OK: benchmarks/manifests/holdout-v1/p2.json         n=187
# P2 standard 540/540 + full 773/800 均为 P2 完整 v1 投影的证据规模
```

| 套件 | 总数 | 组成 |
|------|------|------|
| `smoke-v1` | `200` | `P1 100 (dev) + P2 100 (dev)` |
| `phase1-standard-v1` | `~2,280` | `P1 1,740 (EVAL) + P2 540 (EVAL)` |
| `phase1-full-v1` | `~3,673` | `P1 2,900 (EVAL+HOLDOUT) + P2 773 (EVAL+HOLDOUT)` |
| `holdout-v1` | `~1,007` | `P1 820 + P2 187`（独立隔离，见 `benchmarks/manifests/holdout-v1/ACCESS_POLICY.md`） |

`manifest_version v3.1 / selection_policy {hash_rank_v1, group_aware_cumulative_count_v1, 0.2/0.6/0.2} / seed 42 / manifest_sha256 自洽`，`--full` 下 `holdout P1` 可复现为 `29,835（全池 20% HOLDOUT 分支，论文级证据）`

---

## 5. 测试与四关

```text
215 passed (tests/v3)            # 168 existing + 47 datasets
47 passed  (tests/v3/datasets)   # source_lock / dedup / sampler / manifest / reproducibility / adapters
```

- 适配器纯度：`import openai/anthropic/requests/demotest.targets` 静态拦截、`datasets` 未读 `cache/results_v3/`
- 去重三级：`exact / normalized (BOM/NFC/CRLF/rstrip, 禁小写/去标点/去 HTML)` / `char 5-gram Jaccard 0.85, 仅写 near_dup_cluster_id, payload 不改`
- 采样隔离：`selection_key=sha256(suite_version|seed|dataset_id|source_id|group_id) + group-aware split`，`by_team/unknown + by_scenario email_exfil/calendar/banking` 已在 `stats` 侧计量，复检 P1 标注为 `heuristic approximation`（需 `raw_submissions` 精确回联，后续阶段补）
- 四关（§55）：`dataset verify / manifest verify --strict / validate / render / --dry-run` 已在 `smoke` 全链 `200` 跑通；`manifest` 的 `--strict` 指纹解析已对 `standard 1,740` 与 `full 2,900` 复检

---

## 6. 仍未宣称的范围（§68）

- `完整 P2 / MCP / Credential / Memory / 5 类 11,600` — 本轮仅 `LLMail + AgentDojo v1` 闭环，代码与报告均未宣称，符合 §68
- 下一步再增 `Credential Leakage（Phase 2 建议）`、`AuthBench`、`MCP Memory` 时，须按 `standard-v1 → standard-v2` 升版，不可原地覆盖

---

## 7. 关键命令（默认 A）

```bash
# 锁与体检
PYTHONPATH=src python -m demotest.cli.main dataset verify-source --dataset llmail
PYTHONPATH=src python -m demotest.cli.main dataset verify-source --dataset agentdojo

# 制备（默认有界 ~3,860；加 --full 才 148,545）
PYTHONPATH=src python -m demotest.cli.main dataset prepare --dataset llmail          # ~13M
PYTHONPATH=src python -m demotest.cli.main dataset prepare --dataset llmail --full   # 148,545 / 483M（可选）
PYTHONPATH=src python -m demotest.cli.main dataset prepare --dataset agentdojo       # 1,581
PYTHONPATH=src python -m demotest.cli.main dataset verify --dataset llmail
PYTHONPATH=src python -m demotest.cli.main dataset verify --dataset agentdojo
PYTHONPATH=src python -m demotest.cli.main dataset stats --dataset llmail

# 构建与校验清单（2026-08-19 实测：standard 1,740 / full 2,900 verify OK）
PYTHONPATH=src python -m demotest.cli.main manifest build --suite phase1-standard-v1 --project P1_external_instruction
PYTHONPATH=src python -m demotest.cli.main manifest verify benchmarks/manifests/phase1-standard-v1/p1.json --strict
```
