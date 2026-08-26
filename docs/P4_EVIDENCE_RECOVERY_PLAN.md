# P4 证据回收计划 — Phase 4E Real Evidence Recovery

> **日期**：2026-08-26 · **状态**：计划冻结，执行中（不改已冻结契约、不跑真实网关、不做模式合成）
> **前置**：`docs/P4_FROZEN_BOUNDARY.md`（Phase 4D 定性为 production-schema compatibility proof）· `docs/P4_VISIBILITY_CONTRACT.md` · `docs/P4_SANITIZATION_CONTRACT.md`（P4CANARY 一对一）· `config/v3/datasets/credential_dynamic_traces.yaml`（A/B + DYNAMIC_TRACE + structured headline）
> **底数**：`benchmarks/frozen/datasets/credential_dynamic_traces/raw/reviews/reviewed_traces.jsonl` 当前 1 条 DIRECT（`andytrust-portfolio-claude-code-skill-md / TELEGRAM_BOT_TOKEN / STDOUT_EXPOSURE / TOOL_RESULT / trace_hash sha256:6106329b…`，`exec-a72fb388451334f0`），`benchmarks/frozen/.../normalized/cases.jsonl` 同步 1 例；`cache/datasets_v3/raw/credential_dynamic_traces_sourcebound` 同源 1/5，`cache/datasets_v3/raw/credential_dynamic_traces`（`snap-3e317468aa7c`）0 traces。
> **STOP 门**：`≥50 real DIRECT` 方可提 Full Core 冻结与真实 Smoke 评审；未达门槛前不冻结、不跑 Smoke、不混入合成样本。

---

## 1. 冻结重申（不再改）

- 契约与实现：`docs/P4_VISIBILITY_CONTRACT.md` · `docs/P4_SANITIZATION_CONTRACT.md` · `src/demotest/renderers/credential_flow.py`（`credential_flow/v1`，`structured` 为 headline，`RAW` 亦携带 secret payload）· `config/projects.yaml#P4_credential_flow` · `src/demotest/targets/` / `src/demotest/oracles/`。
- 合成门控：`scripts/_p4_projection_proof.py` 的 13 例 P4CANARY fixture 不扩充、不计入真实门槛。
- 本计划不新增执行管线、不改 Adapter、不装依赖、不做 TLS MITM / Node 拦截 / credential DSL / 通用 Agent 执行器。

## 2. 证据底数（2026-08-26 盘点）

| 池 | 规模 | 说明 |
|---|---|---|
| `p4_skill_candidates`（SkillsMP crawl） | 165（163 ACCEPT / 2 SOURCE_REJECTED） | `RUNTIME_READY 40` / `AGENT_REQUIRED 123`；可用 deterministic 入口仅 40 |
| `p4_sourcebound_candidates`（本地 5 技能，已配 source-bound 绑定） | 5 | andytrust / crunteam / laurenfeminine36 / lesliewylie / xd06，各 1–4 个 credential_name |
| `snap-4b0876baa2eb`（source-bound 快照） | 5 技能，已跑 5 次 deterministic | 1 DIRECT（andytrust / TELEGRAM_BOT_TOKEN / STDOUT_EXPOSURE）· 3 `SUCCESS_NO_SECRET_FLOW` · 1 `FAILED_DEPENDENCY`（crunteam，`CRUN_API_KEY` 格式校验失败） |
| `snap-3e317468aa7c`（官方 forged canary 快照） | 40 技能中已跑 5 次 | 均为 `SUCCESS_NO_SECRET_FLOW`，0 traces（见 `executions.jsonl` / `trace_meta.json n_traces=0`） |
| Frozen Core | 1 DIRECT | 与 `snap-4b0876baa2eb` 的 andytrust trace 同源（`trace_hash / execution_id / skill_snapshot_sha256 57537219…`） |

**结论**：当前真实 Gateway-visible DIRECT 仅 1 条，距离 `≥50` 缺口 49；`0` 条 `ALLOW`（无真实 safe flow，首版保持 TPR-only，`headline_eligible=false` 已在 project 配置中声明）。

## 3. 回收方法（仅两条合法来源）

### 路径 A — 官方 private master（首选，若可得）

`File:Line / Code Snippet / IOC span`（`creds_in_skills.xlsx` 私有母表）→ 内存定位 span → `P4CANARY_<sha256(issue_id)[:16]>` 一对一替换 → 立即丢弃 raw secret，永不落地真实 secret。每 issue 最多一案，不扩写、不引新 skill。

> 当前仓库无 private master 明文，不做批量拉取；若后续可得，仅对已判定 DIRECT 的 issue 做内存替换，不扩大采集功能。

### 路径 B — pinned pipeline 最小动态复现（当前唯一可执行路径）

- **候选源**：`cache/datasets_v3/raw/skillleakbench_pipeline@682521a`（已 pin，`MIT`），`benchmarks/frozen/datasets/credential_dynamic_traces/raw/reviews/` 为唯一正式输入。
- **执行面**：`deterministic` 单条件、`docker_only_hardened`（`concurrency=1 / --network none / cap-drop ALL / no-new-privileges / read-only rootfs + tmpfs /tmp,/mock_creds,/home/sandbox`，见 `trace_meta.sandbox_profile`），`sandbox_image_digest skill-leakbench@sha256:abe6f4…`。
- **凭证**：`official_forged_canary`（`sk-leakbench-mock-* / AKIA-LEAKBENCH-*`）与 `source-bound-v1`（`leakbench-sourcebound-<sha12(candidate_id|source_sha256)>-<sha12(credential_name)>`）均为假 canary，不含真实 secret；本计划延续 `source-bound-v1`，与 `P4CANARY_` 不混用但同满足“假 canary、跨产物一致、可识别”不变式。
- **范围控制**：一次仅对“能跑且能产生 Gateway-visible marker”的少量 affected skills 做复现，跑不了即 skip；不按 `issues.csv` 的 pattern（`Information Exposure` 等）批量构造 stdout 样本充当 DIRECT。

## 4. 准入门控（fail-closed）

每条执行产物必须同时满足方可进入 Core candidate，否则记为排除并分类落因：

| 门 | 条件 | 不满足 → 去向 |
|---|---|---|
| Provenance | `evidence_type=DYNAMIC_TRACE` 且 `dynamic_confirmed=true` 且 `trace_hash`（`sha256:<hex64>` 覆盖 canonical event）且 `skill_snapshot_sha256 / execution_id / sandbox_version / pipeline_revision` 齐全 | 记为 `NOT_VISIBLE` 或 `AMBIGUOUS`，不入 Core |
| Visibility | `STDOUT_EXPOSURE → sink=stdout / channel=TOOL_RESULT / gateway_visibility=DIRECT` 且 `payload` 明文含 `credential_marker`；`NETWORK_EXFIL → sink=network / channel=TOOL_CALL / gateway_visibility=PROJECTED`（payload body 命中 + `exfil_collector.py` sinkhole/forward proxy `network_payload.log` 有据）且 marker 在 payload | 未命中 marker 或 channel/visibility 错配 → `SUCCESS_NO_SECRET_FLOW` 等，排除 |
| Quality | `A`（`stdout DIRECT original`）或 `B`（`network PROJECTED deterministic_projection`），见 `config/v3/datasets/credential_dynamic_traces.yaml` | `C / catalog_derived` 不入本数据集 |
| 去重与分桶 | 同一 issue 最多一案；同 skill 的 stdout+network 永不跨 split（`sha256(version|seed|skill_id)` 分桶） | 重复或跨 split 视为污染，拒入 |

仅 `DIRECT` 与严格 `PROJECTED`（sandbox sinkhole 明确捕获）两档可入；`HARDCODE_ONLY / DIRECT_NETWORK_EXFIL 未进入 Gateway / INSECURE_STORAGE 无观测` 均归 `NOT_VISIBLE`，`无法判定` 归 `AMBIGUOUS`，一律 fail-closed 排除。

## 5. 失败分类（Evidence Inventory 用）

| outcome | 含义 | 是否 Core |
|---|---|---|
| `SUCCESS_REACHED_SECRET_PATH` | 执行成功且 marker 在 Gateway-visible 面命中（当前唯一 frozen 例） | ✅ 1 |
| `SUCCESS_NO_SECRET_FLOW` | 执行成功但 marker 未在 `stdout / network_payload` 命中 | ❌ 排除，需记录原因（如入口未走 secret 分支、无 provider 调用、仅打印配置摘要） |
| `FAILED_DEPENDENCY` | 依赖缺失或 canary 格式被 skill 自校验拒绝（如 crunteam `CRUN_API_KEY` 需 `ak_`+32） | ❌ 排除，记依赖/格式原因 |
| `TIMEOUT / RUNTIME_ERROR` | 超时或非预期异常 | ❌ 排除，记超时/异常栈摘要（已脱敏） |
| `NOT_VISIBLE / AMBIGUOUS` | 可见性判定未落 DIRECT/严格 PROJECTED | ❌ 排除 |

## 6. STOP gate 与交付物

- **阈值**：`≥50 real DIRECT`（`DYNAMIC_TRACE + dynamic_confirmed + trace_hash + A/B`）为首个 STOP；`150–300` 足够第一版 Standard；`400–500` 更佳但不为数量重启复杂工程。
- **未达门槛前**：不冻结 Full Core（不写 `p4-core-smoke/standard` 套件 manifest）、不跑真实 Smoke、不生成 `headline_eligible=true`。
- **达门时提交**（供复核，未经复核不冻结）：
  1. `docs/P4_EVIDENCE_INVENTORY.md`（含 `provenance / channel / skill / flow_class` 分布、失败原因直方图、逐案可追溯记录：`skill_id / issue_id / credential_name / canary / trace_hash / execution_id / snapshot_id / skill_snapshot_sha256 / gateway_channel / sink`）；
  2. `benchmarks/frozen/datasets/credential_dynamic_traces/raw/reviews/reviewed_traces.jsonl` + `review_meta.json` 增量（`n_accepted=n_traces / n_pending=0 / SHA 绑定`）与 `normalized/cases.jsonl`；
  3. 本计划与 Inventory 的复核记录。

## 7. 追溯记录 schema（每案一行）

```
skill_id | issue_id | credential_name | canary | flow_class | sink | gateway_channel | gateway_visibility | evidence_type | dynamic_confirmed | trace_hash | execution_id | snapshot_id | skill_snapshot_sha256 | sandbox_version | pipeline_revision | payload_excerpt (≤120ch, 含 marker 上下文)
```

`payload_excerpt` 仅截含 marker 的前后上下文，不扩含真实 secret；真实 secret 全程不落盘（内存替换后立即丢弃）。

## 8. 下一步（Docker 恢复后）

1. `docker` 恢复后，以同一 `snap-4b0876baa2eb` 继续对剩余 `RUNTIME_READY`（40 池中未跑的）按 `source-bound-v1` 增量复现，每批 `≤5` 技能，`collect` 仍走 `deterministic / docker_only_hardened` 同一 `snapshot` 与 `offset/limit`；
2. 对新命中 `SUCCESS_REACHED_SECRET_PATH` 的执行，人工按 §4 门控逐条审 `payload vs marker vs sink vs channel`，通过后 `review-apply → freeze-reviewed` 增量入 `reviewed_traces`；
3. 若 `RUNTIME_READY` 池不足，新增 `runtime_specs` 需人工逐 skill 审 `SKILL.md / entry_command / credential_name` 后写 `runtime_specs.jsonl` sidecar（绑定 `source_sha256`），不自动猜 `main.py`。

---

*本计划与 `docs/PROJECT_SCOPE.md` 的 OPTIONAL DATASET ACQUISITION 边界一致：Dynamic 采集为可选数据生产工具，Benchmark 运行时仅依赖已冻结的 reviewed artifact，无需 Docker / SkillsMP / candidate / snapshot。*
