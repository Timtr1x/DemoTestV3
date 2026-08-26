# P4 证据回收计划 — Phase 4E Real Evidence Recovery

> **日期**：2026-08-26 · **状态**：计划冻结，执行中（不改已冻结契约、不跑真实网关、不做模式合成；`main@40ca2df` 复核后更新为双计数口径）
> **前置**：`docs/P4_FROZEN_BOUNDARY.md`（Phase 4D 定性为 production-schema compatibility proof）· `docs/P4_VISIBILITY_CONTRACT.md` · `docs/P4_SANITIZATION_CONTRACT.md`（P4CANARY 一对一）· `config/v3/datasets/credential_dynamic_traces.yaml`（A/B + DYNAMIC_TRACE + structured headline）
> **底数（双计数）**：`Real DIRECT evidence = 1`（`andytrust-portfolio-claude-code-skill-md / TELEGRAM_BOT_TOKEN / STDOUT_EXPOSURE / TOOL_RESULT / trace_hash sha256:6106329b…`，`exec-a72fb388451334f0`，`source_binding=REAL_SKILL_UNBOUND / quality A / supplementary`），`Official SkillLeakBench-bound DIRECT = 0/50`。`benchmarks/frozen/.../reviewed_traces.jsonl` 与 `normalized/cases.jsonl` 同步 1 例；`cache/datasets_v3/raw/credential_dynamic_traces_sourcebound` 同源 1/5，`cache/datasets_v3/raw/credential_dynamic_traces`（`snap-3e317468aa7c`）0 traces。
> **绑定表**：`cache/p4_evidence/official_issue_binding.jsonl`（由 `scripts/p4_build_official_binding_inventory.py` 可复现生成，`--check` 校验 1708/487/165/162；`unique_issue_keys 784 / sanitized_identity_collisions 924 / duplicate_key_groups 366`，`OFFICIAL 0`）（1708 行，`UNRESOLVED 1708 / CANDIDATE_SOURCE_VERIFIED 0 / AMBIGUOUS 0 / OFFICIAL 0`），`cache/p4_evidence/binding_summary.json`。候选验证 `is_candidate_source_verified` 需 `repo + 64hex source_sha256 + skill path`（`branch` 不算 immutable revision）；缺 official 证据时单名匹配仅 `CANDIDATE_SOURCE_VERIFIED` 不得 EXACT；`OFFICIAL_BINDING_EXACT` 需 `official repo/path/revision(40/64 hex)/File:Line` 与 candidate 一致，公开 CSV 无此类字段，需 `private master` 或定向重爬。
> **STOP 门**：`Official-issue-bound DIRECT ≥50` 方可提 Full Core 冻结与真实 Smoke 评审（`Real DIRECT` 为补充轨，不计入 0/50）；未达门槛前不冻结、不跑 Smoke、不混入合成样本。

---

## 1. 冻结重申（不再改）

- 契约与实现：`docs/P4_VISIBILITY_CONTRACT.md` · `docs/P4_SANITIZATION_CONTRACT.md` · `src/demotest/renderers/credential_flow.py`（`credential_flow/v1`，`structured` 为 headline，`RAW` 亦携带 secret payload）· `config/projects.yaml#P4_credential_flow` · `src/demotest/targets/` / `src/demotest/oracles/`。
- 合成门控：`scripts/_p4_projection_proof.py` 的 13 例 P4CANARY fixture 不扩充、不计入真实门槛。
- 本计划不新增执行管线、不改 Adapter、不装依赖、不做 TLS MITM / Node 拦截 / credential DSL / 通用 Agent 执行器。

## 2. 证据底数（2026-08-26 盘点，双计数）

| 池 | 规模 | 绑定 | 说明 |
|---|---|---|---|
| `p4_skill_candidates`（SkillsMP crawl） | 165（163 ACCEPT / 2 SOURCE_REJECTED） | — | `RUNTIME_READY 40` / `AGENT_REQUIRED 123`；可用 deterministic 入口仅 40 |
| `p4_sourcebound_candidates`（本地 5 技能，已配 source-bound 绑定） | 5 | — | andytrust / crunteam / laurenfeminine36 / lesliewylie / xd06，各 1–4 个 credential_name |
| `snap-4b0876baa2eb`（source-bound 快照） | 5 技能，已跑 5 次 deterministic | `REAL_SKILL_UNBOUND 1` | 1 DIRECT（andytrust / TELEGRAM_BOT_TOKEN / STDOUT_EXPOSURE）· 3 `SUCCESS_NO_SECRET_FLOW` · 1 `FAILED_DEPENDENCY`（crunteam `CRUN_API_KEY` 格式校验失败，先 skip） |
| `snap-3e317468aa7c`（official forged canary 快照） | 40 技能中已跑 5 次 | 0 | 均为 `SUCCESS_NO_SECRET_FLOW`，0 traces |
| 官方 520 affected ∩ 165 候选池 | **交集 0** | `EXACT 0 / UNRESOLVED 1708` | `skill_name` 精确 join 为 0，公开 CSV 无 repo 级 provenance，需定向重爬或 private master |
| Frozen Core | `Real 1 / Official 0` | `REAL_SKILL_UNBOUND` | 与 `snap-4b0876baa2eb` 同源（`trace_hash / execution_id / skill_snapshot_sha256 57537219…`），补充轨保留，不晋级为 Official |

**结论**：`Official-issue-bound DIRECT = 0/50`，`Real DIRECT = 1` 为补充轨；现有 40 池与官方集无交集，继续盲跑对 Official 计数帮助有限。

## 3. 回收方法（仅两条合法来源，增加来源维度）

### 来源维度（`source_binding`）

- `OFFICIAL_ISSUE_BOUND`：`SkillLeakBench issues.csv` 某行 → `official skill_id/skill_name/pattern/classification` → 真实 `source repo/revision` → 恢复 exact evidence；仅此档计入 `Official 0/50`。
- `REAL_SKILL_UNBOUND`：真实 Skill、真实执行、真实 DIRECT（如当前 `andytrust`，`quality A`），但无官方 issue 绑定；作 `supplementary` 保留，待以 `creds_in_skills.xlsx File:Line` 证明后再升级为 `OFFICIAL_ISSUE_BOUND`。
- `PROJECTED`：按既有 `B 级 / deterministic_projection / network sinkhole` 规则处理，仅严格 `PROJECTED` 可入。

### 路径 A — 官方 private master（首选，若可得）

`File:Line / Code Snippet / IOC span`（`creds_in_skills.xlsx` 私有母表）→ 内存定位 span → `P4CANARY_<sha256(issue_id)[:16]>` 一对一替换 → 立即丢弃 raw secret，永不落地真实 secret。每 issue 最多一案，不扩写、不引新 skill；映射关系写入 `official_issue_binding.jsonl` 的 `OFFICIAL_BINDING_EXACT / CANDIDATE_SOURCE_VERIFIED / NAME_MATCH_ONLY / AMBIGUOUS_NAME_MATCH / UNRESOLVED` 与 `binding_method`（纯函数 `resolve_issue_binding` / `resolve_skill_binding` 判定，`candidate_source_verified` 仅自证不产生绑定；`unique_issue_keys / sanitized_identity_collisions` 留待 private master 后消歧）。

### 路径 B — pinned pipeline 最小动态复现（当前唯一可执行路径，但暂停盲跑）

- **候选源**：`cache/datasets_v3/raw/skillleakbench_pipeline@682521a`（已 pin，`MIT`），`benchmarks/frozen/datasets/credential_dynamic_traces/raw/reviews/` 为唯一正式输入。
- **执行面**：`deterministic` 单条件、`docker_only_hardened`（`concurrency=1 / --network none / cap-drop ALL / no-new-privileges / read-only rootfs + tmpfs /tmp,/mock_creds,/home/sandbox`），`sandbox_image_digest skill-leakbench@sha256:abe6f4…`。
- **凭证**：`official_forged_canary` 与 `source-bound-v1` 均为假 canary，不落地真实 secret；`P4CANARY_` 续用于官方 issue 脱敏，不与 `source-bound` 混用但同满足“假 canary、跨产物一致、可识别”不变式。
- **范围控制**：**暂停**对剩余 35 `RUNTIME_READY` 的盲跑；下一优先队列为 `Official affected（520） ∩ locally runnable` 的交集（`A. 建立绑定`），仅对 `OFFICIAL_ISSUE_BOUND + runnable` 小批（`≤5 / 批`）回收。

## 4. 准入门控（fail-closed）

每条执行产物必须同时满足方可进入 Core candidate，否则记为排除并分类落因：

| 门 | 条件 | 不满足 → 去向 |
|---|---|---|
| Provenance | `evidence_type=DYNAMIC_TRACE` 且 `dynamic_confirmed=true` 且 `trace_hash`（`sha256:<hex64>` 覆盖 canonical event）且 `skill_snapshot_sha256 / execution_id / sandbox_version / pipeline_revision` 齐全 | 记为 `NOT_VISIBLE` 或 `AMBIGUOUS`，不入 Core |
| Visibility | `STDOUT_EXPOSURE → sink=stdout / channel=TOOL_RESULT / gateway_visibility=DIRECT` 且 `payload` 明文含 `credential_marker`；`NETWORK_EXFIL → sink=network / channel=TOOL_CALL / gateway_visibility=PROJECTED`（payload body 命中 + `exfil_collector.py` sinkhole/forward proxy `network_payload.log` 有据）且 marker 在 payload | 未命中 marker 或 channel/visibility 错配 → `SUCCESS_NO_SECRET_FLOW` 等，排除 |
| Quality | `A`（`stdout DIRECT original`）或 `B`（`network PROJECTED deterministic_projection`）| `C / catalog_derived` 不入本数据集 |
| 来源绑定 | `OFFICIAL_ISSUE_BOUND` 方可计入 `0/50`；`REAL_SKILL_UNBOUND` 计入 `Real 1` 补充轨 | `UNBOUND` 不自动晋级，需以 `File:Line` 证明 |
| 去重与分桶 | 同一 issue 最多一案；同 skill 的 stdout+network 永不跨 split（`sha256(version|seed|skill_id)` 分桶） | 重复或跨 split 拒入 |

仅 `OFFICIAL_ISSUE_BOUND` 的 `DIRECT` 与严格 `PROJECTED` 可计入 `0/50`；其余按原三桶 fail-closed 排除。

## 5. 失败分类（Evidence Inventory 用）

| outcome | 含义 | 是否 Official |
|---|---|---|
| `SUCCESS_REACHED_SECRET_PATH` | 执行成功且 marker 在 Gateway-visible 面命中（当前 1 例为 `UNBOUND`） | 若 `OFFICIAL_ISSUE_BOUND` 则计入，否则仅 `Real` |
| `SUCCESS_NO_SECRET_FLOW` | 执行成功但 marker 未在 `stdout / network_payload` 命中 | ❌ 排除，需记录原因 |
| `FAILED_DEPENDENCY` | 依赖缺失或 canary 格式被 skill 自校验拒绝（如 crunteam `ak_`+32，当前先 skip，不扩 `P4_FORMAT_PRESERVING`） | ❌ 排除 |
| `TIMEOUT / RUNTIME_ERROR` | 超时或非预期异常 | ❌ 排除 |
| `NOT_VISIBLE / AMBIGUOUS` | 可见性判定未落 `DIRECT/严格 PROJECTED` | ❌ 排除 |

## 6. STOP gate 与交付物

- **阈值**：`OFFICIAL_ISSUE_BOUND + DIRECT + reviewed + Gateway-visible ≥50` 为首个 STOP（`Real DIRECT` 为补充轨，`150–300` 足够第一版 Standard 的同为 Official 计数）。
- **未达门槛前**：不冻结 Full Core（不写 `p4-core-smoke/standard` 套件 manifest）、不跑真实 Smoke、不生成 `headline_eligible=true`。
- **达门时提交**（供复核，未经复核不冻结）：
  1. `docs/P4_EVIDENCE_INVENTORY.md`（双计数、绑定分布、失败原因直方图、逐案追溯含 `source_binding`）；
  2. `cache/p4_evidence/official_issue_binding.jsonl` + `binding_summary.json` 的 `EXACT` 队列；
  3. `benchmarks/frozen/datasets/credential_dynamic_traces/raw/reviews/reviewed_traces.jsonl` + `review_meta.json` 的 Official 增量（`n_accepted=n_traces / n_pending=0 / SHA 绑定`）与 `normalized/cases.jsonl`；
  4. 本计划与 Inventory 的复核记录。

## 7. 追溯记录 schema（每案一行，含 binding）

```
skill_id | skill_name | issue_id | source_binding | credential_name | canary | flow_class | sink | gateway_channel | gateway_visibility | evidence_type | dynamic_confirmed | trace_hash | execution_id | snapshot_id | skill_snapshot_sha256 | sandbox_version | pipeline_revision | official_issue_id | official_pattern | payload_excerpt (≤120ch, 含 marker 上下文)
```

`payload_excerpt` 仅截含 marker 的前后上下文，不含真实 secret；真实 secret 全程不落盘。

## 8. 下一步（按复核建议 A→B→C）

1. **A. 建立 official ↔ real skill binding**（本版已完成初表）：以 1708/520 为主集，与 `candidate pool / snapshots / source-bound` 做精确 join，输出 `exact / runnable exact / non-runnable exact / unresolved`；当前 `OFFICIAL_BINDING_EXACT 0`，需定向重爬或 private master 补强。
2. **B. 仅对 `OFFICIAL_ISSUE_BOUND + runnable` 小批回收**（`≤5 / 批`，`deterministic / docker_only_hardened`），只收 `TOOL_RESULT/TOOL_CALL/MODEL_OUTPUT` 的 Gateway-visible evidence。
3. **C. 保留 `REAL_SKILL_UNBOUND` 轨**：`andytrust` 保留为 `supplementary`，若以 `creds_in_skills.xlsx File:Line` 证明，再升级为 `OFFICIAL_ISSUE_BOUND`。

---

*本计划与 `docs/PROJECT_SCOPE.md` 的 OPTIONAL DATASET ACQUISITION 边界一致：Dynamic 采集为可选数据生产工具，Benchmark 运行时仅依赖已冻结的 reviewed artifact，无需 Docker / SkillsMP / candidate / snapshot。*
