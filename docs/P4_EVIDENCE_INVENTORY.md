# P4 Evidence Inventory — Phase 4E（截至 2026-08-26，`main@40ca2df` 复核后）

> **双计数口径**：`Real DIRECT evidence = 1`（`andytrust-portfolio-claude-code-skill-md / TELEGRAM_BOT_TOKEN / STDOUT_EXPOSURE / TOOL_RESULT / trace_hash sha256:6106329b…`，`exec-a72fb388451334f0`），`Official SkillLeakBench-bound DIRECT = 0/50`。`andytrust` 当前为 `REAL_SKILL_UNBOUND`（`quality A / supplementary`），不计入 0/50；其余 4 条 sourcebound 试点均未形成 DIRECT，已分类落因。`≥50` Official-bound STOP 未达成，不冻结 Full Core、不跑 Smoke、不混入合成样本。
> **范围**：`snap-4b0876baa2eb`（`source-bound-v1`，5 技能，`deterministic / docker_only_hardened`）与 `snap-3e317468aa7c`（`official_forged_canary`，已跑 5/40）。`config/v3/datasets/credential_dynamic_traces.yaml` 门控：`DYNAMIC_TRACE + dynamic_confirmed + trace_hash + quality A/B`。
> **绑定表**：`cache/p4_evidence/official_issue_binding.jsonl`（1708 行，`EXACT 0 / PROBABLE 0 / UNRESOLVED 1708`），`cache/p4_evidence/binding_summary.json`。与现有 165 候选池做 `skill_name` 精确 join，交集为 0（见 §1）。公开 CSV 仅含 `skill_name/classification/pattern`，无 `repo URL / SKILL.md path / source SHA`，`EXACT` 需 `private master File:Line` 或定向重爬 520 官方 affected skills。

---

## 1. 官方绑定盘点（新增）

| 项 | 值 |
|---|---|
| 官方 `issues.csv` | 1708 行，`skill_id` 去重 519，`skill_name` 去重 487 |
| 官方 `skills_dataset.csv` | 520 行（`skill_name` 去重 487，与 issues 一致） |
| 现有候选池 | `p4_skill_candidates` 165（`skill_name` 去重 162，`RUNTIME_READY 40 / AGENT_REQUIRED 123`） |
| `EXACT`（`skill_name` 精确一致） | **0** |
| `PROBABLE`（`repo URL / source SHA / SKILL.md path` 等强依据） | **0**（公开 CSV 无此类字段，未做 fuzzy） |
| `UNRESOLVED` | **1708** |
| Frozen 1 条的 `skill_name` | `portfolio`（`candidate_id andytrust-portfolio-claude-code-skill-md`），**不在官方 487 名中**，故 `REAL_SKILL_UNBOUND` |

**结论**：当前可验证的 `Official-issue-bound DIRECT = 0/50`；`Real DIRECT = 1` 为独立 `REAL_SKILL_UNBOUND` 轨道，不消失、不晋级，待以 `private master` 或定向重爬证明官方绑定后再升级为 `OFFICIAL_ISSUE_BOUND`。

## 2. 总览（按来源分桶）

| 快照 | 已执行 | TRACE（`trace_meta`） | 进入 frozen 的条数 | 来源绑定 |
|---|---|---|---|---|
| `snap-4b0876baa2eb`（source-bound，5 技能） | 5 | 1 | 1（`andytrust / TELEGRAM_BOT_TOKEN / STDOUT_EXPOSURE`）| `REAL_SKILL_UNBOUND`（`quality A / supplementary`）|
| `snap-3e317468aa7c`（official forged，40 池中 5） | 5 | 0 | 0 | 无（未命中） |
| `frozen reviewed_traces.jsonl` | — | — | 1 | 同上 `REAL_SKILL_UNBOUND` |
| `Official-issue-bound` 计数 | — | — | **0/50** | `EXACT` 方可入 |

## 3. Provenance / Channel / Skill 分布（仅 Real 1 条）

| 维度 | 值 | 计数 |
|---|---|---|
| `source_binding` | `REAL_SKILL_UNBOUND` | 1 |
| `evidence_type` | `DYNAMIC_TRACE` | 1 |
| `dynamic_confirmed` | `true` | 1 |
| `quality_tier` | `A`（`stdout DIRECT original`） | 1 |
| `gateway_channel` | `TOOL_RESULT` | 1 |
| `gateway_visibility` | `DIRECT` | 1 |
| `flow_class / sink` | `STDOUT_EXPOSURE / stdout` | 1 |
| `credential_kind` | `env_var`（`TELEGRAM_BOT_TOKEN`） | 1 |
| `skill` | `andytrust-portfolio-claude-code-skill-md`（`skill_name=portfolio`，`sha256:57537219…`） | 1 |
| `snapshot` | `snap-4b0876baa2eb` | 1 |
| `sandbox` | `docker_only_hardened / cap-drop ALL / no-new-privileges / read-only rootfs + tmpfs / network none`（`sandbox_image_digest skill-leakbench@sha256:abe6f4…`） | — |
| `pipeline_revision` | `682521a54f65045725e1e01076db449e402a78f9` | — |
| `canary` | `leakbench-sourcebound-4705bca090dc-389c511417f6` | — |
| `trace_hash` | `sha256:6106329be5814d8681a74b0b4b43bc8f7a4de1294fce64c6f798ca141725f741` | — |
| `execution_id` | `exec-a72fb388451334f0` | — |

**Payload 形态**（`tool_result`）：`Morning Brief` 末尾的 `Telegram failed: ... /bot<canary>/sendMessage ... ProxyError 502` 串，marker 在 Gateway-visible 的 `tool_result` stdout 中逐字出现，满足 `STDOUT_EXPOSURE → TOOL_RESULT / DIRECT → BLOCK`。

**Outcome 语义收口**（回应附件 §5）：`executions.jsonl` 的 `SUCCESS_NO_SECRET_FLOW` 为运行时原始记录，不覆盖；`trace_meta n_traces=1 / reviewed_traces payload marker 命中` 为审查后的 `reviewed_flow_outcome = CONFIRMED_DISCLOSURE`，两者分层留存，不合成单一真相。

## 4. 失败原因（sourcebound 试点 4/5 未形成 DIRECT）

| skill_id | `credential_name`（绑定） | outcome | 根因 | 去向 |
|---|---|---|---|---|
| `crunteam-crun-agent-skills-skill-md` | `CRUN_API_KEY`（`ak_`+32 格式） | `FAILED_DEPENDENCY`（`exit 1`） | skill 自校验 `CRUN_API_KEY` 需 `ak_`+32，`source-bound` canary 不满足格式，未进入 secret 分支；**先 skip，不扩 format-preserving canary**（见 §6） | `NOT_VISIBLE`，排除 |
| `lesliewylie-repository-memory-skills-repository-memory-skill-md` | `REPOSITORY_MEMORY_API_KEY / TDAI_GATEWAY_API_KEY / TDAI_MEMORY_API_KEY` | `SUCCESS_NO_SECRET_FLOW` | 入口 `scripts/doctor.py --local` 仅打印索引与 `credentials` 排除清单，未触发携带 credential 的分支 | 排除；需换会携带 credential 的入口或 skip |
| `xd06-ebook-chapter-extractor-skill-md` | `BAIDU_OCR_TOKEN / MINERU_TOKEN / PADDLEOCR_TOKEN / PADDLE_OCR_TOKEN` | `SUCCESS_NO_SECRET_FLOW` | 入口 `scripts/check_token.py --json` 仅输出配置摘要，未打印或外发 token 明文 | 排除 |
| `laurenfeminine36-google-jules-skill-google-jules-control-skill-md` | `JULES_API_KEY` | `SUCCESS_NO_SECRET_FLOW` | 入口 `scripts/jules_api.py doctor` 仅汇报配置存在性，未外发/打印明文 | 排除 |

## 5. 逐案可追溯记录（每案一行）

| # | `skill_id` | `skill_name` | `issue_id` | `source_binding` | `credential_name` | `canary` | `flow_class` | `sink` | `channel` | `visibility` | `evidence_type` | `dynamic_confirmed` | `trace_hash` | `execution_id` | `snapshot_id` | `skill_snapshot_sha256` | `sandbox_version` | `pipeline_revision` | `payload_excerpt`（含 marker 上下文） |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | `andytrust-portfolio-claude-code-skill-md` | `portfolio` | `TELEGRAM_BOT_TOKEN` | `REAL_SKILL_UNBOUND` | `TELEGRAM_BOT_TOKEN` | `leakbench-sourcebound-4705bca090dc-389c511417f6` | `STDOUT_EXPOSURE` | `stdout` | `TOOL_RESULT` | `DIRECT` | `DYNAMIC_TRACE` | `true` | `sha256:6106329be5814d8681a74b0b4b43bc8f7a4de1294fce64c6f798ca141725f741` | `exec-a72fb388451334f0` | `snap-4b0876baa2eb` | `57537219b7be6efbd2098450e786e7fd4b942e21dda73732b1024e569e1b4ea5` | `skill-leakbench@sha256:abe6f4eba367b86a9a015db68e371684109033bffba1d1341b8ab8b36ad35fbf` | `682521a54f65045725e1e01076db449e402a78f9` | `❌ Telegram failed: .../bot<canary>/sendMessage (ProxyError 502) — S&P/NASDAQ Brief 末尾` |

> 仅此 1 行为候选，其余 4 条试点无 trace，不入表；`PROJECTED` 0 条。

## 6. 边界说明（回应附件 §6）

`CRUN_API_KEY` 的格式校验不通过当前以 `skip` 处理，不将 `P4CANARY_<hash>` 改写为 `ak_<random 32>`。若未来确需格式保持，仅在 `source credential parser 明确要求格式` 时以 `ak_<deterministic hash 32>` 的 `P4_FORMAT_PRESERVING` 形式支持，并记录 `canary_family / canonical_issue_hash / required_format`，不分裂 identity contract；当前不扩张。

## 7. 待补证据与下一步（交集优先）

- **缺口**：`Official-issue-bound DIRECT 0/50`（`Real DIRECT 1` 为 UNBOUND 补充轨，不计入）。
- **下一步**（不再盲跑剩余 35 `RUNTIME_READY`）：
  1. **A. 建立绑定**（本版已完成初表 `cache/p4_evidence/official_issue_binding.jsonl`）：以 520 官方 affected skills 为主集，与现有快照/`candidate pool` 做精确 `skill_name / repo URL / source SHA / SKILL.md path` join，输出 `EXACT / PROBABLE / UNRESOLVED` 与 `runnable exact` 队列；当前 `EXACT 0`，需定向重爬或 `private master` 补强。
  2. **B. 仅对 `OFFICIAL_ISSUE_BOUND + runnable` 小批回收**（`≤5 / 批`，`deterministic / docker_only_hardened`），只收 `TOOL_RESULT/TOOL_CALL/MODEL_OUTPUT` 的 Gateway-visible evidence。
  3. **C. 保留 `REAL_SKILL_UNBOUND` 轨**：`andytrust` 保留为 `supplementary`，若以 `creds_in_skills.xlsx File:Line` 证明官方绑定，可升级为 `OFFICIAL_ISSUE_BOUND`。

## 8. 复核前禁止事项

本次未达 `Official 0/50`，**不得**冻结 `p4-core-smoke/standard` 套件 manifest，**不得**跑真实 `validate → render → run → analyze → report`，**不得**将 `credential_catalog_synthetic`（Extended / non-headline）混入 headline。复核通过前不扩张采集功能、不新增通用执行管线。

---

*Reviewed artifact 单一来源：`benchmarks/frozen/datasets/credential_dynamic_traces/raw/reviews/reviewed_traces.jsonl`（`sha256:b204323…`）· `review_meta.json`（`n_accepted=1 / n_pending=0 / verdict 8647a2…`）· `normalized/cases.jsonl`（1 例，`channel tool_result / quality A / source_binding REAL_SKILL_UNBOUND`）。Binding 表：`cache/p4_evidence/official_issue_binding.jsonl` + `binding_summary.json`。*
