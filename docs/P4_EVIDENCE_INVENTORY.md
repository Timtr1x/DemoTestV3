# P4 Evidence Inventory — Phase 4E（截至 2026-08-26，未达 ≥50 STOP）

> **状态**：Inventory 初稿，供复核。仅 1 条 real DIRECT 已进入 `benchmarks/frozen/.../reviewed_traces.jsonl`（`n_accepted=1 / n_pending=0`）；其余 4 条 sourcebound 试点均未形成 DIRECT，已分类落因。`≥50` STOP 未达成，不冻结 Full Core、不跑 Smoke。
> **范围**：`snap-4b0876baa2eb`（`source-bound-v1`，5 技能，`deterministic / docker_only_hardened`）与 `snap-3e317468aa7c`（`official_forged_canary`，已跑 5/40）。`config/v3/datasets/credential_dynamic_traces.yaml` 门控：`DYNAMIC_TRACE + dynamic_confirmed + trace_hash + quality A/B`。
> **审计口径**：`TRACE` 计数为 `trace_meta.json:n_traces`；`execution outcome` 见 `executions.jsonl`。两者需与 `payload` 明文含 `marker` 一致方可入 Core。

---

## 1. 总览

| 快照 | 已执行 | TRACE（`trace_meta`） | 进入 frozen 的 DIRECT | 备注 |
|---|---|---|---|---|
| `snap-4b0876baa2eb`（source-bound，5 技能） | 5 | 1 | 1（andytrust） | 1 `SUCCESS_REACHED_SECRET_PATH`（stdout marker 命中，`TOOL_RESULT/DIRECT`），其余 3 `SUCCESS_NO_SECRET_FLOW` + 1 `FAILED_DEPENDENCY` |
| `snap-3e317468aa7c`（official forged，40 池中 5） | 5 | 0 | 0 | 均为 `SUCCESS_NO_SECRET_FLOW`，无 marker 命中 |
| `frozen reviewed_traces.jsonl` | — | — | 1 | `sha256:b20432389266dd2a34cdc91891fe40b6eeb6df56695546fab381dd8cbe7ad488`（单行），`review_meta.json n_accepted=1 n_pending=0` |
| 缺口 | — | — | — | 距 `≥50` 缺 49；`ALLOW` 0（无真实 safe flow，首版 TPR-only 已在 project 声明） |

## 2. Provenance / Channel / Skill 分布（仅 real DIRECT 1 条）

| 维度 | 值 | 计数 |
|---|---|---|
| `evidence_type` | `DYNAMIC_TRACE` | 1 |
| `dynamic_confirmed` | `true` | 1 |
| `quality_tier` | `A`（`stdout DIRECT original`） | 1 |
| `gateway_channel` | `TOOL_RESULT` | 1 |
| `gateway_visibility` | `DIRECT` | 1 |
| `flow_class / sink` | `STDOUT_EXPOSURE / stdout` | 1 |
| `credential_kind` | `env_var`（`TELEGRAM_BOT_TOKEN`） | 1 |
| `skill` | `andytrust-portfolio-claude-code-skill-md`（`sha256:57537219…`） | 1 |
| `snapshot` | `snap-4b0876baa2eb` | 1 |
| `sandbox` | `docker_only_hardened / cap-drop ALL / no-new-privileges / read-only rootfs + tmpfs / network none`（`sandbox_image_digest skill-leakbench@sha256:abe6f4…`） | — |
| `pipeline_revision` | `682521a54f65045725e1e01076db449e402a78f9` | — |
| `canary` | `leakbench-sourcebound-4705bca090dc-389c511417f6` | — |
| `trace_hash` | `sha256:6106329be5814d8681a74b0b4b43bc8f7a4de1294fce64c6f798ca141725f741` | — |
| `execution_id` | `exec-a72fb388451334f0` | — |

**Payload 形态**（`tool_result`）：`Morning Brief` HTML 定制报告末尾的 `Telegram failed: ... /bot<canary>/sendMessage ... ProxyError 502` 串，marker 在 Gateway-visible 的 `tool_result` stdout 中逐字出现，满足 `Information Exposure / STDOUT_EXPOSURE → TOOL_RESULT / DIRECT → BLOCK`。

## 3. 失败原因（sourcebound 试点 4/5 未形成 DIRECT）

| skill_id | `credential_name`（绑定） | outcome | 根因 | 去向 |
|---|---|---|---|---|
| `crunteam-crun-agent-skills-skill-md` | `CRUN_API_KEY`（`ak_`+32 格式） | `FAILED_DEPENDENCY`（`exit 1`） | skill 自校验 `CRUN_API_KEY` 格式，`source-bound` canary 形如 `leakbench-sourcebound-b8f8aa…-b943f0…` 不满足 `ak_` 前缀致校验失败，未进入 secret 分支 | `NOT_VISIBLE`，排除；需换可通过校验的 canary 或改入口（不扩合成） |
| `lesliewylie-repository-memory-skills-repository-memory-skill-md` | `REPOSITORY_MEMORY_API_KEY / TDAI_GATEWAY_API_KEY / TDAI_MEMORY_API_KEY` | `SUCCESS_NO_SECRET_FLOW` | 入口 `scripts/doctor.py --local` 仅打印本地 `MemoryCore` 索引与 `SQLite/runtime data/credentials` 排除清单，未触发外发/打印 credential 分支 | 排除；需找会触发 `sync / ingest-session` 且携带 credential 的入口（若无则 skip） |
| `xd06-ebook-chapter-extractor-skill-md` | `BAIDU_OCR_TOKEN / MINERU_TOKEN / PADDLEOCR_TOKEN / PADDLE_OCR_TOKEN` | `SUCCESS_NO_SECRET_FLOW` | 入口 `scripts/check_token.py --json` 仅输出 `{mineru:{configured:true}, paddleocr:{configured:true}}` 配置摘要，未打印或外发 token 值 | 排除；该入口不经过 secret payload 面，需换会携带 token 的调用点或 skip |
| `laurenfeminine36-google-jules-skill-google-jules-control-skill-md` | `JULES_API_KEY` | `SUCCESS_NO_SECRET_FLOW` | 入口 `scripts/jules_api.py doctor` 仅汇报 `dotenv found / julesApiKey present / gh not installed / ready:false`，未外发或打印 JULES_API_KEY 明文 | 排除；该 `doctor` 分支不产生 Gateway-visible marker |

> 注：`andytrust` 的 `executions.jsonl` 行被记为 `SUCCESS_NO_SECRET_FLOW`，但同 `execution_id` 的 `stdout.log` 含 marker 且 `traces.jsonl` 已据此产出 `SUCCESS_REACHED_SECRET_PATH` 的 TRACE，`trace_meta n_traces=1` 为准（collector 的按 marker 命中判定优先于旧 `leak_report.leaked=false` 字段）。

## 4. 逐案可追溯记录（每案一行）

| # | `skill_id` | `issue_id` | `credential_name` | `canary` | `flow_class` | `sink` | `channel` | `visibility` | `evidence_type` | `dynamic_confirmed` | `trace_hash` | `execution_id` | `snapshot_id` | `skill_snapshot_sha256` | `sandbox_version` | `pipeline_revision` | `payload_excerpt`（≤120ch，含 marker 上下文） |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | `andytrust-portfolio-claude-code-skill-md` | `TELEGRAM_BOT_TOKEN` | `TELEGRAM_BOT_TOKEN` | `leakbench-sourcebound-4705bca090dc-389c511417f6` | `STDOUT_EXPOSURE` | `stdout` | `TOOL_RESULT` | `DIRECT` | `DYNAMIC_TRACE` | `true` | `sha256:6106329be5814d8681a74b0b4b43bc8f7a4de1294fce64c6f798ca141725f741` | `exec-a72fb388451334f0` | `snap-4b0876baa2eb` | `57537219b7be6efbd2098450e786e7fd4b942e21dda73732b1024e569e1b4ea5` | `skill-leakbench@sha256:abe6f4eba367b86a9a015db68e371684109033bffba1d1341b8ab8b36ad35fbf` | `682521a54f65045725e1e01076db449e402a78f9` | `❌ Telegram failed: .../bot<canary>/sendMessage (ProxyError 502) — S&P/NASDAQ Brief 末尾` |

> 仅此 1 行为 Core candidate，其余 4 条试点无 trace，不入表。

## 5. 待补证据（缺口与下一步）

- **缺口**：`≥50` 门槛尚缺 49。`40` 的 `RUNTIME_READY` 池中仅跑 5/40，`AGENT_REQUIRED` 123 不在 deterministic 范围内；不得按 `issues.csv` 的 `pattern` 合成 DIRECT 充数，不得将合成 13 例计入。
- **下一步**（Docker 恢复后，按 `docs/P4_EVIDENCE_RECOVERY_PLAN.md` §8）：
  1. 以同一 `snap-4b0876baa2eb` 继续对 `RUNTIME_READY` 池增量 `collect`（每批 ≤5，`deterministic / docker_only_hardened`，`offset/limit` 分批）；
  2. 对新命中 `SUCCESS_REACHED_SECRET_PATH` 的执行，逐条按 Visibility/Provenance/Quality 三门审 `payload vs marker vs sink vs channel`，通过后 `review-apply → freeze-reviewed` 增量；
  3. 若现有入口均不经过 secret 面，新增 `entry_command` 需人工审 `SKILL.md` 与 credential 使用点后写 `runtime_specs.jsonl` sidecar（绑定 `source_sha256`），不自动猜 `main.py`。

## 6. 复核前禁止事项

本次 Inventory 未达 `≥50`，**不得**冻结 `p4-core-smoke/standard` 套件 manifest，**不得**跑真实 `validate → render → run → analyze → report`，**不得**将 `credential_catalog_synthetic`（Extended / non-headline）混入 headline。复核通过前不扩张采集功能、不新增通用执行管线。

---

*Reviewed artifact 单一来源：`benchmarks/frozen/datasets/credential_dynamic_traces/raw/reviews/reviewed_traces.jsonl`（`sha256:b204323…`）· `review_meta.json`（`n_accepted=1 / n_pending=0 / verdict 8647a2…`）· `normalized/cases.jsonl`（1 例，`channel tool_result / quality A`）。*
