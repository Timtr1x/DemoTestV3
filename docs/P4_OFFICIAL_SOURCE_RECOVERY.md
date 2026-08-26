# P4 官方 487 Skill Source Recovery — Phase 4E（两层分层）

> **日期**：2026-08-26 · **框架**：`P4 4E Binding Resolver — PASS / P4 Recompute-gated Trust — PASS`
> **对象层**：`Source objects verified 20 / 487`（`SOURCE_OBJECT_VERIFIED 20`，`repo@commit` 已落盘且 `source_sha256` 重算一致）
> **映射层**：`Official Skill Bound 0 / 487`（尚无 `VERIFIED_OFFICIAL_MAPPING`，见 §4）
> **Issue 层**：`Official Issue Bound DIRECT 0/50`（未进入 `File:Line` 回收，STOP）
> **双计数**：`Real DIRECT 1 supplementary（andytrust / REAL_SKILL_UNBOUND）`
> **产物**：`cache/p4_evidence/official_source_evidence.jsonl`（20 行）· `cache/p4_evidence/mapping_audit.jsonl`（20 行）· `cache/p4_official_clones/`（20 个落盘 repo，含 `osk_xxx` Windows 兼容副本）· `cache/p4_evidence/official_skill_sources.jsonl`（487 行，`osk:<sha16>` 稳定键）· `--check` 通过
> **禁令**：`Docker=NO / LineMod=NO / runtime-spec=NO / Core manifest=NO / Smoke=NO`

---

## 1. 为什么需要两层分层

公开 `issues.csv / skills_dataset.csv` 只有 7 脱敏字段，无 `repo / commit / path / File:Line`。`official_issue_key = slb:<sha16(7字段)>` 只是 **sanitized identity**（1708 → 784 keys，`924 collisions / 366 groups`），不能直接挂 P4CANARY。现有 165 候选池与 487 官方名交集 0，盲跑帮不了 0/50。

本阶段先做 **skill → repo/commit/path**（第一层），再做 **File:Line evidence**（第二层）。但第一层中"对象是否可重算"与"`official_skill_name → repo/path` 是否为官方映射"是两类不同证据，必须分开计数：

```
SOURCE_OBJECT_VERIFIED = DECLARED_MAPPING + SOURCE_VERIFIED
  repo@immutable_commit 已落盘clone，skill_path 存在，subtree hash 重算一致（20 条满足）

OFFICIAL_SKILL_BOUND   = VERIFIED_OFFICIAL_MAPPING + SOURCE_VERIFIED
  上述对象验证 + 映射来源被证明来自 private master / 官方 pipeline 产物 / Zenodo / 作者 artifact
  或其他可独立复核的官方来源，并记录 mapping_provenance（当前 20 条均未满足，故 0）

STOP 只认第二层：OFFICIAL_ISSUE_BOUND + DIRECT + reviewed + Gateway-visible >= 50
```

`official_skill_key = osk:<sha16(sorted skill_ids | skill_name)>` 不以单一 `skill_name` 为最终身份，保留多 `skill_id` 场景（如 `creative-writer` 双 id）。

## 2. 约束（已收口，不再 hardening）

- `SOURCE_OBJECT_VERIFIED` / `OFFICIAL_SKILL_BOUND` 仅当 DemoTest 实际 `acquire repo@immutable_commit` 并对 `skill_path` 子树重算 `source_sha256` 且通过；仅有 sidecar 声明时为 `OFFICIAL_SOURCE_DECLARED`。同 `(repo,commit,path)` 多个非空不同 `source_sha` → `BOUND_AMBIGUOUS`。
- `branch` 永不算 immutable；`commit_sha` 限 `40/64 hex`；`symlink no-follow`（与 `demotest.datasets.source_lock.hash_raw_snapshot` 对齐，排除 `.git/__pycache__`，`blob = sorted(rel|sha256)`）。
- `resolve_skill_source` 为纯函数，candidate 缓存不一致仅在 `binding_method` 注明，不污染 official；`official_source_evidence.jsonl` 按 `skill -> list[evidence]` 聚合，冲突不静默覆盖。
- Issue 级 `OFFICIAL_BINDING_EXACT` 仍需 `File:Line`，禁止用 `skill_name` fallback。
- 映射晋升由 `cache/p4_evidence/mapping_audit.jsonl` 的 `audit_verdict == VERIFIED_OFFICIAL_MAPPING` 驱动；resolver 不自行推断官方映射。

## 3. 20 个 SOURCE_OBJECT_VERIFIED 明细（对象已重算一致）

每条均已 `git rev-parse HEAD + subtree (relative_path|file_sha sorted) SHA` 双校验通过，20/20 OK。下表 `official_skill_name / repo_url / commit / path / sha[:12] / clone dir`：

| # | skill | repo | commit | path | sha12 | clone dir |
|---|---|---|---|---|---|---|
| 1 | `aslaep123` | `whisolla/whistant-skills` | `de8213c59b6a…` | `tier-w/caldav-calendar` | `96d68ad38352` | `aslaep123` |
| 2 | `base-trading-agent` | `snyk/agent-scan` | `462e136f22e1…` | `tests/skills/malicious-skill` | `bedd41464a9c` | `base-trading-agent` |
| 3 | `creative-writer` | `profbernardoj/everclaw-community-branches` | `0b30b360eb97…` | `skills/skillguard/test-fixtures/evasive-10-roleplay` | `91890cc2a338` | `creative-writer` |
| 4 | `api-helper` | `profbernardoj/everclaw-community-branches` | `0b30b360eb97…` | `skills/skillguard/test-fixtures/evasive-03-prompt-subtle` | `2eefd299eb6c` | `api-helper` |
| 5 | `config-analyzer` | `cisco-ai-defense/skill-scanner` | `48f59347a54b…` | `evals/skills/behavioral-analysis/multi-file-exfiltration` | `626438274654` | `config-analyzer` |
| 6 | `better-polymarket` | `berabuddies/Semia` | `379bc25fe998…` | `tests/fixtures/skills/noreplyboter/polymarket-all-in-one` | `35b37c24a2fc` | `better-polymarket` |
| 7 | `anthropic-token-refresh` | `jx1100370217/my-openclaw-skills` | `1e755b04667e…` | `anthropic-token-refresh` | `44fc22e94258` | `anthropic-token-refresh` |
| 8 | `agent-inbox` | `gsd-build/agent-inbox` | `7cd2f9e15b44…` | `skill` | `d7a362c220f1` | `agent-inbox` |
| 9 | `youtube-watcher` | `whisolla/whistant-skills` | `de8213c59b6a…` | `tier-u/youtube-watcher` | `cd81fe649597` | `youtube-watcher + osk_6ce14…` |
| 10 | `clawhub` | `whisolla/whistant-skills` | `de8213c59b6a…` | `tier-w/clawhub` | `f41cb4c5c9a1` | `clawhub + osk_f9377…` |
| 11 | `frontend-design` | `snyk/agent-scan` | `462e136f22e1…` | `tests/skills/frontend-design` | `d7a20a0122ff` | `frontend-design + osk_64d40…` |
| 12 | `mcp-builder` | `snyk/agent-scan` | `462e136f22e1…` | `tests/skills/mcp-builder` | `91528a00e9f5` | `mcp-builder + osk_05e75…` |
| 13 | `claude-connect` | `berabuddies/Semia` | `379bc25fe998…` | `tests/fixtures/skills/tunaissacoding/claude-connect` | `0d24b1fb604a` | `claude-connect + osk_f3151…` |
| 14 | `godaddy` | `berabuddies/Semia` | `379bc25fe998…` | `tests/fixtures/skills/rdewolff/godaddy` | `fb5448a42039` | `godaddy + osk_b6fef…` |
| 15 | `coolify` | `StuMason/coolify-mcp` | `94bd9d98dc0c…` | `skills/coolify` | `3901223c3487` | `coolify + osk_6130b…` |
| 16 | `dialpad` | `membranedev/application-skills` | `f484c8265e70…` | `skills/dialpad` | `c344936c8206` | `dialpad + osk_ef117…` |
| 17 | `finance-news` | `kesslerio/finance-news-openclaw-skill` | `57c8c16aac17…` | `.` | `00b2bd2c1ae1` | `finance-news + osk_41970…` |
| 18 | `trakt-tv` | `OskarStark/clawdbot-trakt-tv` | `93dcf3ad2900…` | `.` | `2de2049ed9cc` | `trakt-tv + osk_8c91e…` |
| 19 | `kagi-search` | `Mic92/mics-skills` | `5a7817fb4284…` | `kagi-search/skill` | `2c7d4bc430e8` | `kagi-search + osk_0a352…` |
| 20 | `r2-storage` | `mrnsmh/openclaw-skill-r2-storage` | `dbdc3deb476c…` | `.` | `3a5cd1534420` | `r2-storage + osk_b3381…` |

## 4. 映射审计（`mapping_audit.jsonl`）— 为什么 OFFICIAL 仍为 0

20 条的 `mapping_audit.jsonl` 每行包含 `mapping_source_type / mapping_source_uri / mapping_source_revision / mapping_evidence_sha256 / mapping_method / mapping_confidence / audit_verdict / audit_reason / leaf_match / risk_flag`。评审结论：全部为 `skillsmp exact name match + github clone + subtree hash verify` 的**启发式映射**，未追溯到 `creds_in_skills.xlsx / 官方 pipeline 元数据 / Zenodo` 等可验证官方来源，因此**对象验证通过，但官方映射未验证**，按规则不得晋升为 `OFFICIAL_SKILL_BOUND`。

| 段 | 数量 | 代表 | 处置 |
|---|---|---|---|
| `COPIED_FIXTURE`（`FIXTURE/EVAL`） | 9 | `base-trading-agent / creative-writer / api-helper / config-analyzer / better-polymarket / frontend-design / mcp-builder / claude-connect / godaddy`（路径含 `tests/fixtures/evals/evasive/malicious`） | 优先复核，无法证明原始 provenance 则排除，不进入下一层 |
| `INFERRED_MAPPING` | 10 | `anthropic-token-refresh / agent-inbox / youtube-watcher / clawhub / coolify / dialpad / finance-news / trakt-tv / kagi-search / r2-storage` | 保留对象验证，需补官方 manifest 后再议 |
| `AMBIGUOUS` | 1 | `aslaep123`（`whisolla` 大仓 `tier-w/caldav-calendar`，与 `skill_name` 无 `leaf` 相关性） | 暂不晋升 |

当前最可能接近原始来源的为 `anthropic-token-refresh / finance-news / trakt-tv / r2-storage`（`leaf EXACT/PARTIAL` 且非 fixture），也仍需补官方 provenance 才能晋升。

## 5. 汇总与校验

| 项 | 值 |
|---|---|
| `official_source_evidence.jsonl` | 20 行，全部 `commit + source_sha256` 重算一致 |
| `mapping_audit.jsonl` | 20 行（`INFERRED 10 / COPIED_FIXTURE 9 / AMBIGUOUS 1 / VERIFIED_OFFICIAL 0`） |
| `cache/p4_official_clones/` | 20 个落盘 repo（含 `osk_xxx` Windows 兼容副本） |
| `official_skill_sources.jsonl` | 487 行（`SOURCE_NOT_FOUND 467 / SOURCE_OBJECT_VERIFIED 20 / OFFICIAL_SKILL_BOUND 0`；`--check` 同值） |
| `official_skill_sources_summary.json` | `source_object_verified_count 20 / official_bound_skill_count 0 / official_issue_bound_DIRECT 0` |
| `official_issue_binding.jsonl` | 1708 行 `OFFICIAL 0`（沿用，issue 级仍需 File:Line） |

校验：

```
python scripts/p4_recover_official_skill_sources.py --check   # 487: SOURCE_NOT_FOUND 467 / SOURCE_OBJECT_VERIFIED 20
python scripts/p4_build_official_binding_inventory.py --check # 0 OFFICIAL issue-level (p
