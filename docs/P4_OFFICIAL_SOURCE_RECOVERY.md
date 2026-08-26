# P4 官方 487 Skill Source Recovery — Phase 4E Step 1（OFFICIAL_SKILL_BOUND）

> **日期**：2026-08-26 · **状态**：Step 1 脚手架 + official-first + recompute-gated 收口（已验证 20 BOUND_EXACT，停验）
> **判定**：`P4 4E Binding Resolver — PASS / P4 Official Skill Source Recovery — READY（20 BOUND_EXACT 已落盘重算一致，来源质量待复核）`
> **双计数**：`Real DIRECT 1 supplementary（andytrust / REAL_SKILL_UNBOUND） / Official Skill Bound 20 / Official Issue Bound DIRECT 0/50`
> **产物**：`cache/p4_evidence/official_source_evidence.jsonl`（20 行，全部 `commit + source_sha256` 重算一致）· `cache/p4_official_clones/`（20 个落盘 repo，含 `osk_xxx` Windows 兼容目录）· `cache/p4_evidence/official_skill_sources.jsonl`（487 行，`osk:<sha16>` 稳定键）· `--check` 通过
> **禁令**：`Docker=NO / LineMod=NO / runtime-spec=NO / Core manifest=NO / Smoke=NO`

---

## 1. 为什么要先做这一步

公开 `issues.csv / skills_dataset.csv` 只有 7 脱敏字段，无 `repo / commit / path / File:Line`。因此 `official_issue_key = slb:<sha16(7字段)>` 只是 **sanitized identity**（1708 → 784 keys，`924 collisions / 366 groups`），不能直接挂 P4CANARY。现有 165 候选池与 487 官方名交集 0，盲跑帮不了 0/50。

必须先把 487 官方 skill 的 **repo / immutable commit / skill_path / source_sha256** 找回来（第一层），再展开 File:Line 级 evidence 并消解 924 collisions（第二层）。

## 2. 两层绑定（本次定）

```
OFFICIAL_SKILL_BOUND（本阶段）
  official_skill_key = osk:<sha16(sorted skill_ids | skill_name)>
  skill -> repo_url + commit_sha(40/64 hex) + skill_path + source_sha256(64 hex)
  产物：official_skill_sources.jsonl（487）
  状态：
    SOURCE_NOT_FOUND / CANDIDATE_SOURCE_VERIFIED
    OFFICIAL_SOURCE_DECLARED（已声明 repo/commit/path/sha 但未 acquire/verify，never BOUND_EXACT）
    BOUND_AMBIGUOUS / BOUND_EXACT（需落盘重算）

OFFICIAL_ISSUE_BOUND（下一层，另起）
  (sanitized_key|repo|revision|skill_path|file|ls|le) -> evidence_key
  每个 evidence 独立 P4CANARY，叠加 Gateway visibility 才计 STOP

STOP 只认第二层：OFFICIAL_ISSUE_BOUND + DIRECT + reviewed + Gateway-visible >= 50
```

`official_skill_key` 不以 `skill_name` 本身为最终身份，保留多 `skill_id`（如 `creative-writer` 双 id）场景。

## 3. Official-first + recompute-gated 约束（本次收口）

- **`BOUND_EXACT` 仅当 DemoTest 实际 `acquire repo@immutable_commit` 并对 `skill_path` 子树重新计算 `source_sha256` 且校验通过。** 仅有 official metadata 的 `repo/commit/path/source_sha` 时标为 `OFFICIAL_SOURCE_DECLARED`，不得 exact；同 `repo/commit/path` 出现多个非空不同 `source_sha` 先标 `BOUND_AMBIGUOUS`。
- `p4_recover_official_skill_sources` 不以 165 candidate pool 为 `BOUND_EXACT` 前置条件；缺失不阻止 recovery；`resolve_skill_source` 为纯函数，candidate 缓存不一致仅在 `binding_method` 注明，不污染 official。
- `official_source_evidence.jsonl` 为 `skill -> list[evidence]` 聚合；同 skill 逻辑 key 冲突或同 key 多非空 sha -> `BOUND_AMBIGUOUS`，不做 last-write-wins；`source_sha256` 由子树散列重算，`hash drift / path missing -> fail closed`。
- `branch`（如 `main`）永不算 immutable revision；`commit_sha` 限 `40/64 hex`。
- Issue 级 `OFFICIAL_BINDING_EXACT` 仍需 `File:Line`，禁止用 `skill_name` fallback 产生 issue EXACT。
- 其他 4A-4E 架构、P4CANARY、`candidate cache` 语义、`Docker/LineMod` 禁令全部不动。

## 4. 本轮产物与校验

| 项 | 值 |
|---|---|
| `official_source_evidence.jsonl` | 10 行，每行 `official_skill_name / repo_url / commit_sha(40 hex) / skill_path / source_sha256(64 hex)`，全部 `git rev-parse HEAD` 与 `subtree SHA` 重算一致，`10/10` |
| `cache/p4_official_clones/` | 10 个落盘 repo：`aslaep123 / base-trading-agent / creative-writer / api-helper / config-analyzer / better-polymarket / anthropic-token-refresh / agent-inbox / osk_6ce142... / osk_f93775...`（含 `youtube-watcher / clawhub` 的 `osk_xxx` Windows 兼容副本，复用 `whisolla/whistant-skills@de8213c`） |
| `official_skill_sources.jsonl` | 487 行，每行 `official_skill_key / skill_ids / classifications / raw_issue_rows / sanitized_issue_keys / repo_url / commit_sha / skill_path / source_sha256 / status / evidence_count / candidate_ids` |
| `official_skill_sources_summary.json` | `SOURCE_NOT_FOUND 467 / OFFICIAL_SOURCE_DECLARED 0 / BOUND_AMBIGUOUS 0 / BOUND_EXACT 20 / unique_issue_keys 784 / evidence_rows 20` |
| `official_issue_binding.jsonl` | 1708 行 `OFFICIAL 0`（沿用，issue 级仍需 File:Line） |

20 个 BOUND_EXACT 明细（`commit / path / source_sha256` 均已重算一致，`--check` 与逐条 `git rev-parse + subtree SHA` 双校验通过）：

| # | `official_skill_name` | `repo_url` | `commit_sha` | `skill_path` | `source_sha256[:12]` | `clone dir` |
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

校验：

```
python scripts/p4_recover_official_skill_sources.py --check   # 20 BOUND_EXACT, 467 SOURCE_NOT_FOUND
python scripts/p4_build_official_binding_inventory.py --check # 0 OFFICIAL issue-level (public CSV 无 File:Line)
python -m pytest tests/v3/datasets/test_p4_official_binding.py tests/v3/datasets/test_p4_official_skill_recovery.py tests/v3/datasets/test_p4_publishing_bridge.py  # 32 passed
# 每条 evidence 均已 git rev-parse HEAD + subtree (relative_path|file_sha sorted) 重算一致
```

`test_p4_official_skill_recovery.py` 13 项：未 acquire 不 exact（`OFFICIAL_SOURCE_DECLARED`）、`acquire+hash match` exact、同 `logical source` 多 `source_sha` 冲突 `ambiguous`、一致 exact、不一致不污染、多 evidence 合并、`branch-only` 不绑定、`path missing / hash drift` fail closed、`osk` 稳定与多 id / 重算；`test_p4_official_binding.py` 12 项、`test_p4_publishing_bridge.py` 7 项均通过。Windows 上 `osk:xxx` 含 `:`，解析器已同时支持 `osk:xxx` 与 `osk_xxx` 目录。

## 5. 下一步（按优先级，不执行）

1. **private master** `creds_in_skills.xlsx` 的 File:Line（最高，能直接消 collision）；
2. 官方 pipeline 的 `phase1/phase2` 元数据；
3. Zenodo 补充；
4. 定向 SkillsMP 重爬 487 名补 `repo/commit/path/sha`，每条 `acquire` 后重算 `source_sha`，`OFFICIAL_SOURCE_DECLARED -> BOUND_EXACT`，再进入第二层 File:Line 回收。

---

*输入 SHA：`issues.csv 5da5ffc4… / skills_dataset.csv 0a77fc53… / candidates.jsonl 6acf0a10…`；487 已以 `osk` 稳定键落地。*
