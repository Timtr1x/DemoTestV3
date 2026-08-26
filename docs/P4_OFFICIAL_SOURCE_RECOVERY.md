# P4 官方 487 Skill Source Recovery — Phase 4E Step 1（OFFICIAL_SKILL_BOUND）

> **日期**：2026-08-26 · **状态**：Step 1 脚手架 + official-first 收口完成
> **判定**：`P4 4E Binding Resolver — PASS / P4 Official Skill Source Recovery — READY`
> **双计数**：`Real DIRECT 1 supplementary（andytrust / REAL_SKILL_UNBOUND） / Official Skill Bound 0 / Official Issue Bound DIRECT 0/50`
> **产物**：`cache/p4_evidence/official_skill_sources.jsonl`（487 行，`osk:<sha16>` 稳定键）· `--check` 通过
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

OFFICIAL_ISSUE_BOUND（下一层，另起）
  (sanitized_key|repo|revision|skill_path|file|ls|le) -> evidence_key
  每个 evidence 独立 P4CANARY，叠加 Gateway visibility 才计 STOP

STOP 只认第二层：OFFICIAL_ISSUE_BOUND + DIRECT + reviewed + Gateway-visible >= 50
```

`official_skill_key` 不以 `skill_name` 本身为最终身份，保留多 `skill_id`（如 `creative-writer` 双 id）场景。

## 3. Official-first 约束（本次收口）

- `p4_recover_official_skill_sources` 不以 165 candidate pool 为 `BOUND_EXACT` 前置条件；private master / official metadata 一旦提供 `repo + commit + path`即可独立 `acquire/verify` 并 `BOUND_EXACT`。
- Candidate pool 仅作本地复用缓存，缺失不阻止 recovery；`resolve_skill_source(managed)` 为纯函数，official 与 candidate 一致/不一致均不被污染（不一致时 official 仍可独立 EXACT，仅在 method 中注明 cache differs）。
- `official_source_evidence.jsonl` 为 `skill -> list[evidence]` 聚合；同 skill 多条 evidence 按 `(repo, commit, path, sha)` 去重，`(repo, commit, path)` 逻辑 key 冲突 -> `BOUND_AMBIGUOUS`，不做 last-write-wins。
- `source_sha256` 必须由 DemoTest 对 `repo@commit / skill_path` 的实际子树重新计算；若存在本地树则 `hash drift / path missing -> fail closed`，不只信 sidecar。未 acquire 时允许以官方 64 hex 占位，但下次 acquire 时必重算校验。
- `branch`（如 `main`）永不算 immutable revision；`commit_sha` 限 `40/64 hex`。
- Issue 级 `OFFICIAL_BINDING_EXACT` 仍需 `File:Line`，禁止用 `skill_name` fallback 产生 issue EXACT（见 `p4_build_official_binding_inventory`）。

## 4. 本轮产物与校验

| 项 | 值 |
|---|---|
| `official_skill_sources.jsonl` | 487 行，每行 `official_skill_key / skill_ids / classifications / raw_issue_rows / sanitized_issue_keys / repo_url / commit_sha / skill_path / source_sha256 / status / evidence_count / candidate_ids` |
| `official_skill_sources_summary.json` | `SOURCE_NOT_FOUND 487 / CANDIDATE 0 / BOUND_AMBIGUOUS 0 / BOUND_EXACT 0 / unique_issue_keys 784`（当前预期，尚未接入 private master/定向重爬） |
| `official_issue_binding.jsonl` | 1708 行 `OFFICIAL 0`（沿用） |

校验：

```
python scripts/p4_recover_official_skill_sources.py --check
python scripts/p4_build_official_binding_inventory.py --check
python -m pytest tests/v3/datasets/test_p4_official_binding.py tests/v3/datasets/test_p4_official_skill_recovery.py
```

`test_p4_official_skill_recovery.py` 覆盖 9 项：无 candidate 仍 EXACT / 一致 EXACT / 不一致不污染 / 多 evidence 一致合并 / 冲突 AMBIGUOUS / branch-only 不绑定 / path missing 与 hash drift fail closed / `osk` 稳定与多 id / 重算校验。

## 5. 下一步（按优先级，不执行）

1. **private master** `creds_in_skills.xlsx` 的 File:Line（最高，能直接消 collision）；
2. 官方 pipeline 的 `phase1/phase2` 元数据；
3. Zenodo 补充；
4. 定向 SkillsMP 重爬 487 名补 `repo/commit/path/sha`，每条冻结 `repo/commit/path/source_sha`。

每补一条更新 `official_skill_sources.jsonl`，`SOURCE_NOT_FOUND -> BOUND_EXACT`，再进入第二层 File:Line 回收。

---

*输入 SHA：`issues.csv 5da5ffc4… / skills_dataset.csv 0a77fc53… / candidates.jsonl 6acf0a10…`；487 已以 `osk` 稳定键落地。*
