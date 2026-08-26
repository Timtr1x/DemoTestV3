# P4 官方 487 Skill Source Recovery — Phase 4E Step 1（OFFICIAL_SKILL_BOUND）

> **日期**：2026-08-26 · **状态**：Step 1 脚手架完成（仅身份清单，不执行、不出 Core）
> **判定**：`P4 4E Binding Resolver — PASS / P4 Official Skill Source Recovery — READY`
> **双计数**：`Real DIRECT 1 supplementary（andytrust / REAL_SKILL_UNBOUND） / Official Skill Bound 0 / Official Issue Bound DIRECT 0/50` — 未达 STOP，不冻 Core，不跑 Smoke

---

## 1. 为什么要先做这一步

公开 `issues.csv / skills_dataset.csv` 只有 7 个脱敏字段：

```
skill_id / skill_name / classification / pattern_id / academic_code / pattern / severity
```

不含 `repo_url / commit SHA / SKILL.md path / File:Line / snippet`。因此：

- `official_issue_key = slb:<sha16(7字段)>` 只是 **sanitized identity**，不是物理 issue 身份；
- 1708 行只对应 784 个 sanitized key，`sanitized_identity_collisions = 924 / duplicate groups 366`；
- 现有 165 候选池与 487 官方名交集为 0 — 盲跑帮不了 0/50。

下一步必须先把 487 官方 skill 的 **repo / immutable revision / skill path / source SHA** 找回来（第一层），再在每个 skill 下展开 File:Line 级 evidence 并消解 924 collisions（第二层）。

## 2. 两层绑定语义（本次复核定）

```
第一层  OFFICIAL_SKILL_BOUND
  official_skill_name -> repo_url + commit SHA(40/64 hex) + skill_path + source_sha256(64 hex)
  产物：cache/p4_evidence/official_skill_sources.jsonl（487 行）

第二层  OFFICIAL_ISSUE_BOUND
  (sanitized_issue_key + repo + revision + skill_path + file_path + line_start + line_end + sink)
    -> official_evidence_key = sha256(sanitized_key|repo|revision|skill_path|file|ls|le)
    -> 每个 evidence 独立 P4CANARY
    -> 再叠加 Gateway visibility evidence 才可计入 STOP
  当前不能用 skill_name fallback 来产生 issue 级 EXACT

STOP gate 只认第二层：
  OFFICIAL_ISSUE_BOUND + DIRECT + reviewed + Gateway-visible >= 50
```

第一层 `BOUND_EXACT` 只是“已找到官方 skill 的可复现源码身份”；第二层才产生可进 Core 的 case。

本阶段 resolver 已修好信任边界：

- `is_candidate_source_verified` 只认 `repo + 64hex + path`，`branch` 永不参与；
- 无 official evidence 时单名命中仅 `CANDIDATE_SOURCE_VERIFIED`，不得 `OFFICIAL_BINDING_EXACT`；
- `source_sha256` 严格 64 hex，official revision 40/64 hex，允许 `candidate sha == official sha` 的内容-hash fallback 建立 EXACT。

## 3. 本轮产物（Step 1 脚手架）

| 产物 | 说明 |
|---|---|
| `scripts/p4_recover_official_skill_sources.py` | 纯本地、可复现的 487 清单生成器（`--check` 校验 1708/520/487 与 784 unique keys） |
| `cache/p4_evidence/official_skill_sources.jsonl` | 487 行，每行含 `official_skill_name / skill_ids / classifications / raw_issue_rows / sanitized_issue_keys / repo_url / commit_sha / skill_path / source_sha256 / status / binding_method` |
| `cache/p4_evidence/official_skill_sources_summary.json` | 汇总：`SOURCE_NOT_FOUND 487 / CANDIDATE 0 / BOUND_AMBIGUOUS 0 / BOUND_EXACT 0 / unique_issue_keys 784` |
| `cache/p4_evidence/official_issue_binding.jsonl` + `skill_binding.jsonl` + `binding_summary.json` | 沿用 `p4_build_official_binding_inventory` 的 1708/487 绑定表（`OFFICIAL 0`） |

当前 487 全部 `SOURCE_NOT_FOUND` — 预期值，因为未接入 private master / 定向重爬，现有 165 池 0 overlap。

## 4. 924 collisions 意味着什么

```
1708 raw rows -> 784 sanitized keys -> 924 collisions (366 groups)
最大碰撞：slb:c29d9b27430cb24c 占 48 行，a6dbf4215cfb049a 占 18 行
每个 skill 平均 1.61 个 sanitized keys，最多 6 个
30 个 skill_name 对应 2 个 skill_id（双分类留下）
```

因此 `slb:xxx` 上不能直接挂 P4CANARY。第二层必须展开为：

```
slb:abc -> slb-evidence:001 (File:Line A)
        -> slb-evidence:002 (File:Line B)
        -> slb-evidence:003 (File:Line C)
```

每个 evidence 独立 canary，`sanitized_identity_collisions` 在 private master 后消歧。

## 5. 下一步（按优先级，不执行）

1. **private master**：`creds_in_skills.xlsx` 的 File:Line / snippet / sink（最高优先级，能直接消解 collisions）；
2. **官方 pipeline 元数据**：`code/results/` 下若存在 `phase1/phase2` 的 repo/path 元数据；
3. **Open Science artifact / Zenodo 补充元数据**；
4. **定向 SkillsMP 重爬**：仅对 487 官方名定向 `repo + commit SHA + skill_path + tree SHA` 回填，每找到一条就冻结 `repo_url / commit_sha / skill_path / source_sha256`。

每补一条就更新 `official_skill_sources.jsonl` 的对应行，`status` 从 `SOURCE_NOT_FOUND` 升至 `BOUND_EXACT`，并记录 `binding_method / binding_confidence`。累计到一批 `BOUND_EXACT` 后再进入第二层 File:Line 回收。

## 6. 本阶段禁令

```
Docker = NO
LineMod 实际执行 = NO
runtime-spec 变更 = NO
Core manifest 生成 = NO
Smoke = NO
```
只做身份清单，不出可执行证据。

---

*输入 SHA：`issues.csv 5da5ffc4… / skills_dataset.csv 0a77fc53… / candidates.jsonl 6acf0a10…`；唯一键 784 /  collisions 924；`--check` 均通过。*
