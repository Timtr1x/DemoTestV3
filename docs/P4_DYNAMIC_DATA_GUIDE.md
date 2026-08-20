# P4 Dynamic 候选与审查（D1–D4）

本文只覆盖 **P4 Dynamic 数据生产的前置链路**：候选集 → 审查 → 切分。沙箱执行与冻结仍见 `docs/P4_DYNAMIC_ROADMAP.md`。

## 链路

```
真实来源（本地目录 / SkillsMP crawl 输出）
   ↓  candidates import-*   （不执行 Skill，只做文件级预检）
p4_skill_candidates/candidates.jsonl + candidate_meta.json
   ↓  candidates materialize --seed 42 --limit 35   （确定性排位）
staged skills dir
   ↓  dynamic snapshot  （archive/per-skill SHA）
snapshot
   ↓  dynamic collect --offset/--limit  （Docker-only 沙箱）
traces.jsonl + trace_meta.json + executions.jsonl
   ↓  dynamic review-export → 人工改 review.jsonl → review-apply
reviews/reviewed_traces.jsonl + review_meta.json  （仅 ACCEPTED）
   ↓  split（按 source_skill_id，同一 Skill 不跨 split）
dev / eval / holdout
```

## 预检（不执行）

`REJECT_EMPTY / REJECT_OVERSIZE / REJECT_SYMLINK_ESCAPE / REJECT_DUPLICATE / REJECT_INCOMPLETE` 会留在 `candidates.jsonl` 中审计，但不会进入 `materialize` 默认输出；**危险代码不作为拒绝理由**；`classification_hint` 等仅作候选优先级参考，不会成为标签。

## 审查

`traces.jsonl` 永不手改。审查是每条 trace 的覆盖式裁决（`ACCEPTED / REJECTED / NEEDS_REVIEW`），`review-apply` 校验 `REVIEW_VERSION` 与 `DYNAMIC_TRACE + dynamic_confirmed + trace_hash` 后冻结 `reviewed_traces.jsonl`。

## 切分

`seed` + `split_version` 决定 `sha256(version|seed|skill_id)` 的分桶；同一 Skill 的 stdout + network 永远同 split，LineMod 不参与。

## CLI

```bash
demotest dynamic candidates import-local --skills-dir <dir>
demotest dynamic candidates import-skillsmp --source <crawl-output>
demotest dynamic candidates verify
demotest dynamic candidates materialize --dest-dir <skills-dir> --limit 35 --seed 42
demotest dynamic snapshot --skills-dir <skills-dir>
demotest dynamic collect --snapshot <id> --offset 0 --limit 5 --condition deterministic
demotest dynamic review-export --raw-dir <traces-raw-dir>
# 人工编辑 review.jsonl ...
demotest dynamic review-apply --review <edited-review.jsonl>
demotest dynamic review-status
demotest dynamic freeze-reviewed
demotest dynamic verify --snapshot <id>
```
