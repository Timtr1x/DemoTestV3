# P4 Dynamic 候选与审查（D1–D4）

本文只覆盖 **P4 Dynamic 数据生产的前置链路**：候选集 → 审查 → 切分。沙箱执行与冻结仍见 `docs/P4_DYNAMIC_ROADMAP.md`。

> 约束：宿主机 / Windows 命令统一用 `python`（`python -m pytest` / `python scripts/...` / `python -m demotest ...`），不再写 `python3`。Docker 镜像内若仅有 `python3`，应在镜像中提供 `python -> python3` 兼容入口。

## 链路（正确顺序）

```
真实来源（本地目录 / SkillsMP crawl 输出）
   ↓  candidates import-*        （不执行 Skill，preflight 先于 hash/copy）
p4_skill_candidates/candidates.jsonl + candidate_meta.json  （含 runtime_status）
   ↓  candidates materialize --seed 42 --limit 35 --require-runtime-ready  （一次 35，确定性排位）
staged skills dir + _p4_materialization.json  （candidate_set_id / selection_sha256 / source provenance）
   ↓  dynamic snapshot           （archive/per-skill SHA + 绑定 candidate_provenance）
snapshot
   ↓  dynamic doctor --self-test
   ↓  dynamic collect --snapshot <same> --offset 0  --limit 5   （同一 snapshot 分批）
      dynamic collect --snapshot <same> --offset 5  --limit 10
      dynamic collect --snapshot <same> --offset 15 --limit 20
traces.jsonl + trace_meta.json + executions.jsonl
   ↓  dynamic review-export → 人工逐项确认 7 gates → review-apply（fail-closed，flow 语义校验）
reviews/reviewed_traces.jsonl + review_meta.json  （仅 ACCEPTED，绑定 source/traces/verdict SHA）
   ↓  split（按 source_skill_id，同一 Skill 不跨 split）
dev / eval / holdout
```

## 预检（不执行）

先 `lstat` preflight：任何 symlink 直接 `REJECT_SYMLINK_ESCAPE`，不 `read_bytes` 宿主机文件；`REJECT_SYMLINK_* / REJECT_OVERSIZE` 只记 metadata、不复制内容；重复 SHA 去重，`classification_hint` 等仅作优先级、不成标签；危险代码不拒。

`REJECT_EMPTY / REJECT_OVERSIZE / REJECT_SYMLINK_ESCAPE / REJECT_DUPLICATE / REJECT_INCOMPLETE` 留在 `candidates.jsonl` 审计，`materialize` 默认只出 `ACCEPT`；P4 deterministic Core 应加 `--require-runtime-ready` 只取显式 `entry_command` 的 `RUNTIME_READY`（外置 `runtime_specs/runtime_specs.jsonl` sidecar，不改 Skill 字节），`SKILL.md`-only 为 `AGENT_REQUIRED` 留给 Extended。

sidecar 每条 spec 绑定写入时的 `source_sha256`；重新 crawl 后同一 `candidate_id` 字节变化（SHA 漂移）会自动降级为 `RUNTIME_SPEC_STALE`、不可执行，必须人工 `runtime-spec set` 重新确认，绝不沿用旧 spec 跑新代码。

## 审查（fail-closed）

新导出 `review.jsonl` 7 项 gates 默认为 `false`，`ACCEPTED` 必须人工逐项置 `true`；并严格校验 flow：`STDOUT_EXPOSURE -> stdout/TOOL_RESULT/DIRECT + marker in payload`，`NETWORK_EXFIL -> network/TOOL_CALL/PROJECTED + marker in payload`，`AUTHORIZED_SECRET_USE -> authorized_sink`，`REDACTED_OUTPUT -> safe_redaction`；未知 `flow_class` 不予 ACCEPT。`review-apply` / `freeze-reviewed` 绑定 `source traces.jsonl SHA / trace_meta SHA / verdict SHA`，`pending>0` 不许 freeze。

## 切分

`seed` + `split_version` 决定 `sha256(version|seed|skill_id)` 的分桶；同一 Skill 的 stdout + network 永远同 split，LineMod 不参与。

## CLI

```bash
python -m pytest tests/v3/datasets/test_p4_*.py -q

demotest dynamic candidates import-local --skills-dir <dir>
# 官方 SkillLeakBench 布局：Skill 在 repos/，metadata 在上一级 —— 显式两个参数最可复现
demotest dynamic candidates import-skillsmp \
  --skills-dir <phase1_downloads/repos> \
  --metadata <phase1_downloads/skills_metadata.json>
# 无 --metadata 时自动探测 <skills-dir>/skills_metadata.json 再 <skills-dir>/../skills_metadata.json
demotest dynamic candidates verify
# 人工确认 execution contract 后才写 sidecar（绑定当时 source_sha256）
demotest dynamic candidates runtime-spec set --candidate-id <id> --entry-command python /skills/main.py
demotest dynamic candidates materialize --dest-dir <skills-dir> --limit 35 --seed 42 --require-runtime-ready
# 同一 materialize 产物只做一次：
demotest dynamic snapshot --skills-dir <skills-dir>
demotest dynamic doctor --self-test
demotest dynamic collect --snapshot <id> --offset 0 --limit 5 --condition deterministic
demotest dynamic collect --snapshot <id> --offset 5 --limit 10 --condition deterministic
demotest dynamic collect --snapshot <id> --offset 15 --limit 20 --condition deterministic
demotest dynamic review-export --raw-dir <traces-raw-dir>
# 人工编辑 review.jsonl（7 gates 逐项改为 true 后再标 ACCEPTED）...
demotest dynamic review-apply --review <edited-review.jsonl>
demotest dynamic review-status
demotest dynamic freeze-reviewed
demotest dynamic verify --snapshot <id>
```
