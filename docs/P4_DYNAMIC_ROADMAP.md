# P4 Dynamic 采集路线（冻结声明）

## 当前状态（`main@9723067` 后）

- 合成链路已冻结为 **Extended / non-headline**：`credential_catalog_synthetic`（`C / catalog_derived`，`benchmark_track=extended, headline_eligible=false`），仅作对照，不计入 overall。
- 动态链路为**唯一 headline 路径**：`credential_dynamic_traces`（`A/B / DYNAMIC_TRACE`，`track=core`），由一次性沙箱的真实 `stdout / network_payload` 产生。
- **控制面已冻结**，全链路校验通过；P4 数据面为**代码就绪、零真实数据**——首批真实痕迹尚未在隔离机上采集。

## 下一步（一次性 Linux VM，顺序执行）

```bash
demotest dynamic doctor --self-test          # T3 官方 fixture：stdout + network 必须都 detected
demotest dynamic snapshot --skills-dir <dir> # 冻结 skill 快照（archive/per-skill SHA）
demotest dynamic collect --snapshot <id> --limit 20 --condition deterministic
# parser 人工逐条复核：stdout/network/allow/unresolved 是否符合 guide §17-§19
# 通过后冻结首个 headline 候选
```

Smoke 目标（`deterministic` 模式、fake-only、可复现）：5 个官方 fixture + 10–20 个真实 Skill → ≥5 stdout / ≥3 network / ≥5 allow。

## 套件占位（有意留白）

在 Smoke 人工复核前**不创建**任何 `p4-core-*` headline 套件（`smoke/standard/full/holdout`）。首个候选为：

> **`p4-dynamic-dev-v1` — `track=adhoc, headline_eligible=false`**

仅在 trace validity 验收通过后，再冻结 `p4-core-smoke-v1` 及后续 `standard/full/holdout`。此占位仅为文档声明，不在 `config/v3/suites.yaml` 与 `benchmarks/` 中预建文件。

## 隔离机要求

真实 Skill 为不可信代码，采集机应为一次性 Linux VM（非日常开发机），满足：disposable VM → Docker，无 host home/docker.sock/SSH agent/cloud metadata 挂载，仅注入 `TEST_SECRET` 假凭据。

`P3_mcp_definition / P5_memory_write` 按 Phase 3/5 排期，当前不阻塞 P4；`credential_traces`（`enabled=false`）为历史垫片，保留不动。
