# P4 Dynamic 采集路线（冻结声明）

## 当前状态（`main@9723067` 后）

- 合成链路已冻结为 **Extended / non-headline**：`credential_catalog_synthetic`（`C / catalog_derived`，`benchmark_track=extended, headline_eligible=false`），仅作对照，不计入 overall。
- 动态链路为**唯一 headline 路径**：`credential_dynamic_traces`（`A/B / DYNAMIC_TRACE`，`track=core`），由一次性沙箱的真实 `stdout / network_payload` 产生。
- **控制面已冻结**，全链路校验通过；P4 数据面为**代码就绪、零真实数据**——首批真实痕迹尚未在隔离机上采集。

## 下一步（Docker-only 可执行，VM 为优选而非硬要求）

```bash
demotest dynamic doctor --self-test          # T3 官方 fixture：stdout + network 必须都 detected
demotest dynamic snapshot --skills-dir <dir> # 冻结 skill 快照（archive/per-skill SHA）
demotest dynamic collect --snapshot <id> --offset 0 --limit 5 --condition deterministic
# 看资源占用/timeout/trace，稳定后继续串行分批累积：
demotest dynamic collect --snapshot <id> --offset 5  --limit 10 --condition deterministic
demotest dynamic collect --snapshot <id> --offset 15 --limit 10 --condition deterministic
# parser 人工逐条复核：stdout/network/allow/unresolved 是否符合 guide §17-§19
# 通过后冻结首个 headline 候选
```

Smoke 目标（`deterministic` 模式、fake-only、可复现）：先 5 个，再按 10/20 个分批；数量不足不做模板扩充。环境稳定、真实候选足够时可继续扩到几百甚至上千条真实 trace，主要成本是总耗时而不是同时内存。

## 套件占位（有意留白）

在 Smoke 人工复核前**不创建**任何 `p4-core-*` headline 套件（`smoke/standard/full/holdout`）。首个候选为：

> **`p4-dynamic-dev-v1` — `track=adhoc, headline_eligible=false`**

仅在 trace validity 验收通过后，再冻结 `p4-core-smoke-v1` 及后续 `standard/full/holdout`。此占位仅为文档声明，不在 `config/v3/suites.yaml` 与 `benchmarks/` 中预建文件。

## 隔离要求

真实 Skill 为不可信代码。**优选**仍是 disposable Linux VM → Docker；没有 VM/WSL 时，允许 `docker_only_hardened` 进入 Core，但必须在 trace/source lock 中如实记录 isolation level。

Docker-only Core 最低 profile：串行 `concurrency=1`、`--network none`、memory/CPU/PID limit、`--cap-drop ALL`、`no-new-privileges`、只读 `/skills`、默认只读 rootfs + tmpfs `/tmp`。不挂载 host home、docker.sock、SSH agent 或真实 credential，仅注入 `TEST_SECRET_*`。资源不足/timeout 记 unresolved，不得当 benign。

同一 snapshot 使用 `--offset/--limit` 分批累积；collector 按 `(skill_id, condition)` 跳过已完成 execution。snapshot、pipeline revision、collector version 或 sandbox resource profile 变化时拒绝混跑。

规模不再按机器内存硬限制：先 Smoke 20–50 trace；Docker 稳定且真实候选充足后，可逐批扩到 500–1000 左右。Core 只接受真实 `DYNAMIC_TRACE`，绝不使用 synthetic 补数量。

`P3_mcp_definition / P5_memory_write` 按 Phase 3/5 排期，当前不阻塞 P4；`credential_traces`（`enabled=false`）为历史垫片，保留不动。
