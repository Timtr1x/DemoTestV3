# P4 Dynamic 采集路线（冻结声明）

## 当前状态（`main@9723067` 后）

- 合成链路已冻结为 **Extended / non-headline**：`credential_catalog_synthetic`（`C / catalog_derived`，`benchmark_track=extended, headline_eligible=false`），仅作对照，不计入 overall。
- 动态链路为**唯一 headline 路径**：`credential_dynamic_traces`（`A/B / DYNAMIC_TRACE`，`track=core`），由一次性沙箱的真实 `stdout / network_payload` 产生。
- **控制面已冻结**，全链路校验通过；P4 数据面为**代码就绪、零真实数据**——首批真实痕迹尚未在隔离机上采集。
- 宿主机命令统一 `python`：`python -m pytest` / `python scripts/...` / `python -m demotest ...`，文档与示例不再写 `python3`；容器内执行统一 `python`，镜像应提供 `python -> python3` 兼容入口。

## 下一步（正确顺序：intake → 人工 runtime spec → 一次 materialize 35 → 一次 snapshot → 同一 snapshot 分 5/10/20）

拿到数据源后不会自动得到 35 个 `RUNTIME_READY`：真实 Skill 通常没有 execution contract，import 后大多是 `AGENT_REQUIRED`。必须先由人工逐条确认入口并写入 sidecar（`runtime-spec set`，绑定当时 `source_sha256`），再 verify、materialize。绝不自动猜 `main.py` 当入口。

```bash
demotest dynamic candidates import-skillsmp --skills-dir <phase1_downloads/repos> --metadata <phase1_downloads/skills_metadata.json>
# 人工确认 ≥35 个 deterministic execution contract：
demotest dynamic candidates runtime-spec set --candidate-id <id> --entry-command python /skills/<entry>
demotest dynamic candidates verify
demotest dynamic candidates materialize --dest-dir <p4-smoke-35> --limit 35 --seed 42 --require-runtime-ready
demotest dynamic snapshot --skills-dir <p4-smoke-35>   # 绑定 candidate_set_id / materialization_sha256 / selected_runtime_specs_sha256 / source provenance
demotest dynamic doctor --self-test                    # T3 官方 fixture：stdout + network 必须都 detected
demotest dynamic collect --snapshot <same> --offset 0  --limit 5  --condition deterministic
# review 5
demotest dynamic collect --snapshot <same> --offset 5  --limit 10 --condition deterministic
# review incremental
demotest dynamic collect --snapshot <same> --offset 15 --limit 20 --condition deterministic
# review 全部 ACCEPTED/REJECTED（pending=0）且 hash 绑定一致后：
demotest dynamic freeze-reviewed
# 盲审通过后再冻结 p4-dynamic-dev-v1（adhoc, non-headline）
```

同一 `materialize` 产物只做一次 `snapshot`，后续 5/10/20 共享同一 `snapshot_id`，`resume / image digest / collector v4 / sandbox profile` 保持同一实验身份；每次都先走 Docker-only 串行 hardening 路径。

Smoke 目标（`deterministic` 模式、fake-only、可复现）：先 5 个，再按 10/20 个分批；数量不足不做模板扩充。环境稳定、真实候选足够时可继续扩到几百甚至上千条真实 trace，主要成本是总耗时而不是同时内存。

## 套件占位（有意留白）

在 Smoke 人工复核前**不创建**任何 `p4-core-*` headline 套件（`smoke/standard/full/holdout`）。首个候选为：

> **`p4-dynamic-dev-v1` — `track=adhoc, headline_eligible=false`**

仅在 trace validity 验收通过后，再冻结 `p4-core-smoke-v1` 及后续 `standard/full/holdout`。此占位仅为文档声明，不在 `config/v3/suites.yaml` 与 `benchmarks/` 中预建文件。

## 隔离要求

真实 Skill 为不可信代码。**优选**仍是 disposable Linux VM → Docker；没有 VM/WSL 时，允许 `docker_only_hardened` 进入 Core，但必须在 trace/source lock 中如实记录 isolation level。

Docker-only Core 最低 profile：串行 `concurrency=1`、`--network none`、memory/CPU/PID limit、`--cap-drop ALL`、`no-new-privileges`、只读 rootfs + tmpfs `/tmp` + tmpfs `/mock_creds`；冻结快照永不直接挂载，每次 execution 复制到可写工作区后以 `:rw` 挂载到 `/skills`，再配合 `official_forged_canary`（`sk-leakbench-mock-*` / `AKIA-LEAKBENCH-*`，与容器 entrypoint 完全同源）。`doctor --self-test` 必须走同一 `prepare_execution_copy → build_docker_argv → run_skill → parse_execution` 正式路径。

同一 snapshot 使用 `--offset/--limit` 分批累积；collector 按 `(skill_id, condition)` 跳过已完成 execution，execution 工作区按 `executions/<snapshot>/<skill>/<condition>/` 隔离。snapshot、pipeline revision、collector version、sandbox resource profile 或 image digest 变化时拒绝混跑；trace/source-lock 记录 `credential_provenance: official_forged_canary` 与完整 `sandbox_profile`，以及 `candidate_set_id / materialization_sha256`。

`demotest dynamic collect` 仅接受 `--condition deterministic`（P4 Core）；`benign/adversarial` 改由 `demotest dynamic agent-collect`（Host-side `AgentDriver`，真实 API Key 永不进入 Docker/trace/manifest），第一版数据保持 Extended / non-headline。

`P3_mcp_definition / P5_memory_write` 按 Phase 3/5 排期，当前不阻塞 P4；`credential_traces`（`enabled=false`）为历史垫片，保留不动。
