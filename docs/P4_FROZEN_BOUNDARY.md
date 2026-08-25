# P4 冻结边界 — Frozen Boundary（Phase 4D 后）

> **日期**：2026-08-25 · **状态**：冻结声明（`4614168` 后）
> **验收定性**：`P4 Phase 4D Synthetic Projection Gate — COMPLETE`，非 `P4 Core READY`

---

## 1. 结论

- `4614168` 的 `13` 例 `P4CANARY` 门控是 **production-schema compatibility proof**：证明“若未来得到满足真实 `provenance contract` 的 `CredentialTrace`，现有 `Adapter/Renderer` 能正确处理”。
- 它**没有**证明“已拥有满足该 contract 的 SkillLeakBench `DIRECT` trace”。
- 因此：**Full Core Freeze / Real Smoke / Standard 均不得开始**。下一阶段唯一合法任务为 **Phase 4E Real Evidence Recovery**。

合成 fixture 中的 `DYNAMIC_TRACE / dynamic_confirmed / trace_hash` 为测试构造，占位 `placeholder`，不得解释为真实 `A 级 provenance`。

---

## 2. 冻结清单（不再改）

- `docs/P4_VISIBILITY_CONTRACT.md`
- `docs/P4_SANITIZATION_CONTRACT.md`
- `src/demotest/renderers/credential_flow.py` 与 `config/projects.yaml#P4_credential_flow` 的 renderer / fidelity
- `src/demotest/targets/` / `src/demotest/oracles/`
- `scripts/_p4_projection_proof.py` 的 synthetic fixture（不再扩充为真实数据）

---

## 3. 禁止事项

- 不得按 `issues.csv` 的 `pattern`（如 `Information Exposure`）批量生成 `stdout` 泄漏样本充当 `DIRECT`；
- 不得将 synthetic `P4CANARY` / synthetic `ALLOW` 计入真实 Core 的 `≥50 / ≥150–300` 门槛；
- 不再扩展 `Adapter` 与通用 Skill runtime 平台，Phase 4E 仅作为**证据恢复工具**小范围复现“能跑且能产生 Gateway-visible marker”的 case，跑不了即 `skip`.

---

## 4. Phase 4E 的两条合法来源

- **路径 A（首选）**：论文 `private master`（`File:Line / Code Snippet / IOC span`）→ 内存定位 `span` → `P4CANARY` 一对一替换 → 立即丢弃 `raw secret`，仓库永不落地真实 `secret`；
- **路径 B（备选）**：官方 `pinned pipeline` 对少量 `affected skills` 以 `fake credential` 复现，严格作证据恢复用，不扩展为平台。

真实 Core 门槛：`≥50 real DIRECT` 可先做真实 Smoke/Dev，`150–300` 足够第一版 Standard，`400–500` 更佳但不为数量重启复杂工程。`ALLOW` 若无真实 `safe credential flow`，则第一版保持 `TPR-only / headline_eligible=false`，不混入 synthetic `ALLOW` 冒充 `FPR`。

---

## 5. 研判对齐

本文档固化评审研判：`4A ✅ / 4B ✅ / 4C ✅ / 4D ✅(synthetic proof)`，`真实 DIRECT evidence ❌ / Full Core ❌ / Real Smoke/Standard ❌`。与 `docs/P4_PROJECTION_PROOF.md` 的“合成样本仅验证链路”声明一致。
