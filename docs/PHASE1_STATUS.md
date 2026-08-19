# DemoTest Phase 1 — 当前状态报告（截至 2026-08-19，e64ce6b → 本次 final-final fix）

> 验收基准：`LLMail 1063bdf01ec8...`、`AgentDojo 089ed468cf3e...`、清单 `v3.2 byte-identical`、`split-v2 case-weighted`、`strata+cluster cap`
> 权威清单：`benchmarks/suites/*.json`（含 `manifest_sha256` 与 `suite_config_hash`，见 `manifest suite-verify`）

---

## 1. 概览结论

- **P1/P2 Core 语义已冻结**：`P1=LLMail-only`（真实人类攻击）、`P2=AgentDojo tool_call`（`ground_truth` 确定性投影，`quality B`）。AgentDojo `P1 tool_result / get_injection_vector_defaults` 已彻底删除，仅可作 `Extended` track。
- **清单与套件 v2 已冻结**：`manifest v3.2` 无 `created_at`、真 `read_bytes` 一致、`split-v2 case-weighted`、`strata+max_cluster_share 0.01` 生效、suite 绑定 `manifest_sha256` 与 `suite_config_hash`。
- **默认路径真低内存**：`BoundedHashSelector` 为 `O(K)`（`heap + heap_ids`，1M offers 已测）；`verify_normalized` 逐条 `validate_provenance` 真 streaming；`full-source` 为逐条 `exact+normalized` 去重直写证据，不调 `run_dedup / sorted`，不产生 `O(N2)`。
- **存储隔离**：`--full-source` 写入 `cache/datasets_v3/evidence/<dataset>/cases.jsonl`，不覆盖 `normalized/` 正式快照；`manifest build` 会拒绝证据池（需重做 bounded prepare）。

---

## 2. 数据与锁

```text
datasets.yaml  llmail 1063bdf01ec8... 1.1.0 A / agentdojo 089ed468cf3e... v1 1.1.0 B
locks  llmail a223abaf... / agentdojo 57726b74...  均为 1.1.0
normalized  llmail 3860 (3700 attack 3145/555 + 160 benign, 13M) / agentdojo 952 tool_call (exact 153)
evidence  llmail --full-source 时 148K 逐条去重直写，非 manifest 用途
```

> `llmail.yaml / agentdojo.yaml` 的重复 `suite_targets` 已删除，配额唯一来源为 `suites.yaml`。

---

## 3. 清单与套件

```text
OK: llmail normalized 3860 / agentdojo 952
OK: benchmarks/manifests/smoke-v2/p1.json           n=120  (dev 80+40)
OK: benchmarks/manifests/phase1-standard-v2/p1.json n=1674 (eval 1580+94)
OK: benchmarks/manifests/phase1-full-v2/p1.json     n=2683 (eval+holdout 2563+120)
OK: suite-verify smoke-v2 / standard-v2 / full-v2 / holdout-v2  all OK
```

| 套件 | 总数 | P1 | P2 |
|------|------|----|-----|
| `smoke-v2` | `220` | `120` | `100` |
| `phase1-standard-v2` | `2214` | `1674` | `540` |
| `phase1-full-v2` | `3444` | `2683` | `761` |
| `holdout-v2` | `676` | `526` | `150` |

权威 hash 查询：`benchmarks/suites/*.json` 的 `manifest_sha256` 与 `suite_config_hash`；`manifest_sha256` 为清单自哈希，`suite_config_hash` 绑定 `suites.yaml` 当前配置，不再手抄 abbreviate hash。

---

## 4. Full-source 说明

`--full-source` 当前逐条计算 `raw_sha / normalized_sha` 去重后直接 `jsonl` 写出（source-order），不保存完整 `SecurityCase` 列表、不 `sorted`、不 `near-dup O(N2)`，内存仅 `seen_raw + seen_norm` hash 集合。type 证据写入 `evidence/`，正式 Benchmark 始终走 `bounded 3860 → dedup/sorted → strata`，与证据路径物理隔离。

---

## 5. 测试与验证

```text
PYTHONPATH=src pytest tests/v3 -q   # 含 1M bounded selector 测试，全部通过
PYTHONPATH=src pytest tests/ -q     # 全量通过
manifest suite-verify <suite>       # 含 manifest 自hash + suite_config_hash 绑定
```

---

## 6. 归档

- `docs/archive/PHASE1_STATUS_56948f8.md`（56948f8 时代）
- 本报告为 final-final 后唯一现状说明；后续数据变更按 `v2 -> v3` 升版，不原地覆盖。
