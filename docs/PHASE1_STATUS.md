# DemoTest Phase 1 — 当前状态报告（截至 2026-08-19，56948f8 → 本次 final fix）

> 验收基准：`LLMail 1063bdf01ec8…`、`AgentDojo 089ed468cf3e…`、清单 `v3.2 byte-identical`、`split-v2 20/60/20 case-weighted`、`strata+cluster cap`

---

## 1. 概览结论

- **P1/P2 Core 语义已正确**：`P1=LLMail-only`（真实人类攻击 160 benign + 3700 attack bounded pool）、`P2=AgentDojo tool_call`（`ground_truth` 确定性投影，`quality B`）。AgentDojo 错误 `P1 tool_result / get_injection_vector_defaults` 已从 core 删除（含 dead code 清理），仅可作为 Extended track 另起 `agentdojo_extended.py`。
- **清单与套件已冻结 v2**：`manifest v3.2`（无 `created_at`，真 `read_bytes` 一致）、`split-v2`（case-weighted）、`strata` 与 `max_cluster_share 0.01` 真实生效、suite 已绑定 `manifest_sha256` 且新增 `manifest suite-verify`。
- **默认小规模已可用，内存合规**：`BoundedHashSelector` 为真 `O(K)`（仅 `heap + heap_ids`，无 `O(N) _seen`），百万级已测 `1_000_000 offers -> heap 10 / heap_ids 10`；`verify_normalized` 为逐条 `validate_provenance` 真 streaming；`--full` 已改为 `--full-source` 证据模式且禁用 `O(N2) near-dup`。
- **旧 v1 保留为 superseded**：`benchmarks/manifests/*-v1` 与 `suites/*-v1` 保留不覆盖，当前报告为 `56948f8`，本轮 final fix 后进入冻结。

---

## 2. 数据与锁

```text
datasets.yaml
  llmail:   huggingface_dataset microsoft/llmail-inject-challenge 1063bdf01ec8... MIT 1.1.0 quality A
  agentdojo: github ethz-spylab/agentdojo 089ed468cf3e... v1 1.1.0 quality B
locks
  llmail   a223abaf159d...  1.1.0
  agentdojo 57726b746c7d... 1.1.0
```

| 数据集 | 归一化（默认 bounded） | 通道/说明 |
|--------|------------------------|-----------|
| LLMail | `3860 = 3700 attack (phase1 3145 / phase2 555, BoundedHashSelector) + 160 benign` | `email`，`near_dup 2679 clusters` |
| AgentDojo | `952 tool_call`（`exact 153` 去重） | `P2 tool_call only`，`quality B`，`group_id=parent_source_id` |

全量证据：`--full-source` 产 `148K` 时仅 `exact+normalized`、`near_dup status=not_computed`，不走 `O(N2)`，且 `manifest build` 会拒绝 full-source 证据池。

---

## 3. 清单与套件取证（2026-08-19 rebuilt）

```text
OK: llmail normalized 3860  / agentdojo 952  (streaming verify)
OK: benchmarks/manifests/smoke-v2/p1.json              n=120  sha256:da9f7... (dev, 80+40)
OK: benchmarks/manifests/phase1-standard-v2/p1.json    n=1674 sha256:dc93d... (eval, 1580+94)
OK: benchmarks/manifests/phase1-full-v2/p1.json        n=2683 sha256:56ebb... (eval+holdout, 2563+120)
OK: benchmarks/manifests/holdout-v2/p1.json            n=526  sha256:1a02d... (holdout, 500+26)
OK: suite-verify smoke-v2 / standard-v2 / full-v2 / holdout-v2  all OK
```

| 套件 | 总数 | P1 | P2 |
|------|------|----|----|
| `smoke-v2` | `220` | `120 (dev 80+40)` | `100 (dev)` |
| `phase1-standard-v2` | `2214` | `1674 (eval 1580+94)` | `540` |
| `phase1-full-v2` | `3444` | `2683 (eval+holdout 2563+120)` | `761` |
| `holdout-v2` | `676` | `526` | `150` |

> target 已对齐 actual（`smoke 120 / standard 1674 / full 2683+761`），`llmail.yaml / agentdojo.yaml` 的重复 `suite_targets` 已删除，`suites.yaml` 为唯一配额来源。

`manifest_version v3.2 / hash_rank_v1 + split-v2 / seed 42 / strata+cap` 均在清单内可验证；`created_from` 含 `revision + raw_sha256 + adapter/adapter_version + benchmark_version`。

---

## 4. 测试与验证

```text
PYTHONPATH=src pytest tests/v3 -q    # 全部通过（含新增 BoundedHashSelector 1M 测试）
PYTHONPATH=src pytest tests/ -q      # 全量通过
```

---

## 5. 关键命令

```bash
PYTHONPATH=src python -m demotest.cli.main dataset verify-source --dataset llmail
PYTHONPATH=src python -m demotest.cli.main dataset prepare --dataset llmail          # bounded 3860 ~13M
PYTHONPATH=src python -m demotest.cli.main dataset prepare --dataset llmail --full-source  # 148K evidence, no O(N2)
PYTHONPATH=src python -m demotest.cli.main dataset prepare --dataset agentdojo       # 952 B
PYTHONPATH=src python -m demotest.cli.main dataset verify --dataset llmail
PYTHONPATH=src python -m demotest.cli.main manifest suite-verify phase1-standard-v2
```

---

## 6. 归档

- 旧报告：`docs/archive/PHASE1_STATUS_56948f8.md`
- 本报告为 final fix 后唯一现状说明。
