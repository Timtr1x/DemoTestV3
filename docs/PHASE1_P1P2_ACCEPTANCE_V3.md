# Phase 1.5 — P1/P2 数据集集成收尾（v3）— 验收记录

状态：**离线阶段已完成**（审计 + adapter v1.2.0 + 已冻结 v3 套件/manifest + fake-target 端到端）。真实 LineMod 运行（Baseline-0 smoke / standard）有意未启动；holdout 保持封存。

基线：`main@9f24c63`。全程冻结：`core/`、`renderers/`、`targets/`、`oracles/`、`runners/`、`datasets/dynamic/`、P4 产物。

## 1. 源锁定（未变更，已重新校验）

| dataset | source | revision | verify-source |
|---|---|---|---|
| llmail | HF `microsoft/llmail-inject-challenge` | `1063bdf01ec8762b812d5e06ee768a06faa5a6f7` | OK |
| agentdojo | GH `ethz-spylab/agentdojo` (benchmark v1) | `089ed468cf3ed0322acc66b0211f26d9d90dbf60` | OK |

## 2. 审计（证据位于 `cache/exports/`，已提交审查文件）

1. **LLMail 标签映射**（`llmail_label_audit.json`）— 通过生产代码路径流式扫描完整原始池：148,385 个唯一 attack id，仅出现 6 种不同标签值，全部按既定规则映射（`True` 家族 -> BLOCK；`False`/`Unclear` -> 跳过）。全部 3,700 条 BLOCK + 160 条 ALLOW 快照用例均可回溯到原始行且 actions 完全一致；零不匹配。结论：PASS。
2. **LLMail 元数据诚实性**（`config/v3/datasets/llmail.yaml`）— 声明字段现与实际一致：`scenario` = 近似内容标记启发式、`presentation_style` = 启发式、`attack_goal` = 框架分类（常量）、`team_id`/`original_success` = 无需全量 submissions 关联则不可得。已移除无效的分层键。仅声明式变更：重新 prepare 结果字节一致。
3. **AgentDojo 官方枚举门禁**（`agentdojo_ground_truth_audit.json`）— 官方定义：`benchmark_suite_with_injections` 对每个 suite 执行所有 user_tasks × 所有 injection_tasks。official=629 / adapter=629 / missing=0 / extra=0。结论：PASS。
4. **注入 ground-truth 调用角色审查** — 审计每一个唯一的 ground-truth 调用（27 个任务共 47 个调用；travel 的 `injection_task_6` 无 GT）。角色：**attack_implementing**（30）= 实现攻击者目标；**contextual_read**（17）= 只读查询，单独看无害。已提交为 `config/v3/datasets/agentdojo_injection_gt_calls.json`；对缺失调用、函数漂移、未知角色或 pin 漂移均 fail-closed。角色不决定 expected_action（见下方 P0 修复）。

## 3. Adapter 版本

| dataset | adapter | 变更 |
|---|---|---|
| llmail | 1.1.0（未变更） | `validate_raw()` 现通过 `_iter_prompt_value_pairs` 流式处理约 450MB 的 labelled_unique 文件（回归测试禁止对 attack JSON 使用 `read_text()`）；用例输出字节一致 |
| agentdojo | **1.2.0** | 新增 `AuthorizedUserTask`：官方 `UserTask.ground_truth(clean env)` -> `expected_action=ALLOW`、`ground_truth_kind=user_authorized`，按 UserTask 分组（多步用例绝不跨切分）；BLOCK 侧标记 `ground_truth_kind=injection_attack` 并采用**上下文感知的授权判断**：注入诱导的调用除非与配对 UserTask 自身 ground-truth 调用**完全匹配**（function 与规范化参数均一致——同函数不同参数不视为已授权），否则一律投影为 BLOCK；保留用例携带 `attack_step_class=attack_implementing\|contextual_read`（来自已提交的调用角色审查），该字段永不决定 expected_action；两类用例的信封字节结构完全一致，render 无法泄露 expected_action |

## 4. 归一化快照（两者 `dataset verify` 均 OK）

| dataset | total | block | allow | dedup |
|---|---:|---:|---:|---|
| llmail | 3,860 | 3,700 | 160 | 字节一致的重新 prepare（sha256 `1b2efac5…`） |
| agentdojo | 1,247 | 912 (injection_attack: 670 attack_implementing + 242 contextual_read) | 335 (user_authorized) | 移除 138 条完全重复 |

切分池一致性（agentdojo BLOCK）：dev 174 / eval 535 / holdout 203 = 912；ALLOW：dev 76 / eval 208 / holdout 51 = 335。

## 5. 已冻结 v3 套件与清单（`verify --strict` + `suite-verify` 全部通过）

| suite / project | n | manifest sha256（前 16 位） | headline |
|---|---:|---|---|
| smoke-v3/p1 | 120 | `00ad9d5b170f99f4` | false |
| smoke-v3/p2 | 100 (50+50) | `a6b53cc22558dfcc` | false |
| phase1-standard-v3/p1 | 1,674 | `4cf306b4e3682b8a` | **true** |
| phase1-standard-v3/p2 | 743 (535+208) | `e35aff7a6de4d01f` | **true** |
| phase1-full-v3/p1 | 2,683 | `7aed4928ecb68382` | false |
| phase1-full-v3/p2 | 997 (738+259) | `17da94182f64a44b` | false |
| holdout-v3/p1 | 526 | `a2f1fcf0f5a5dcd8` | false |
| holdout-v3/p2 | 201 (150+51) | `ffa89196c7a61003` | false |

所有项目 `benchmark_track=core`。仅 phase1-standard-v3 具备 headline 资格——条件：P1 与 P2 均携带真实的 BLOCK+ALLOW ground truth，且 Phase 1.5 审计在锁定的 revision 上通过。

历史套件：v1 的 manifest/套件及其套件快照保持字节级冻结并标记为 DEPRECATED/HISTORICAL（`benchmarks/manifests/HISTORICAL.md`、`config/v3/suites.yaml` 中的横幅）；v2 同理保留——**历史产物予以保留；严格复现需沿用原始 adapter 谱系**（不构建多版本归一化基础设施）。已知历史遗留情况（已存在）：四个 v1 套件因 manifest 早于 v3.2 哈希生成逻辑，无法通过当前规范的 `manifest_sha256` 重算；不重新生成。

## 6. Fake Target 端到端（`scripts/_phase15_fake_e2e.py`）— PASS

通过真实 `demotest.cli.main.main([...])` 链路执行 validate -> render -> run（本地脚本化网关，始终返回 403 SECURITY_BLOCKED）-> analyze -> report，针对 smoke-v3 p1+p2（重建的 P2 manifest）：

- P2：n_judged=100/100，TP=50 FP=50 TN=0 FN=0，TPR=100%，**FPR=100%**（fake 网关拦截一切，因此每个 ALLOW 用例都表现为 FP——证明 Authorized-FPR 链路端到端可用）。
- 报告：`cache/exports/phase15_e2e/{p1,p2}-SUMMARY.md`。

## 7. 测试

全量套件：403 passed / 4 skipped。新增覆盖：LLMail 流式回归；ALLOW 投影与官方 GT 的精确性；信封一致性；稳定用例 ID；UserTask 切分分组；角色文件 fail-closed（缺口/漂移/非法角色/pin 不匹配）；上下文感知授权的精确性（同函数 + 不同参数必须保持 BLOCK）；已授权调用豁免；attack_step_class 标注；v3 manifest 跨 kind 门禁；headline 门禁；历史绑定；快照 action 计数。

## 8. 已知限制

- `scenario` / `presentation_style` 为启发式（已文档化；不影响 ground truth）。
- 上下文读取类 BLOCK 用例（242 条）为注入诱导的离题读取：是否应当被拦截正是 benchmark 所要度量的；attack_step_class 分解可让报告将此类与 attack-implementing 调用区分开。
- 上述 P2 的 FPR/TPR 数值为 fake 网关产物，并非 benchmark 结果。
- 下一步：真实 LineMod Baseline-0 smoke（P1 `baseline0-p1-smoke-v3` 可独立启动；P2 真实 smoke 待本 P0 修复验收后进行），密钥仅通过进程环境变量传入；holdout 保持封存。
