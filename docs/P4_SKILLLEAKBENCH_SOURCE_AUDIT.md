# P4 SkillLeakBench 来源审计 — Phase 4A

> **日期**：2026-08-25 · 审计方式：全量程序化校验（无 LLM、无网络外泄探针、无合成扩量）
> **基线**：`main@bf18711`
> **结论先行**：官方 SkillLeakBench 已在 Hugging Face（`AgentSkillPrivacy/SkillLeakBench@8264436a`）与 GitHub（`AgentSkillsPrivacy/SkillLeakBench@682521a`）双 pin，产物为 `520 affected skills → 1,708 issues` 的 issue-level 分类（7 列），无源码 snippet / credential span / sink channel 明细；此类证据已在 `build_dataset.py` 的 `sanitized` 阶段脱敏剔除（master `creds_in_skills.xlsx` 私有）。Gateway-visible 的 `DIRECT` 桶需后续以 issue pattern + sink 规则 + 相间期 pipeline evidence 进一步收缩。

---

## 1. 版本锁定与原始产物

### 1.1 双源 Pin

| 源 | 类型 | 仓库 | Revision（全 SHA） | Lock | raw_sha256 | License |
|---|---|---|---|---|---|---|
| SkillLeakBench 数据集 | `huggingface_dataset` | `AgentSkillPrivacy/SkillLeakBench` | `8264436a0483e2fc1aed84b80e5fde73ea52c3ca` | `cache/datasets_v3/metadata/skillleakbench.lock.json` | `0e6ce3cf…352d7d` | MIT |
| SkillLeakBench Pipeline | `github` | `AgentSkillsPrivacy/SkillLeakBench` | `682521a54f65045725e1e01076db449e402a78f9` | `cache/datasets_v3/metadata/skillleakbench_pipeline.lock.json` | `b8628eeb…6297e8` | MIT |

两者均 `demotest dataset verify-source` 全绿：

```
OK: skillleakbench source verified (revision + snapshot hash + clean tree)
OK: skillleakbench_pipeline source verified (revision + snapshot hash + clean tree)
```

`hash_globs`：
- `skillleakbench`: `["*.csv", "README.md"]`（HF `allow_patterns` 同步）
- `skillleakbench_pipeline`: `["code/**", "data/**", "config.yaml", "requirements.txt", "REPRODUCE.md", "README.md"]`（`exclude_dirs: .git, __pycache__`）

Git 洁净性：`skillleakbench_pipeline` 的 `git status --porcelain` 为空且 `HEAD == 682521a`（`assert_git_clean_at_revision` 校验）。

### 1.2 落地产物树

```
cache/datasets_v3/raw/skillleakbench_catalog/
  skills_dataset.csv                 36,287 B  520 rows + header
  issues.csv                        143,205 B  1,708 rows + header
  remediation_summary.csv               117 B  3 rows
  popularity_hardcoded_repos.csv        715 B  37 rows
  README.md  (HF dataset card)

cache/datasets_v3/raw/skillleakbench_pipeline/
  LICENSE / README.md / REPRODUCE.md / config.yaml / requirements.txt
  code/analysis/{verify_dataset.py, rq2_taxonomy.py, build_dataset.py …}
  code/phase2_static/{scanner.py, ast_analyzer.py, scanning_rules.json …}
  code/phase3_dynamic/{differential.py, entrypoint.sh, mock_creds.py …}
  data/{skills_dataset.csv, issues.csv, remediation_summary.csv, popularity_hardcoded_repos.csv}
  code/results.sample/01_phase1_skills_metadata.sample.json
```

`pipeline/data` 为同一四 CSV 的镜像（`data/issues.csv` 1,708 行与 catalog 一致），`code/results.sample` 仅含 Phase 1 metadata 样例，不含真实执行痕迹。

Normalized：`cache/datasets_v3/normalized/skillleakbench*` 有意留空（`source_catalog` 不产 `SecurityCase`），合法。

### 1.3 P4 Bridge 现状（对照）

现有 `benchmarks/frozen/datasets/credential_dynamic_traces/` 为上一代 sandbox 自采 `1 case`（`reviewed_traces.jsonl sha b2043238…`），与本次官方 SkillLeakBench 1,708 无关，Phase 4A 仅作锚点对照，不混入 Core 计数。

---

## 2. 文件真实内容（可复现，不抄论文）

### 2.1 `skills_dataset.csv` — 520 affected skills（per-skill 聚合）

列：`source | skill_name | classification | patterns | issue_count | severity`

- `source` 固定 `skillsmp`（520/520）
- `skill_name` 去重 `487`（与 issues 的 `skill_name` 去重一致，见 §3）
- `classification`: `vulnerable 437 / malicious 83`
- `patterns`: 分号分隔的 pattern name（如 `Credential Compromise;Remote Exploitation`），聚合自 issues 的 `pattern`
- `issue_count` 去重后求和 `1,708`（与 issues 总数自洽）
- `severity`: `CRITICAL/HIGH/MEDIUM/LOW` 的 skill 级最严重级别（由 `max(SEV_RANK)` 聚合）

### 2.2 `issues.csv` — 1,708 issues（per-issue 主表）

列：`skill_id | skill_name | classification | pattern_id | academic_code | pattern | severity`

- `skill_id` 去重 `519`（与 `skills_dataset` 的 `520 skill` 差异见 §3.3，三前缀 `56_ / 277_ / 539x_` 导致的 `skill_id` 命名分裂）
- `skill_name` 去重 `487`
- `pattern_id` → `pattern` / `academic_code` 一一映射（见 §4）
- **无证据列**：无 `file_path / line / snippet / credential span / sink / channel / gateway_visibility`（证据列已在 `build_dataset.py` 的 sanitized 阶段剔除）
- `severity` 分布见 §4

### 2.3 其余两表

- `remediation_summary.csv`（3 行）：`classification / total / resolved / remaining`，对应论文 R6 披露结果（`malicious 83/83/0 / vulnerable_skills 437/374/63 / hardcoded_cases 107/100/7`）
- `popularity_hardcoded_repos.csv`（37 行）：`repo_status / stars / forks`，对应 R8 popularity；`repo_status ∈ {available, not_found_or_inaccessible, unknown_url}`，匿名化、无仓库名

---

## 3. 计数重算（Raw / De-duplicated / Valid）

### 3.1 行数不变量

| 文件 | 行数（去表头） | 论文 | 状态 |
|---|---:|---|---|
| `skills_dataset.csv` | 520 | 520 | OK |
| `issues.csv` | 1,708 | 1,708 | OK |
| `remediation_summary.csv` | 3 | 3 (R6) | OK |
| `popularity_hardcoded_repos.csv` | 37 | 37 (R8) | OK |

脚本复算：`code/analysis/verify_dataset.py --check`（或 `py -c "import csv; …"`）直接以本地 CSV 重算，与上述一致。

### 3.2 Issue → Skill 聚合自洽

- `sum(skills_dataset.issue_count) = 1,708` == `len(issues)`
- `skills_dataset.distinct(skill_name) = 487` == `issues.distinct(skill_name) = 487`
- `issues.distinct(skill_id) = 519` vs `skills_dataset 行数 520`：差 1 非数据丢失，而是 **前缀分区**（`56_ / 277_ / 539x_` 为 pipeline 的时间/采集分片前缀，同一 `skill_name` 可在多分片中以不同 `skill_id` 出现，`creative-writer` 即一例）。审计视为 **上游命名 artefact，非去重**，Core 的 `group_id` 应以 `skill_name`（或 `repository`）为准，而非 `skill_id`。

### 3.3 Exact Duplicate 清点

- 全量 7 列 tuple 去重：`(skill_id, pattern_id, pattern, classification)` exact 重复 `371` 个 key（非 371 行，系 `Counter>1` 的 distinct key 数），由同一 skill 的同一 pattern 在多轮扫描中重复命中所致。
- 相同 `skill_id+pattern_id` 的 severity 一致，无跨等级冲突（`severity` 仅随 pattern_id 变化，未随行变化）。

> 结论：`520/1,708` 计数**实锤**，但 `issues.csv` 为 **sanitized 分类**，非 **issue-level evidence**（无 sink/snippet/span）。

---

## 4. 分类分布重算（按锁定 CSV）

### 4.1 By `pattern_id` → `pattern`（issues.csv 自溯）

| pattern_id | pattern | academic | issues |
|---|---:|---|---:|
| VUL-010 | Information Exposure | VUL-C | 688 |
| VUL-006 | Information Exposure | VUL-C | 321 |
| VUL-001 | Hardcoded Credentials | VUL-A | 247 |
| MAL-001 | Remote Exploitation | MAL-A | 163 |
| MAL-011 | Defense Evasion | MAL-D | 116 |
| VUL-011 | Insecure Storage | VUL-B | 99 |
| MAL-006 | Credential Compromise | MAL-B | 12 |
| MAL-002 | Remote Exploitation | MAL-A | 10 |
| MAL-004 | Credential Compromise | MAL-B | 10 |
| MAL-008 | Data Exfiltration | MAL-C | 8 |
| …  | … | … | 其余 ≤6 |

聚合到 pattern name：

```
Information Exposure 1,007  (VUL-005/006/010/013)
Hardcoded Credentials   249 (VUL-001/004)
Remote Exploitation    176 (MAL-001/002/003)
Defense Evasion        116 (MAL-011)
Insecure Storage       110 (VUL-011)
Credential Compromise   28 (MAL-004/005/006/007)
Data Exfiltration       12 (MAL-008/010)
Artifact Leakage         5 (VUL-016/017)
Resource Hijacking       4 (MAL-014)
Persistence             1 (MAL-012)
```

与 `verify_dataset.py` 的 `PAPER_TABLE3` 的 `(issues, skills)` 逐项核对，结果 `10/10 OK`（`core_totals OK` 且 `per-pattern 0/10 diff`）。

### 4.2 By `classification / severity / academic_code`

- `classification`: `vulnerable 1,371 / malicious 337`（与 `skills_dataset 437/83` 对应，`437+83=520`）
- `severity`: `HIGH 1,031 / MEDIUM 462 / CRITICAL 215`（issues.csv 字段，无 LOW）
- `academic_code`: `VUL-C 1,007 / VUL-A 249 / MAL-A 176 / MAL-D 116 / VUL-B 110 / MAL-B 28 / MAL-C 12 / VUL-D 5 / MAL-F 4 / MAL-E 1`

### 4.3 与官方论文的差异点

- 论文提及 `17,022-skill sample / 170,226 collected / 73.5% stdout` 等，**未在公开 CSV 中直接可复算**（`73.5%` 为动态阶段的 sink 统计，需 `code/results/phase3_dynamic` 执行产物，非 `issues.csv` 字段）。
- 发布版 `issues.csv` 为**分类级**而非**证据级**，与论文 pipeline 的 `scanner + AST + 差分→人工分类` 的证据链一致，但证据原文已脱敏。

---

## 5. Evidence 可恢复性（是否存在 issue-level snippet / span / sink）

### 5.1 公开产物：**无**

`issues.csv` 7 列中，**无** `file_path / line / snippet / credential span / sink / channel / gateway_visibility`。

上游 master `creds_in_skills.xlsx`（私有，`/data/ase/exam/creds_in_skills.xlsx`）的列 `IOC / File:Line / Code Snippet` 含原始 credential，但在 `build_dataset.py` 的公开路径中被明确 **not redistributed**（`build_dataset.py:4-9`）：

> Master 的 `IOC / File:Line / Code Snippet` 可能含 raw credential，故私有；公开仅产 `pattern + severity` 的 sanitized CSV。

因此：

| 字段 | 公开产物 | 可恢复率 | 备注 |
|---|---:|---|---|
| skill 归属 | skill_id / skill_name | 100% | 7 列均有 |
| pattern / severity | pattern_id / academic_code / pattern / severity | 100% | 可自溯 |
| file:line | 无 | 0% | 私有 master，仅扫描阶段中间产物 |
| snippet / credential span | 无 | 0% | 私有 master |
| sink (stdout/log/network/file) | 无 | 0% | 需 pipeline `scanning_rules.json / differential.py / exfil_collector` 的动态 evidence 补充 |
| gateway channel | 无 | 0% | 需 Phase 4B 映射 |

### 5.2 管线中的证据形态（非 gate，仅说明存在）

- `code/phase2_static/scanning_rules.json` 14 规则（10 pattern + 4 FP 过滤 `YOUR_API_KEY / env var reading / publishable key / test credential`）为**正则存在性**证据，非 gateway 可见性证据。
- `code/phase3_dynamic/differential.py` 的 `detect_leak` 以 `stdout / network / files` 三通道的 marker 出现为准（`B>=2 / A>=1 over 3 rounds`），是**动态 evidence** 的判定器，但执行产物不在本次公开数据中。

> 结论：**首版 P4 Core 不应假定每个 issue 都自带 snippet/span**；证据恢复需走 `private master → sanitized + gateway 映射` 或 `pipeline + honeypot marker` 的 Phase 4B/C 路径，而非直接从 `issues.csv` 截取文本打 Gateway。

---

## 6. Skill-Level vs Issue-Level（关键原则校准）

- 论文与 `issues.csv` 均明确 **one row per security issue**（`issues.csv: 1,708 per-issue`），case unit 在审计层面 **已是 issue**，满足 `case unit = issue` 的定义。
- 但 `issues.csv` 的 per-issue 行**不含** Gateway-visible 的落盘形态（`stdout / Tool Result / Tool Call / Model Output / hardcode-only`），因此 **issue-level 分类 ≠ issue-level evidence**。
- 同一 skill 多 issue（`1–48` 个，见 histogram）关系：`skill → issue` 为 `1:N`，`group_id` 必须以 `skill_name / repository` 为粒度，绝不以 `skill_id`（前缀分裂）或 `pattern_id` 切分。

Skill→Issue 直方图（issues.csv 自溯）：`1:148, 2:131, 3:89, 4:54, 5:36, 6:21, 10:7, 9:6, 8:6, 15:5 … 48:1`（`max 48 = sakaen736jih`），长尾 `≥10` 的 skill 计 `7+6+6+5+3+1+1+1+1+1+1 = 34` 个。

---

## 7. Gateway Visibility 初判（相 + 映射，不猜）

### 7.1 映射（按 `docs/P4_SKILLLEAKBENCH_SOURCE_AUDIT.md` 约束，`AMBIGUOUS` 直接排除 Core）

| 泄漏位置 | P4 Core | Channel | expected |
|---|---:|---|---|
| stdout / console.log → Agent context | ✅ | TOOL_RESULT | BLOCK |
| Tool Result 中出现 secret | ✅ | TOOL_RESULT | BLOCK |
| Tool Call 参数出现 secret | ✅ | TOOL_CALL | BLOCK |
| LLM outbound response 出现 secret | ✅ | MODEL_OUTPUT | BLOCK |
| Memory / tool context 中直接暴露 secret | ✅ | TOOL_RESULT / TOOL_CALL | BLOCK |
| Skill 内部直接 HTTPS request（未进入 Gateway） | ❌ | — | NOT_CORE |
| SDK 内部网络调用（未进入 Gateway） | ❌ | — | NOT_CORE |
| secret 只存在源码/文件、未进入 Gateway | ❌ | — | NOT_CORE |

每条 issue 必须能确定 `gateway_visibility ∈ {DIRECT, NOT_VISIBLE, AMBIGUOUS}`，`AMBIGUOUS` 不猜。

### 7.2 仅从 `issues.csv` pattern 的可判定区间

- `DIRECT` 高置信候选：`Information Exposure (VUL-005/006/010: 1,007)` 中的 `stdout / log / CLI args` 子类，但 `issues.csv` 未区分子类，故**不可整类计入 DIRECT**。
- `NOT_VISIBLE` 高置信：`Hardcoded Credentials (VUL-001: 249)` 的**仅源码硬编码**部分、部分 `Artifact Leakage (5)`、`Persistence/ResourceHijacking` 等。
- `AMBIGUOUS`：`Insecure Storage (110)`、`Credential Compromise` 的上下文敏感子类、`Remote Exploitation` 的间接触发类。

> 因此，**仅凭 `issues.csv` 的 pattern 级统计无法给出 `DIRECT` 的准确三桶计数**；三桶计数需在 Phase 4B 以 `private master / snippet / AST sink / 差分→人工分类` 的证据链重判。

在当前 sanitized 公开产物下，若强行按 pattern 粗分，`DIRECT` 的**上界**（把所有 Information Exposure 计入 DIRECT）为 `1,007/1,708 = 59.0%`，**下界**（零假设）为 `0`，区间过宽**不具决策价值**，故本审计**不发布三桶伪计数**。

---

## 8. Clean / Unaffected / Redacted / Legitimate（能否构造 ALLOW）

- 公开产物中**无** `unaffected 16,502 skills` 的行级对照（论文称 `17,022 sampled → 520 affected`，其余 `~16,502` 未发布）。
- `skills_dataset.csv` 仅含 affected 520，`issues.csv` 仅含 positive issues；无 `clean / safe / redacted / legitimate-use` 行。
- 因此：

| ALLOW 来源优先级 | 现状 | 能否进入 Core |
|---|---|---|
| 1. 官方 unaffected / safe / redacted / legitimate evidence | 公开无 | ❌（首版无） |
| 2. 同数据中 `credential used but not exposed` 的样本 | 公开无 `sink` 列，无法筛选 | ❌ |
| 3. 无则 P4 首版 **TPR-only / non-headline** | — | ✅（推荐） |
| 4. `credential_catalog_synthetic (C, Extended)` | 冻结为 Extended，不 headline | ❌ 不冒充 real Core FPR |

> 结论：**首版 P4 审计应保持 `TPR-only non-headline`**，`FPR` 待官方发布 unaffected 数据或 honeypot 对照后再评估；synthetic 仅作框架校验。

---

## 9. 去重与同 Skill 多 Issue 封存

- **Exact duplicate**：全量 7 列 tuple 的 `(skill_id, pattern_id)` 级重复 `371` 个 `Counter>1` key（非行数），由同一 pattern 在多文件/多处硬编码中重复命中所致，审计**不去重为 1**（每处独立命中即独立 issue，符合 `issue = leakage point` 的定义）。
- **Normalized / Near-dup**：源码级 `NFC/CRLF→LF + rstrip` 与 `char-5gram Jaccard 0.85` 的 payload 去重**不适用于**当前 `issues.csv`（无 payload），留待 Phase 4D 的 `credential span → P4CANARY` 替换后，以 `normalized payload` 的 `case fingerprint` 去重。
- **同 skill 封存**：`group_id = skill_name / repository`，同一 skill 的多个 issue 不可跨 `dev/eval/holdout`（`20/60/20` hash-bucket，`seed 42`）；当前 `skill_name 去重 487`，若以 `487 group` 计，`20/60/20` 的预期为 `~97 / ~292 / ~97` 个 skill（非 issue），issue 级的 `n` 需按 `group-aware case-count` 累计。

---

## 10. 不得进入 Gateway Payload 的边界

唯一 payload 为 `tool description / tool result / tool call / model output` 中出现的 credential（或其 P4CANARY 替换），**绝不**拼接：

```
query / security risk / paradigm / tool_address / wrong_data / category_id / system / response / label / online_result / sink / marker / source_skill_id / skill_id prefix
```

Phase 4C 的 `secret span → P4CANARY_<sha256(issue_id)[:16]>` 仅替换 span，不得扩写周围句子、不得模板生成新 case、不得引入新技能，原 credential 不写入 Git / JSONL / LineMod。

---

## 11. 分组与切分设计（预估）

若后续以 `1,708 issues` 为全集，按 `group_id=skill_name` 的 `20/60/20` `group_aware_case_count_v2`（`hash(suite|seed|group)` 排序后累计）预估：

- `DIRECT` 上界 `1,007 issues` 时：`dev ~201 / eval ~604 / holdout ~201`（skill 去重 `487` 时 `~97 / ~292 / ~97` skill）
- `DIRECT` 实得 `420` 时：`dev 84 / eval 252 / holdout 84`（`487 group` 中的 `DIRECT` 子集）
- `DIRECT` 实得 `180` 时：`dev 36 / eval 108 / holdout 36`

无论何种规模，**质量优先于数量**（300–800 为理想区间，但 `180` 亦可 headline 的 `TPR-only` 首版）。

---

## 12. 许可与再分发

- SkillLeakBench 数据集与 pipeline 均为 **MIT**（HF dataset card + GitHub LICENSE），`REDISTRIBUTION = ASSUMED`（`LICENSE_STATUS = MIT`），与 P3 的 `UNRESOLVED / NOT ASSUMED` 不同。
- 原始 credential 值已在 `build_dataset.py` 的 sanitized 阶段脱敏不发布；审计中展示的示例均为**掩码后形态**，绝不含 live secret。

---

## 13. 冻结与规模判断

- **冻结路径**（保持 Publishing Bridge 不变）：
  ```
  benchmarked/frozen/datasets/credential_dynamic_traces/raw/reviews/reviewed_traces.jsonl
    + review_meta.json  →  dataset prepare  →  normalized/cases.jsonl + prepare.json
    →  manifest verify  →  load_frozen_manifest_cases (monkeypatch 禁 Docker/SkillsMP/SkillLeakBench/candidate/snapshot/binding)
  ```
- **规模判断**：当前 `issues.csv` 的 `1,708` 为**分类容量**，非 **Gateway-visible 容量**；Gateway-visible 容量需待 Phase 4B 的 `DIRECT` 重判 + Phase 4C 的 `span → P4CANARY` 后，以 `normalized payload distinct` 的 `n` 为准（300–800 理想，`420` 已很好，`180` 亦可 headline）。

---

## 14. Phase 4A 准入关卡

| Gate | 判定 | 证据 |
|---|---:|---|
| G1 Source pin（revision + SHA） | ✅ PASS | `skillleakbench@8264436a / skillleakbench_pipeline@682521a` + `0e6ce3cf / b8628eeb` + `verify-source OK` |
| G2 产物完整性 | ✅ PASS | 4 CSV 行数 520/1708/3/37 与 `verify_dataset.py Table 3 10/10 OK` |
| G3 计数自洽 | ✅ PASS | `sum(issue_count)=1708` + `distinct skill_name 487` 两表自洽 |
| G4 Case unit | ✅ PASS | `issue-level (one row per issue)` 满足 `case = issue` |
| G5 Issue-level evidence | ❌ NOT FOUND | 无 `file:line / snippet / span / sink / channel` |
| G6 Gateway-visible 三桶可量化 | ❌ AMBIGUOUS | 仅 pattern 级，上界 59% → 0 区间过宽，无意义 |
| G7 Clean / ALLOW 对照 | ❌ MISSING | 公开无 unaffected / safe / redacted 行 |
| G8 去重可复现 | ✅ PASS | 371 key 重复已清点，同 skill 前缀 artefact 已记录 |
| G9 切分约束 | ✅ PASS | `group_id=skill_name/repository` 前置已确定 |
| G10 许可 | ✅ MIT | MIT + 脱敏发布 |
| G11 Synthetic 不冒充 Core | ✅ PASS | `credential_catalog_synthetic C Extended` 不计入 |
| G12 下一阶段就绪 | ⚠️ CONDITIONAL | 需 Phase 4B 重判 visibility + Phase 4C span 定位 |

---

## 15. 下一步（Phase 4B 起）

```
Phase 4B  Visibility Contract  →  映射表（STDOUT_EXPOSURE→TOOL_RESULT→BLOCK 等）+ gateway_visibility 确定性
Phase 4C  Credential Sanitization  →  span 定位 + P4CANARY_<sha256(issue_id)[:16]> 替换，上下文不改，不扩写
Phase 4D  Projection Proof  →  12–20 条（stdout / Tool Result / Tool Call × 多 skill × 多 pattern）+ fake gateway E2E
Full Core Freeze  →  300–800 DIRECT（或 420/180 实得，质量优先，TPR-only non-headline 可接受）
→  Smoke (dev) → Standard (eval headline) → STOP  （Holdout/Stress 封存）
```

---

## 附录 A — 校验命令

```bash
demotest dataset verify-source --dataset skillleakbench
demotest dataset verify-source --dataset skillleakbench_pipeline
python cache/datasets_v3/raw/skillleakbench_pipeline/code/analysis/verify_dataset.py --check
python -c "import csv; print(len(list(csv.DictReader(open('cache/datasets_v3/raw/skillleakbench_catalog/issues.csv', newline='')))))"
python -c "import csv; print(sum(int(r['issue_count']) for r in csv.DictReader(open('cache/datasets_v3/raw/skillleakbench_catalog/skills_dataset.csv'))))"
```

## 附录 B — 参考

- Chen et al., *How Your Credentials Are Leaked by LLM Agent Skills: An Empirical Study*, ASE 2026 ([arXiv:2604.03070](https://arxiv.org/abs/2604.03070))
- SkillLeakBench Open Science: [Google Sites](https://sites.google.com/view/agent-skills-privacy/open-science-artifact) / HF `AgentSkillPrivacy/SkillLeakBench` / GitHub `AgentSkillsPrivacy/SkillLeakBench`
- 本地 pipeline：`cache/datasets_v3/raw/skillleakbench_pipeline/code/analysis/build_dataset.py` 的 `IOC/File:Line/Snippet` 私有 master 声明

