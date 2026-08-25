# P3 MCPTox Clean 重建审计 — Phase 3C0

日期：2026-08-25 · revision `f85189f9ad12504c197c7f920ab818a40657b1fa` · probe `cache/probe/mcptox`
前置要求：核心 headline 不得发布基于解析器行为计算的 FPR。
前置文档：`docs/P3_MCPTox_SOURCE_AUDIT.md`（Phase 3A）与 `docs/P3_MCPTox_PROJECTION_PROOF.md`（Phase 3B 攻击证明）。

## 判定

- **Core BLOCK** 为 `pure_tool.json` 的 485 条 canonical 定义，`def_tool/1.py … 485.py`，已在 Phase 3B 中证明。
- **Core ALLOW** 并非“约 352”。而是从 `response_all.json` 的 `servers[*].clean_system_promot` 严格解析出的 **309 条高置信度 clean 定义**，附带精确的源区间与 prompt SHA。剩余约 43 个块以 `CLEAN_PARSE_AMBIGUOUS` 排除。
- `response_all.json` 中 valid 的 1,312 条仍作为 **Extended/Stress（仅攻击，去重后约 1,302 条 distinct）** 保留，不作为 headline。

禁止回填或改写 benign 定义。每个 ALLOW 必须可追溯至 `response_all.json → server.clean_system_promot → 精确字节区间`。

## Clean 来源

仅 `response_all.json:servers[*].clean_system_promot`。

```
clean_system_promot: 列出该 server 合法工具的完整渲染 prompt
  Tool: <name>
  Description: <text>
  Arguments:
    - ...
```

另以 `tool_names` 作为一致性校验，绝不作为唯一生成源。

`pure_tool.json` 不存在 clean 对应物。`def_tool` 也不存在 clean 对应物。

## 解析器契约（严格、fail-closed）

正则 `Tool:\s*([^\n]+?)\s*\nDescription:\s*(.*?)\nArguments:`，使用 `DOTALL`。

单个块（per-block）接受条件：

- `name` 与 `description` 均非空；`description` 不为字面量 `None`
- 块边界唯一（同一 server 的 prompt 内无重复 `name`）
- 区间 `clean_system_promot[start:end]` 等于捕获的原始描述字节 `m.group(2)`；Gateway 可见的 `mcp_description` 为 `raw.strip()`（精确源区间提取 + 外层空白归一化）。309 条已接受中，有 22 条 `raw != stripped`（差异 1-5），均为外层换行/空格；溯源区分 `source_span_sha256=sha256(raw)` 与 `normalized_sha256=sha256(stripped)`，并记录 `projection_transform=strip_outer_whitespace`
- description 不等于 `pure_tool.json` 或 `response_all.json` valid 集合中的任何 poisoned 描述
- server 整体在 `tool_names` 与已解析块之间无不匹配，且无重复折叠描述（除非重复本身具有语义意义——见下文审计）

若任一 per-server 检查失败，则**整个 server 的 clean 侧整体排除**为 `CLEAN_PARSE_AMBIGUOUS`。跨 server 的 per-block 重复亦会排除（本次未发现）。

每条已接受的 clean 用例如下记录：

```
source_server, tool_name, description (normalized = raw.strip()), source_span_start, source_span_end, clean_prompt_sha256, source_span_sha256, projection_transform=strip_outer_whitespace
```
Gateway 可见为 `mcp_description = stripped`；溯源 `raw_sha256=sha256(raw_span)`，`normalized_sha256=sha256(stripped)`。

## Server 级别审计（45 个 server，352 个已解析块）

```
servers_total:            45
clean_blocks_raw:         352  (所有从 clean_system_promot 解析出的 Tool 块)
tool_names_total:         353  (sum len tool_names)
servers_clean_parse_ok:   42
servers_ambiguous:         3
clean_blocks_accepted:    309
clean_blocks_excluded:     43
duplicate_clean_defs:      0  (已接受集合中无跨 server 重复描述)
poisoned_collisions:       0  (已接受的 clean 从未等于 poisoned 描述)
```

被排除的 server（严格排除，不做修补）：

| server | tool_names | parsed | reason | detail |
| --- | --- | --- | --- | --- |
| Apify | 7 | 16 | `MISMATCH_TOOL_NAMES` extra | `apify-actor-help-tool`, `apify-slash-rag-web-browser`, `get-actor-run-list`, `get-dataset-list`, `get-key-value-store`, `get-key-value-store-keys`, `get-key-value-store-list`, `get-key-value-store-record`, `search-actors` 出现在 clean prompt 中但不在 `tool_names` 中 |
| DoDo Payments | 20 | 10 | `MISMATCH_TOOL_NAMES` missing | 10 个名称在 clean prompt 中缺失：`activate_licenses`, `charge_subscriptions`, `list_license_key_instances`, `list_subscriptions`, `retrieve_license_key_instances`, `retrieve_line_items_payments`, `retrieve_payments`, `retrieve_subscriptions`, `update_license_keys`, `validate_licenses` |
| Email | 17 | 17 | `DUP_DESC` + empty | 全部 17 个描述均为字面量字符串 `None`；17 个 `tool_names` 有效，但不存在可用的 benign 描述 |

其余 42 个 server 均为 `OK`（已解析数量等于 `tool_names` 长度，无重名，无 `None`/空，无 poisoned 碰撞）。其 309 个块为已接受集合。

43 个被排除块的构成：

- Apify 16
- DoDo Payments 10
- Email 17

若将 Email 计为 17 个 clean 块，则 FPR 将建立在常量字符串与缺失语义之上，因此严格排除的判定是正确的。

跨 server 唯一性（309 条已接受）：309 个 distinct 描述，309 个 distinct `server:tool` 对，零 poisoned 碰撞，与 455 个 distinct poisoned `tool_name` 值零重叠。

## 已接受的 Clean 集合

42 个 server，309 条定义。按 server 汇总：

```
12306-mcp 1, AWSKnowledgeBase 1, AdFin 20, AgentQL 1, AlphaVantage 20, AmapMap 12,
BaiduMap 10, BraveSearch 2, Claude Post 4, ClickHouse 3, Codacy 20, Commander 18,
DumplingAI 20, E2B 1, EverArt 1, Everything 8, Fetch 1, FileSystem 11,
Financial Dataset 11, Flomo 1, Git 11, Github 20, Gitlab 9, Google Maps 7,
GoogleDrive 1, Gyazo 4, HyperBrowser 10, KeywordsPeopleUse 4, Memory 9,
OP.GG 20, Prisma 7, Puppeteer 7, QuickChart 2, Redis 4, SQLite 6, Sentry 1,
Sequential Thinking 1, Slack 8, Tavily 4, gNucleus Text to CAD 1, mcp-simple-arxiv 4, wechat 3
```

融合后的 Core 规模（一旦 normalized/cases.jsonl 冻结）：

```
BLOCK  485  (pure_tool canonical)
ALLOW  309  (高置信度 clean)
TOTAL  794
```

所有 ALLOW 与 BLOCK 共享同一 `group_id = mcptox:server:<server_name>`，因此 `FileSystem` 的攻击与 clean 在任意 `20/60/20` 哈希分桶中始终同行。不做任何合成改写，不删除恶意语句，不做 LLM 改写。

若评审方希望达到“约 1,000”规模，诚实的做法是从去重后的 1,302 个 valid 变体中增补一个 P3-Stress 评估子集，并分别报告 `P3-Core TPR/FPR` 与 `P3-Stress attack TPR`。

## 12 条 Clean ALLOW Golden 证明

确定性选取（描述最长，12 个 distinct server，已验证区间）。每条必须满足：

- `server_name` 与 `tool_name` 等于解析出的 header
- `group_id == mcptox:server:<server_name>`
- `raw source span == projected description`（strip 等价，保留区间索引）
- `expected_action == ALLOW`，`channel == mcp_definition`，`operation == register_tool`
- 无 `query` 字段（clean 轨迹无 query）且 `description` 中无 poisoned 载荷
- 结构化信封 `{server, tool, description, input_schema}` 恰好包含该三个 payload 字段

| # | server | tool | len | span start–end | clean_prompt_sha[:8] |
| --- | --- | --- | --- | --- | --- |
| 1 | AdFin | get_customers | 2365 | 6453–8818 | ec744676 |
| 2 | BraveSearch | brave_local_search | 437 | 630–1067 | 2f837006 |
| 3 | Codacy | codacy_search_repository_srm_items | 1721 | 3960–5681 | 1e1e4684 |
| 4 | Commander | edit_block | 1596 | 7384–8980 | 48ee59e1 |
| 5 | EverArt | generate_image | 452 | 92–544 | 35503100 |
| 6 | Financial Dataset | get_historical_crypto_prices | 506 | 2748–3259 | 14c15c2d |
| 7 | HyperBrowser | browser_use_agent | 1096 | 1841–2937 | 176c92c8 |
| 8 | OP.GG | lol-champion-analysis | 682 | 567–1249 | bd0a8b8e |
| 9 | Prisma | Create-Prisma-Postgres-Database | 968 | 2955–3923 | 7d0b55b3 |
| 10 | Sentry | get_sentry_issue | 377 | 94–471 | 499fdf82 |
| 11 | Sequential Thinking | sequentialthinking | 2780 | 96–2876 | 9ffdc2b2 |
| 12 | mcp-simple-arxiv | search_papers | 516 | 91–607 | 69e99393 |

每条区间 `clean_system_promot[start:end]` 经 strip 后等于投影的 `mcp_description` 与存储的 `description`。12 条描述中均不含任何 poisoned 子串，且均未与任何 poisoned `tool_name` 碰撞。

12 条均共享其 server 的 BLOCK 分组（`mcptox:server:<server>`），因此针对同一 MCP server 的 server 级别 20/60/20 分桶绝不会将 BLOCK 与 ALLOW 拆分。

## 本文不主张的内容

- “已恢复 353 个 authentic clean 工具作为 ALLOW”——不成立；实际恢复 309 条，43 条在严格审计下被排除。
- “Extended/Stress 现已冻结”——已延期；去重后约 1,302 个 distinct 攻击变体已完成特征刻画，但尚未作为套件冻结。
- `tool_content` 的任何再分发许可——在 `f85189f` 仍为 `LICENSE_STATUS = UNRESOLVED, REDISTRIBUTION = NOT ASSUMED`。

## 后续关卡

1. 实现 `p3_mcptox` adapter 扩展（或第二个 adapter id），将 309 个 clean 块作为 `ALLOW` 投影，使用同一 `mcptox:server` 分组，精确源区间提取 + `strip_outer_whitespace` 归一化（Gateway 可见 = 归一化后，溯源 raw=区间 / normalized=strip 后）。
2. 冻结 `p3_mcptox_core` 归一化数据集（485 + 309 + 共享 SHA），此后不再做任何数据编辑。
3. 以确定性方式（seed 42）将 45 个 server 哈希分桶为 `20/60/20`，并为 `p3-*-v1` 套件生成 manifests。
4. 在对接任何真实 LineMod 流量前，完成完整的 fake-gateway 集成测试（render → TargetAdapter → fake 403/observation → oracle → report）。

Holdout 在 Core Standard 被 STOP-gated 之前保持封存。
