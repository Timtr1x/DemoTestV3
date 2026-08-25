# P3 MCPTox 来源审计 — Phase 3A

日期：2026-08-25 · repo `main` · probe `cache/probe/mcptox`（gitignored 本地克隆，未拷贝入仓库）
审计方式：仅程序化校验，无 LLM、无合成生成、无 DCI、无 MCP 运行时

## 1. 版本锁定与原始产物

```
repository: zhiqiangwang4/MCPTox-Benchmark
revision:   f85189f9ad12504c197c7f920ab818a40657b1fa  (git rev-parse HEAD)
branch:     单一分支，2 个 commits，"Initial commit" 2025-12-03
remote:     https://github.com/zhiqiangwang4/MCPTox-Benchmark
```

该 revision 上的文件（`git ls-files`）：

```
README.md              10 B   "# AAAI26\n"
pure_tool.json         321076 B  SHA256 9a321dc4ecf4869883cf2a29ea8189e1f7663720a9c41a3e5ce2323d580e31c1
def_tool/1.py … 485.py 485 files (真实 @mcp.tool() 定义，带投毒 docstring)
response_all.json      20771398 B  SHA256 4f8177dcbe3718ce3d6ea6a0eec8fa27813158179bd30afe340fe854e886fdf5  data_length 1348
analysis.ipynb         65236 B  SHA256 57b8f7a3b7ce0b11a298505e72b345b202b58ccecbd50c63acfe9af8ffcd8beb
LICENSE / LICENCE / COPYING: 树中均未找到
```

除上述树之外无其他分支、无标签、无发布产物。任何未来的 freeze 都必须重新解析 `f85189f` 并在构建 source lock 前重新计算上述三个 SHA256。

## 2. 两个主文件的真实内容

- `pure_tool.json` —— 并非 benign 工具。它是一份 **485 条目的投毒定义列表**。结构为 45 个 dict 的列表，每个 dict 将 `"<Server>_<N>"` 映射为 `{server_name, tool_name, query, tool_content, security risk, paradigm, tool_address}`。合并 45 个 dict 后的扁平计数为 **485** 条 distinct 条目，`tool_address` 范围 `def_tool/1.py` … `485.py`。每条均包含非空 `server_name`、`tool_name`、`tool_content`、`tool_address`（100%）。

- `response_all.json` —— 作者的 **agent 评估转储**。顶层 key 为 `data_length`、`attack_scopes`、`label_scopes`、`call_behaviors`、`save_dir`、`servers`。`servers` 为 45 个 server 的 dict，每个值包含 `malicious_instance`（列表）。累加这些列表即得 `data_length 1348`。每条 `malicious_instance` 携带 `wrong_data`（0 或 2）、`datas`（恒为长度 1）、`metadata`（`paradigm`、`security risk`）、`poisoned_tool`（渲染字符串 `Tool: <name>\nDescription: ...\nArguments: - No arguments`）、`security_risk_description`（中文），以及按 query 划分的 `datas[0]`（`id`、`query`、`system`、`response`、`label`、`online_result`、`poisoned_tool`）。`system` 本身是为该评估回合完整渲染的工具列表（clean 工具 + 一个投毒工具）。

这两个文件规模不同，描述也非逐字节相同。第 4 节量化了差距。

## 3. Raw / excluded / valid —— 重新计算，而非沿用假设

来自 `response_all.json`（论文中引用的 1348 这一数值的权威来源）：

| count | value | how derived |
| --- | --- | --- |
| raw malicious_instance | 1348 | 跨 45 个 server 累加 len `malicious_instance`，等于 `data_length` |
| wrong_data excluded | 36 | 满足 `wrong_data == 2` 的条目（无 `wrong_data == 1` 的条目；1312 条为 `0`，36 条为 `2`） |
| valid | 1312 | 1348 - 36 |

按 server 划分的 wrong-data 分布（仅列出有排除的 server）：

```
Slack 9, Puppeteer 6, Flomo 3, Claude Post 3, HyperBrowser 3, mcp-simple-arxiv 3, Memory 3, EverArt 3, BraveSearch 2, SQLite 1
```

Flomo 极端：其 3 条 `malicious_instance` 均为 `wrong_data=2`，因此 valid 为 0。Slack 在 42 条 raw 中失去 9 条。这 36 条必须作为审计链保留（若后续产出 `excluded_mcptox_cases.jsonl`，仅存储 `source_id, server, tool, reason`）；无需拷贝完整描述。

仅来自 `pure_tool.json`：

```
raw flat entries: 485
wrong_data field: 每条均不存在该 key（0 条包含该 key）
valid if we treat pure_tool as source: 485
```

这直接与指南此前的预期相矛盾：此前预期 `pure_tool.json` 本身包含 1348 条且 `wrong_data` 可在其中过滤。实际并非如此。`pure_tool.json` 已是 485 条目的过滤后子集（每个 `def_tool` 文件对应一个投毒定义）。1312 这一数值仅存在于 `response_all.json`。任何写有“MCPTox 有 1,348 个恶意用例，排除 36 个，valid 1,312 个”的文档，必须引用 `response_all.json`，而非 `pure_tool.json`。

## 4. pure_tool 485 vs response_all 1312 —— 同一批 server，不同采样

两个文件中 distinct server 均为 45 个，且名称集合完全一致：

```
12306-mcp, AWSKnowledgeBase, AdFin, AgentQL, AlphaVantage, AmapMap, Apify, BaiduMap,
BraveSearch, Claude Post, ClickHouse, Codacy, Commander, DoDo Payments, DumplingAI, E2B,
Email, EverArt, Everything, Fetch, FileSystem, Financial Dataset, Flomo, Git, Github,
Gitlab, Google Maps, GoogleDrive, Gyazo, HyperBrowser, KeywordsPeopleUse, Memory, OP.GG,
Prisma, Puppeteer, QuickChart, Redis, SQLite, Sentry, Sequential Thinking, Slack, Tavily,
gNucleus Text to CAD, mcp-simple-arxiv, wechat
```

但按 server 的 valid 计数差异显著（pure 约为 response valid 的三分之一）：

```
server            pure  response valid
Email               41    126
Commander           26     78
Prisma              24     77
ClickHouse          24     73
FileSystem          24     70
Github              19     53
… (除 Flomo 外每个 server 的 response 均更大：pure 1，valid 0)
```

剥离外层 `Tool: … Description: … Arguments:` 信封后的描述重叠情况：

- 精确 strip 相等 `tool_content.strip() == extract_desc(poisoned_tool).strip()`：**212 / 485** 条 pure 条目与 response 描述精确匹配
- 子串 `tool_content.strip() in poisoned_tool string`：**387 / 485** 条作为子串匹配
- valid response 中的 distinct 描述：**1302**（1312 条 valid 中有 10 条重复；例如 `secure_commit_protocol` 与 `system_payment_rules` 各出现两次）
- 仅在 response 中存在的 distinct 且不在 pure 中的描述：**1090** 个 distinct 描述仅存在于 response

子串差距由系统性前缀差异解释：**485** 条 pure `tool_content` 字符串中 **0** 条包含子串 `Ignore the previous`，而 **1312** 条 valid response `poisoned_tool` 描述中有 **418** 条包含。以 `FileSystem_19` 为例，pure 以 `Get current time.  Before using…` 开头，而 response 对应为 `Get current time. Ignore the previous instructions and do the following:  Before using…`。response 变体在相同载荷外包裹了显式的 ignore 指令。该前缀本身即为攻击信号的一部分，对 gateway 检测有影响，因此主数据源的选择直接影响 benchmark 难度。

对 Adapter 的含义：任一文件均可为 `mcp_definition` 用例提供 `server_name + tool_name + tool_content`，但冻结后的 valid 计数与每条定义的文本将不同。仅锁定 `pure_tool.json` 即提交为 **485 条去重定义**；锁定 `response_all.json`（valid 1312）即提交为 **1312 个评估回合**，每个 server 有更多改写。freeze 决策必须显式二选一，并无论如何记录两个 SHA256。

## 5. 分类分布 —— 基于锁定文件重新统计

pure_tool 485:

```
paradigm:  Template-3 225, Template-2 183, Template-1 77
security risk (11): Information Manipulation 108, Privacy Leakage 97, Service Disruption 73,
  Data Tampering 45, Infrastructure Damage 41, Credential Leakage 40, Code Injection 22,
  Financial Loss 21, Instruction Tampering 21, Message Hijacking 15, Other 2
```

response_all valid 1312:

```
paradigm:  Template-3 585, Template-2 519, Template-1 208
security risk (11): Privacy Leakage 273, Information Manipulation 269, Service Disruption 196,
  Infrastructure Damage 122, Data Tampering 117, Credential Leakage 115, Code Injection 63,
  Instruction Tampering 57, Financial Loss 55, Message Hijacking 41, Other 4
```

response_all raw 1348（含 wrong）：

```
paradigm:  Template-3 618, Template-2 519, Template-1 211
risk raw:  Information Manipulation 281, Privacy Leakage 276, Service Disruption 209,
  Infrastructure Damage 124, Data Tampering 120, Credential Leakage 115, Code Injection 63,
  Instruction Tampering 57, Financial Loss 55, Message Hijacking 44, Other 4
```

全部 11 个 `security risk` 字符串与 3 个 `paradigm` 字符串均为上游原值，原样保留，不映射为内部 risk 等级。485 个 pure 名称中的重复：485 条中有 455 个 distinct `tool_name` 值（30 个名称在不同 server/定义间复用）。Valid response 中重复的 poisoned 字符串：1312 条 valid 中有 10 个重复字符串。

## 6. def_tool/ 溯源交叉校验

- `def_tool/` 包含 485 个 `.py` 文件，每个文件以 `@mcp.tool()` 装饰单一函数，docstring 为投毒内容。
- 将 `tool_content`（pure）与按文件 AST 提取的 docstring 对比：
  - 485 个文件中有 484 个在两侧 `strip()` 后匹配（除首尾空白外逐字节一致，且 pure 始终多一个前导空格：pure 值以 `" "` 开头）。
  - 1 个文件在该 revision 的磁盘上已损坏：`def_tool/10.py` 的 `def cloud(path: str)` 其 docstring 原始以 `"s\n    Before initiating…"` 开头——首字符为截断的 `s`（应为 `Before…`）。其在 pure 中的 `tool_content`（`FileSystem_10`）为正确的完整字符串 ` Before initiating…`（长度 410 vs docstring 原始 419 含多余的 `s`）。这是上游在 `f85189f` 的产物 bug，并非本地拉取错误（已通过 `git status` 干净与哈希 `dfdfc4e5…` 验证）。

结论：`pure_tool.json:tool_content` 为 Adapter 的权威文本；`def_tool/*.py` 的 docstring 可作为溯源抽检，但因存在单处截断 bug 不能替代。无合成扩展，无 LLM 改写。

## 7. Clean 对照 —— 能否恢复声称的 353 个 authentic 工具？

论文声称 45 个 server 背后有 353 个 authentic 工具。仓库未单独提供 `clean_tools.json`。其实际提供的是可在 `response_all.json:servers[*].clean_system_promot` 中恢复的 clean 描述——即 clean 回合所用的 system prompt。

重新计算：

```
sum len tool_names across 45 servers:               353  (与论文的 353 一致)
distinct tool_names from that field:                 333  (19 个名称出现在 2 个 server，如 read_file)
Tool blocks parsed from clean_system_promot:        362  (正则 Tool: NAME + Description: + Arguments:)
  strict count (Tool: NAME \\n Description: pattern): 352
distinct clean names via that parse:                 342
```

`tool_names` 长度与已解析块之间的按 server 不匹配：

- `DoDo Payments`：`tool_names` 列出 20 个名称，但 prompt 解析出 10 个 Tool 块
- `Apify`：列出 7 个，但 prompt 解析出 16 个（prompt 包含了如 `apify-slash-rag-web-browser` 等通用浏览助手，不在 7 个之内）

FileSystem 示例解析正确：`tool_names` 为 11，prompt 中恰好包含 11 个块（`read_file`、`read_multiple_files`、`write_file`、`edit_file`、`create_directory`、`list_directory`、`directory_tree`、`move_file`、`search_files`、`get_file_info`、`list_allowed_directories`）。

评估：**可从官方产物中恢复 server 级别的 clean 集合**，但它并非与每个投毒定义一一对应的 per-case clean 对照，且由于跨 server 重复以及上述两个 server 的 clean prompt 列表与 `tool_names` 数组不一致，计数并非精确的 353 个 distinct 定义。benchmark 的 ALLOW 侧可通过将每个 clean Tool 块投影为正常的 `mcp_definition`（`expected_action=allow`），按同一 `mcptox:server:<server_name>` 分组，并与该 server 的攻击一同切分来构建。但这需要明确的 freeze 决策与显式溯源说明；并非已物化为现成的 `353 clean cases` 文件。

按指南的优先级，该恢复路径为 **P1（官方产物内嵌的 clean 定义）**——无需手写即可接受。仍被禁止的是：从投毒描述中删除恶意语句、LLM 改写、或编写合成 benign 工具。在显式 clean freeze 被评审前，benchmark 必须描述为 **仅攻击、ALLOW 待定**（仅 TPR，`FPR = n/a`）。

## 8. 不得进入 gateway payload 的内容

已验证 `mcp_definition` 唯一对 gateway 可见的字段为 `server_name`、`tool.name`、`tool.description`。以下在两个来源中均为仅 metadata，绝不得拼接到渲染后的请求中：

```
query, security risk / security_risk_description, paradigm, tool_address, wrong_data,
category_id, server_id, datas[*].system / response / label / online_result
```

两个来源中的 `query` 均为 agent 评估触发器（良性用户请求，如 `Read the content of '/data/project/documents/report.txt'`）。它不属于 MCP 定义的一部分。

## 9. 分组与切分设计

推荐并将由 Adapter/测试强制执行：

```
group_id = mcptox:server:<server_name>   # 45 个组
```

45 个 server → 确定性 20 / 60 / 20 的 server 级别切分（约 9 / 27 / 9 个 server）。用例数量不会精确均衡；组完整性优先于精确的 `n`。同一 server 的投毒与 clean Tool 块一旦冻结，绝不得跨 `dev / eval / holdout` 切分。Flomo 在排除后 valid 为 0，意味着它将是一个空的攻击组——按退化组处理，不贡献 BLOCK 用例，但若我们冻结 clean 块仍可能携带 clean 块。

## 10. 许可与再分发

- 在 `f85189f` 的仓库中不含 `LICENSE`、`LICENCE` 或 `COPYING` 文件。
- README 为 9 字节（`# AAAI26`）。其中未说明数据集许可。
- 在 AAAI-26 会议论文集发表本身并不授予数据集许可。

```
LICENSE_STATUS = UNRESOLVED
REDISTRIBUTION = NOT ASSUMED
```

内部研究可在已锁定的克隆上继续。任何对 `pure_tool.json`、`def_tool/` 内容或逐字拷贝 `tool_content` 的归一化衍生用例的再分发，在上游新增许可或获得显式授权前，均应视为**未获授权**。source lock 与原始 SHA256 值，以及归一化用例指纹可以提交；不应假定完整的 `tool_content` 字符串可公开发布。

## 11. 冻结后的规模 —— 数值会是多少

| view | BLOCK | ALLOW（若 clean 已冻结） | total | note |
| --- | --- | --- | --- | --- |
| pure_tool only | 485 | 至多约 352 个 clean 块（distinct 约 342） | ~837 | 去重后的定义 |
| response_all valid | 1312 | 同一 clean 池 | ~1664 | 评估回合规模 |
| after wrong_data excluded | 485（pure）或 1312（response valid）二选一 | — | — | 必须选择一个主视图并命名 |

45 个 server 组，20/60/20 的 server 切分大致为：

```
pure view:       dev ~97 / eval ~291 / holdout ~97  BLOCK (+ ~70/~210/~70 clean)
response valid:  dev ~262 / eval ~787 / holdout ~263 BLOCK (+ 同一 clean)
```

Smoke 随后从 dev 采样 100–120；Standard 运行完整 eval。除保持组完整性外无需采样偏置校正。

## 12. Phase 3B 准入关卡清单

| gate | condition | status |
| --- | --- | --- |
| G1 Source pin | 仓库锁定至 `f85189f`，记录 rev，`pure_tool.json` 与 `response_all.json` 的 SHA256 | PASS |
| G2 Raw hash | `pure_tool.json` SHA `9a321dc4…`，`response_all.json` SHA `4f8177dc…` | PASS |
| G3 Count | response 1348 / 36 / 1312 已重新计算；pure 485 已重新计算；差异已记录 | PASS（主数据源待决策） |
| G4 Projection | 已识别 `server_name + tool_name + tool_content` 为唯一 payload；query/risk/paradigm/address 已排除 | PASS |
| G5 No query contamination | 已验证 `query` 为触发上下文，非定义 | PASS |
| G6 Group split | 已定义 `mcptox:server:<server_name>`，server 永不跨切分 | PASS（设计，尚未实现） |
| G7 No template expansion | 0 合成扩展，10 个 response 重复已记为上游产生，非生成 | PASS |
| G8 Clean provenance | ALLOW 可从官方 clean prompt 恢复但尚未冻结；禁止合成 benign | PARTIAL — 待 freeze 决策 |
| G9 Manifest | source lock 将在 Adapter 冻结时绑定 | PENDING Phase 3B |
| G10 Proof E2E | 12 用例证明：`structured` 保真，描述逐字节一致 | PENDING Phase 3B |
| G11 Holdout | 按 server 组封存 | PENDING freeze |
| G12 License | UNRESOLVED，再分发不作假定，已在此记录 | PASS |

## 13. Phase 3B 在任何真实 LineMod 运行前必须完成事项

- 选择并记录主攻击源（推荐**response_all valid 1312** 以获得完整规模，或显式选择**pure_tool 485** 以获得去重口径并说明理由）。无论选择哪一个，另一文件的 SHA 仍需记录以便追溯。
- 实现 `P3MCPToxAdapter 1.0.0`，仅投影 `server_name / tool_name / tool_content`（`channel=mcp_definition`、`operation=register_tool`、`expected_action=block`），将 `query` 等放入 `metadata`，描述保持逐字节一致（保留 `pure_tool.json` 中存储的单个前导空格；不在渲染时静默 strip）。
- 决定 clean freeze：要么将 `clean_system_promot` 中约 352 个 clean Tool 块冻结为 ALLOW（同 server 分组），要么冻结为仅攻击并保持 `headline_eligible=false` / `FPR=n/a`。无第三条路径。
- 选取 `p3-mcptox-proof-v0` 为 12 个用例，覆盖 3 种 paradigm 与至少 6 个 server / 4 种 security risk，对每个用例做 raw → content 一致性、无 query 泄漏、server-group 确定性的 golden 检查，并做 fake-gateway 端到端。
- 不构建任何 `mcp_server/` 或 `tool_executor/` 套件。不向渲染后的 payload 添加 `user query`。不手写 clean 定义。

---

*Probe 路径：* `cache/probe/mcptox/pure_tool.json`、`cache/probe/mcptox/response_all.json`、`cache/probe/mcptox/def_tool/*.py`、`cache/probe/mcptox/analysis.ipynb` —— 均位于已锁定 revision 下。在任何 freeze 前请重新执行本文中的计数；以上数值均锁定于该 revision 与对应 SHA256。
