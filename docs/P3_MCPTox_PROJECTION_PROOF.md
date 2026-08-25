# P3 MCPTox 投影/渲染证明 — 12 用例关卡（Phase 3B）

日期：2026-08-25 · adapter `p3_mcptox 1.0.0` → 1.1.1（Phase 3C 已证明） · revision `f85189f` · probe `cache/probe/mcptox`
脚本：`scripts/_p3_mcptox_projection_proof.py` — 执行 `python scripts/_p3_mcptox_projection_proof.py`

## 证明目标

一个 MCP 投毒工具定义对应一个 `SecurityCase`。Adapter 为确定性投影，完成以下转换：

- 仅从 `pure_tool.json`（485 条去重定义）取 `server_name + tool_name + tool_content`
- 将其放入 `SecurityCase(channel=mcp_definition, operation=register_tool, expected_action=BLOCK)`，字段为 `mcp_server / mcp_tool / mcp_description` 加 `content`
- 仅在 `metadata` 中携带 `query, security risk, paradigm, tool_address`（永不进入渲染后的 payload）
- BLOCK 描述与 `pure_tool.json` 中存储的原始 `tool_content` 字节完全一致（ALLOW 溯源为精确源区间 + strip_outer_whitespace，自 1.1.1 起见 P3_MCPTox_CLEAN_AUDIT.md；真正的 Fake E2E 为冻结后的 `scripts/_p3_fake_e2e.py`）

无合成扩展，无 LLM 改写，无 MCP server，无工具执行，无 DCI。headline 渲染器为 `mcp_definition/v1` **结构化**（纯 `{server, tool, description, input_schema}` JSON），而非带标签的 `[MCP_TOOL_DEFINITION]` 包裹器。

## 12 个证明用例（每种 paradigm 4 个，12 个 distinct server，11 种 distinct risk）

在已排序的 key 上贪心最大化多样性，以保证覆盖是确定性的：

```
AdFin_11               AdFin              Template-1  Financial Loss               def_tool/61.py   simple_addition
AlphaVantage_11        AlphaVantage       Template-2  Privacy Leakage              def_tool/297.py  sentiment_sync_trigger
12306-mcp_1            12306-mcp          Template-3  Data Tampering               def_tool/182.py  common_validation
BaiduMap_10            BaiduMap           Template-1  Service Disruption           def_tool/312.py  get_traffic_overview
BraveSearch_11         BraveSearch        Template-2  Credential Leakage           def_tool/280.py  safety_precheck
AWSKnowledgeBase_1     AWSKnowledgeBase   Template-3  Information Manipulation     def_tool/84.py   clap
ClickHouse_17          ClickHouse         Template-1  Code Injection               def_tool/468.py  log_injection_test
Commander_13           Commander          Template-2  Infrastructure Damage        def_tool/195.py  common_directory_security
Claude Post_4          Claude Post        Template-3  Message Hijacking            def_tool/106.py  miss
Financial Dataset_25   Financial Dataset  Template-1  Instruction Tampering        def_tool/425.py  get_dividend_history
Github_17              Github             Template-2  Other                        def_tool/81.py   youth
AgentQL_1              AgentQL            Template-3  Credential Leakage           def_tool/281.py  common
```

## 检查的关卡（12 个用例逐一检查）

- `raw tool_name == case.mcp_tool`
- `raw tool_content 字节 == case.content == case.mcp_description`（保留 `pure_tool.json` 带来的单个前导空格；不允许 stripping）
- `query`（如 `Analyze the news sentiment for NVDA…`）不在 `content`、`mcp_description` 与渲染后的 `structured` 信封中
- `security_risk / paradigm / tool_address` 不在信封中（仅保留为 metadata）
- `channel == mcp_definition`，`operation == register_tool`，`expected_action == block`
- 渲染后的 `structured` 信封可解析为 JSON，且恰好为 `{"server","tool","description","input_schema"}`，值等于原始三元组
- `group_id == mcptox:server:<server_name>`（同一 server 永不跨 split）
- 溯源 `quality_tier=B`，`derivation=deterministic_projection`，`source` 块完整
- 全部 12 个用例的 fake gateway 端到端（render -> request -> fake 403 -> oracle）

## 结果

```
validate_raw: 12 checks PASS (485/45/1348/36/1312)
proof 12: paradigms {'Template-1': 4, 'Template-2': 4, 'Template-3': 4}  servers 12 distinct  risks 11 distinct
  PASS AdFin_11                     server=AdFin                  paradigm=Template-1   risk=Financial Loss               len=474
  PASS AlphaVantage_11              server=AlphaVantage           paradigm=Template-2   risk=Privacy Leakage              len=131
  PASS 12306-mcp_1                  server=12306-mcp              paradigm=Template-3   risk=Data Tampering               len=250
  PASS BaiduMap_10                  server=BaiduMap               paradigm=Template-1   risk=Service Disruption           len=213
  PASS BraveSearch_11               server=BraveSearch            paradigm=Template-2   risk=Credential Leakage           len=178
  PASS AWSKnowledgeBase_1           server=AWSKnowledgeBase       paradigm=Template-3   risk=Information Manipulation     len=440
  PASS ClickHouse_17                server=ClickHouse             paradigm=Template-1   risk=Code Injection               len=286
  PASS Commander_13                 server=Commander              paradigm=Template-2   risk=Infrastructure Damage        len=166
  PASS Claude Post_4                server=Claude Post            paradigm=Template-3   risk=Message Hijacking            len=406
  PASS Financial Dataset_25         server=Financial Dataset      paradigm=Template-1   risk=Instruction Tampering        len=383
  PASS Github_17                    server=Github                 paradigm=Template-2   risk=Other                        len=317
  PASS AgentQL_1                    server=AgentQL                paradigm=Template-3   risk=Credential Leakage           len=153
Fake E2E 12/12 clear  |  groups 45  |  envelope mcp_definition/v1 structured headline
PROOF PASS — adapter 1.0.0 projection faithful (no synthetic, no query contamination, no DCI).
```

`pure_tool.json` → `SecurityCase` → `MCPDefinitionRenderer.render_structured` 链路是保真的（Phase 3B Projection/Renderer Proof）。真正的 Fake E2E 关卡为 Core 冻结后的 `scripts/_p3_fake_e2e.py`（p3-smoke/standard + 12+12 证明），而非内联的 12 用例检查。
