# P3 MCPTox Projection Proof — 12-case gate (Phase 3B)

Date: 2026-08-25 · adapter `p3_mcptox 1.0.0` · revision `f85189f` · probe `cache/probe/mcptox`
Script: `scripts/_p3_mcptox_projection_proof.py` — run with `python scripts/_p3_mcptox_projection_proof.py`

## What is being proven

One MCP poisoned tool definition is one `SecurityCase`. The Adapter is a deterministic projection that:

- takes only `server_name + tool_name + tool_content` from `pure_tool.json` (485 deduped definitions)
- puts them into `SecurityCase(channel=mcp_definition, operation=register_tool, expected_action=BLOCK)` as `mcp_server / mcp_tool / mcp_description` plus `content`
- carries `query, security risk, paradigm, tool_address` only in `metadata` (never in the rendered payload)
- leaves the description byte-identical to the raw `tool_content` stored in `pure_tool.json`

No synthetic expansion, no LLM paraphrase, no MCP server, no tool execution, no DCI. The headline renderer is `mcp_definition/v1` **structured** (a plain `{server, tool, description, input_schema}` JSON), not the labeled `[MCP_TOOL_DEFINITION]` wrapper.

## 12 proof keys (4 per paradigm, 12 distinct servers, 11 distinct risks)

Greedy max-diversity over sorted keys so coverage is deterministic:

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

## Gates checked (each of the 12)

- `raw tool_name == case.mcp_tool`
- `raw tool_content bytes == case.content == case.mcp_description` (the single leading space from `pure_tool.json` is preserved; stripping is not allowed)
- `query` (e.g. `Analyze the news sentiment for NVDA…`) absent from `content`, `mcp_description`, and the rendered `structured` envelope
- `security_risk / paradigm / tool_address` absent from the envelope (they remain metadata-only)
- `channel == mcp_definition`, `operation == register_tool`, `expected_action == block`
- rendered `structured` envelope parses as JSON with exactly `{"server","tool","description","input_schema"}` and values equal to the raw triple
- `group_id == mcptox:server:<server_name>` (same server never crosses a split)
- provenance `quality_tier=B`, `derivation=deterministic_projection`, `source` block present
- fake gateway end-to-end for all 12 (render -> request -> fake 403 -> oracle)

## Result

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

The `pure_tool.json` → `SecurityCase` → `MCPDefinitionRenderer.render_structured` chain is faithful. The `mcp_definition` channel is ready for a full freeze without any further Adapter changes; the 1312 number from `response_all.json` remains recorded for traceability but does not feed the current Adapter iteration (485 deduplicated).
