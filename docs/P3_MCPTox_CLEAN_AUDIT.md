# P3 MCPTox Clean Reconstruction Audit — Phase 3C0

Date: 2026-08-25 · revision `f85189f9ad12504c197c7f920ab818a40657b1fa` · probe `cache/probe/mcptox`
Required by: Core headline must not ship with an FPR grounded in parser behavior.
Follows: `docs/P3_MCPTox_SOURCE_AUDIT.md` (Phase 3A) and `docs/P3_MCPTox_PROJECTION_PROOF.md` (Phase 3B attack proof).

## Decision

- **Core BLOCK** is `pure_tool.json` 485 canonical definitions, `def_tool/1.py … 485.py`, as proven in Phase 3B.
- **Core ALLOW** is **not** "about 352". It is **309 high-confidence clean definitions** parsed strictly from `response_all.json` `servers[*].clean_system_promot`, with exact source spans and prompt SHAs. The remaining ~43 blocks are excluded as `CLEAN_PARSE_AMBIGUOUS`.
- `response_all.json` valid 1,312 remains available as **Extended/Stress** (attack-only, dedup ~1,302 distinct), not headline.

Backfilling or paraphrasing benign definitions is forbidden. Every ALLOW must be traceable to `response_all.json → server.clean_system_promot → exact byte span`.

## Source for clean

Only `response_all.json:servers[*].clean_system_promot`.

```
clean_system_promot: fully rendered prompt listing the legitimate tools for that server
  Tool: <name>
  Description: <text>
  Arguments:
    - ...
```

plus `tool_names` as a consistency check, never as the sole generator.

No `pure_tool.json` clean counterpart exists. No `def_tool` clean counterpart exists.

## Parser contract (strict, fail-closed)

Regex `Tool:\s*([^\n]+?)\s*\nDescription:\s*(.*?)\nArguments:` with `DOTALL`.

Per-block acceptance requires:

- `name` and `description` both non-empty; `description` not the literal `None`
- block boundary unique (no duplicate `name` within the same server's prompt)
- span `clean_system_promot[start:end]` equals the captured description bytes; `strip()` of that span equals the projected `mcp_description`
- description not equal to any poisoned description from `pure_tool.json` or `response_all.json` valid set
- the server as a whole has no mismatch between `tool_names` and parsed blocks and no duplicate collapsed descriptions (unless the duplication itself is meaningful — see audit below)

If any per-server check fails, the **entire server's clean side is excluded** as `CLEAN_PARSE_AMBIGUOUS`. Per-block duplicates across servers are also excluded (none found).

Each accepted clean case is recorded with:

```
source_server, tool_name, description, source_span_start, source_span_end, clean_prompt_sha256
```

## Server-level audit (45 servers, 352 parsed blocks)

```
servers_total:            45
clean_blocks_raw:         352  (all Tool blocks parsed from clean_system_promot)
tool_names_total:         353  (sum len tool_names)
servers_clean_parse_ok:   42
servers_ambiguous:         3
clean_blocks_accepted:    309
clean_blocks_excluded:     43
duplicate_clean_defs:      0  (no cross-server duplicate descriptions among accepted)
poisoned_collisions:       0  (accepted clean never equals a poisoned description)
```

Excluded servers (strict exclude, not patched):

| server | tool_names | parsed | reason | detail |
| --- | --- | --- | --- | --- |
| Apify | 7 | 16 | `MISMATCH_TOOL_NAMES` extra | `apify-actor-help-tool`, `apify-slash-rag-web-browser`, `get-actor-run-list`, `get-dataset-list`, `get-key-value-store`, `get-key-value-store-keys`, `get-key-value-store-list`, `get-key-value-store-record`, `search-actors` appear in the clean prompt but not in `tool_names` |
| DoDo Payments | 20 | 10 | `MISMATCH_TOOL_NAMES` missing | 10 names missing from the clean prompt: `activate_licenses`, `charge_subscriptions`, `list_license_key_instances`, `list_subscriptions`, `retrieve_license_key_instances`, `retrieve_line_items_payments`, `retrieve_payments`, `retrieve_subscriptions`, `update_license_keys`, `validate_licenses` |
| Email | 17 | 17 | `DUP_DESC` + empty | all 17 descriptions are the literal string `None`; the 17 `tool_names` are valid but no usable benign description exists |

All other 42 servers are `OK` (parsed count equals `tool_names` length, no duplicate names, no `None`/empty, no poisoned collision). Their 309 blocks are the accepted set.

43 excluded blocks break down as:

- Apify 16
- DoDo Payments 10
- Email 17

Had Email been counted as 17 clean blocks, FPR would be grounded in a constant string and in missing semantics, so the strict decision is correct.

Cross-server uniqueness among the 309 accepted: 309 distinct descriptions, 309 distinct `server:tool` pairs, zero poisoned collisions, zero overlap with the 455 distinct poisoned `tool_name` values.

## Accepted clean set

42 servers, 309 definitions. Sum per server:

```
12306-mcp 1, AWSKnowledgeBase 1, AdFin 20, AgentQL 1, AlphaVantage 20, AmapMap 12,
BaiduMap 10, BraveSearch 2, Claude Post 4, ClickHouse 3, Codacy 20, Commander 18,
DumplingAI 20, E2B 1, EverArt 1, Everything 8, Fetch 1, FileSystem 11,
Financial Dataset 11, Flomo 1, Git 11, Github 20, Gitlab 9, Google Maps 7,
GoogleDrive 1, Gyazo 4, HyperBrowser 10, KeywordsPeopleUse 4, Memory 9,
OP.GG 20, Prisma 7, Puppeteer 7, QuickChart 2, Redis 4, SQLite 6, Sentry 1,
Sequential Thinking 1, Slack 8, Tavily 4, gNucleus Text to CAD 1, mcp-simple-arxiv 4, wechat 3
```

Fused Core scale (once normalized/cases.jsonl is frozen):

```
BLOCK  485  (pure_tool canonical)
ALLOW  309  (high-confidence clean)
TOTAL  794
```

All ALLOW share the same `group_id = mcptox:server:<server_name>` as BLOCK, so `FileSystem` attack and `FileSystem` clean travel together across any `20/60/20` hash bucket. No synthetic rewriting, no deletion of malicious sentences, no LLM paraphrase.

If a reviewer wants the "about 1,000" scale, the honest way to reach it is to add a P3-Stress eval subset from the deduped 1,302 valid variants, reported separately as `P3-Core TPR/FPR` and `P3-Stress attack TPR`.

## 12-case clean ALLOW golden proof

Deterministically chosen (longest descriptions, 12 distinct servers, verified spans). Each must satisfy:

- `server_name` and `tool_name` equal the parsed header
- `group_id == mcptox:server:<server_name>`
- `raw source span == projected description` (strip-equivalent, with span indices preserved)
- `expected_action == ALLOW`, `channel == mcp_definition`, `operation == register_tool`
- no `query` field (clean traces have no query) and no poisoned payload in `description`
- structured envelope `{server, tool, description, input_schema}` contains exactly those three payload fields

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

Each spans `clean_system_promot[start:end]` strip-equals the projected `mcp_description` and the stored `description`. None of the 12 descriptions contains any poisoned substring, and none collides with any poisoned `tool_name`.

All 12 share their server's BLOCK group (`mcptox:server:<server>`), so a server-level 20/60/20 bucket never splits BLOCK and ALLOW for the same MCP server.

## What is NOT being claimed

- "353 authentic clean tools recovered as ALLOW" — not true; 309 recovered, 43 excluded under strict audit.
- "Extended/Stress freezes now" — deferred; the deduped ~1,302 distinct attack variants are characterized but not frozen as a suite.
- Any redistribution license for `tool_content` — still `LICENSE_STATUS = UNRESOLVED, REDISTRIBUTION = NOT ASSUMED` at `f85189f`.

## Next gates

1. Implement a `p3_mcptox` adapter extension (or second adapter id) that projects the 309 clean blocks as `ALLOW` with the same `mcptox:server` grouping, byte-identical to the spans above.
2. Freeze `p3_mcptox_core` normalized dataset (485 + 309 + shared SHAs) without any further data edits.
3. Hash-bucket the 45 servers deterministically (seed 42) into `20/60/20` and emit manifests for `p3-*-v1` suites.
4. Full fake-gateway integration test (render → TargetAdapter → fake 403/observation → oracle → report) before any real LineMod traffic.

Holdout stays sealed until Core Standard is STOP-gated.
