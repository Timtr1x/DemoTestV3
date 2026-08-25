# P3 MCPTox Source Audit — Phase 3A

Date: 2026-08-25 · repo `main` · probe `cache/probe/mcptox` (gitignored local clone, not copied into repo)
Auditor: programmatic verification only, no LLM, no synthetic generation, no DCI, no MCP runtime

## 1. Pin and raw artifact

```
repository: zhiqiangwang4/MCPTox-Benchmark
revision:   f85189f9ad12504c197c7f920ab818a40657b1fa  (git rev-parse HEAD)
branch:     single branch, 2 commits, "Initial commit" 2025-12-03
remote:     https://github.com/zhiqiangwang4/MCPTox-Benchmark
```

Files on that revision (`git ls-files`):

```
README.md              10 B   "# AAAI26\n"
pure_tool.json         321076 B  SHA256 9a321dc4ecf4869883cf2a29ea8189e1f7663720a9c41a3e5ce2323d580e31c1
def_tool/1.py … 485.py 485 files (real @mcp.tool() definitions, poisoned docstrings)
response_all.json      20771398 B  SHA256 4f8177dcbe3718ce3d6ea6a0eec8fa27813158179bd30afe340fe854e886fdf5  data_length 1348
analysis.ipynb         65236 B  SHA256 57b8f7a3b7ce0b11a298505e72b345b202b58ccecbd50c63acfe9af8ffcd8beb
LICENSE / LICENCE / COPYING: none found anywhere in tree
```

No other branches, no tags, no release artifact beyond this tree. Any future freeze must re-resolve `f85189f` and recompute the three SHA256 above before building a source lock.

## 2. What the two main files actually are

- `pure_tool.json` — NOT benign tools. It is a **485-entry poisoned definition list**. Structure is a list of 45 dicts, each dict maps `"<Server>_<N>"` → `{server_name, tool_name, query, tool_content, security risk, paradigm, tool_address}`. Flat count after merging the 45 dicts is **485** distinct entries, with `tool_address` ranging `def_tool/1.py` … `485.py`. Every entry has non-empty `server_name`, `tool_name`, `tool_content`, `tool_address` (100%).

- `response_all.json` — the authors' **agent evaluation dump**. Top keys are `data_length`, `attack_scopes`, `label_scopes`, `call_behaviors`, `save_dir`, `servers`. `servers` is a dict of 45 servers, each value holds `malicious_instance` (a list). Summing those lists gives `data_length 1348`. Each `malicious_instance` entry carries `wrong_data` (0 or 2), `datas` (always length 1), `metadata` (`paradigm`, `security risk`), `poisoned_tool` (a rendered string `Tool: <name>\nDescription: ...\nArguments: - No arguments`), `security_risk_description` (Chinese), and per-query `datas[0]` (`id`, `query`, `system`, `response`, `label`, `online_result`, `poisoned_tool`). `system` itself is a fully rendered tool list (clean tools plus the one poisoned tool) for that evaluation episode.

These two files are not the same scale and not byte-for-byte the same descriptions. Section 4 quantifies the gap.

## 3. Raw / excluded / valid — recomputed, not assumed

From `response_all.json` (authoritative for the 1348 number quoted in the paper):

| count | value | how derived |
| --- | --- | --- |
| raw malicious_instance | 1348 | sum len `malicious_instance` across 45 servers, equals `data_length` |
| wrong_data excluded | 36 | entries where `wrong_data == 2` (no entries have `wrong_data == 1`; 1312 have `0`, 36 have `2`) |
| valid | 1312 | 1348 - 36 |

Wrong-data split by server (only servers with exclusions):

```
Slack 9, Puppeteer 6, Flomo 3, Claude Post 3, HyperBrowser 3, mcp-simple-arxiv 3, Memory 3, EverArt 3, BraveSearch 2, SQLite 1
```

Flomo is extreme: its 3 `malicious_instance` entries are all `wrong_data=2`, so valid 0. Slack loses 9 of its 42 raw. These 36 must be kept as an audit chain (store only `source_id, server, tool, reason`) if we later emit `excluded_mcptox_cases.jsonl`; we do not need to copy full descriptions.

From `pure_tool.json` alone:

```
raw flat entries: 485
wrong_data field: absent in every entry (0 entries have the key)
valid if we treat pure_tool as source: 485
```

This directly contradicts the guide's prior expectation that `pure_tool.json` would itself contain 1348 entries and that `wrong_data` would be filterable there. It does not. `pure_tool.json` is already a 485-entry filtered subset (one poisoned definition per `def_tool` file). The 1312 number lives only in `response_all.json`. Any documentation that says "MCPTox has 1,348 malicious cases, 36 excluded, 1,312 valid" must cite `response_all.json`, not `pure_tool.json`.

## 4. pure_tool 485 vs response_all 1312 — same servers, different sampling

Distinct servers are 45 in both files and the name sets match exactly:

```
12306-mcp, AWSKnowledgeBase, AdFin, AgentQL, AlphaVantage, AmapMap, Apify, BaiduMap,
BraveSearch, Claude Post, ClickHouse, Codacy, Commander, DoDo Payments, DumplingAI, E2B,
Email, EverArt, Everything, Fetch, FileSystem, Financial Dataset, Flomo, Git, Github,
Gitlab, Google Maps, GoogleDrive, Gyazo, HyperBrowser, KeywordsPeopleUse, Memory, OP.GG,
Prisma, Puppeteer, QuickChart, Redis, SQLite, Sentry, Sequential Thinking, Slack, Tavily,
gNucleus Text to CAD, mcp-simple-arxiv, wechat
```

But per-server valid counts diverge sharply (pure is ~one-third of response valid):

```
server            pure  response valid
Email               41    126
Commander           26     78
Prisma              24     77
ClickHouse          24     73
FileSystem          24     70
Github              19     53
… (every server larger in response except Flomo: pure 1, valid 0)
```

Description overlap after stripping the outer `Tool: … Description: … Arguments:` envelope:

- exact stripped equality `tool_content.strip() == extract_desc(poisoned_tool).strip()`: **212 of 485** pure entries match a response description exactly
- substring `tool_content.strip() in poisoned_tool string`: **387 of 485** match as substring
- distinct descriptions in valid response: **1302** (10 duplicates among the 1312 valid entries; e.g. `secure_commit_protocol` and `system_payment_rules` each appear twice)
- response distinct not in pure: **1090** distinct descriptions exist only in response

The substring gap is explained by a systematic prefix difference: **0 of 485** pure `tool_content` strings contain the substring `Ignore the previous`, while **418 of 1312** valid response `poisoned_tool` descriptions do. Example `FileSystem_19` pure starts `Get current time.  Before using…` while the response counterpart is `Get current time. Ignore the previous instructions and do the following:  Before using…`. The response variant wraps the same payload with an explicit ignore instruction that pure omits. This prefix is itself part of the attack signal and matters for gateway detection, so the choice of primary source directly affects the benchmark's difficulty.

Implication for the Adapter: either file can supply `server_name + tool_name + tool_content` for a `mcp_definition` case, but the frozen valid count and the per-definition text will differ. Pinning only `pure_tool.json` commits to **485 deduplicated definitions**; pinning `response_all.json` (valid 1312) commits to **1312 evaluation episodes** with many more paraphrases per server. The freeze decision must explicitly choose one and record both SHA256 values regardless.

## 5. Taxonomy distributions — recomputed from pinned files

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

response_all raw 1348 (including wrong):

```
paradigm:  Template-3 618, Template-2 519, Template-1 211
risk raw:  Information Manipulation 281, Privacy Leakage 276, Service Disruption 209,
  Infrastructure Damage 124, Data Tampering 120, Credential Leakage 115, Code Injection 63,
  Instruction Tampering 57, Financial Loss 55, Message Hijacking 44, Other 4
```

All 11 `security risk` strings and 3 `paradigm` strings are the upstream values, preserved as-is. No remapping to internal risk tiers. Duplicates across the 485 pure names: 455 distinct `tool_name` values among 485 entries (30 names reused across servers/definitions). Valid response duplicate poisoned strings: 10 duplicated strings among 1312 valid entries.

## 6. def_tool/ provenance cross-check

- `def_tool/` contains 485 `.py` files, each decorated `@mcp.tool()` with a single function and a poisoned docstring.
- Compared `tool_content` (pure) against the AST-extracted docstring per file:
  - 484 of 485 files match after `strip()` on both sides (byte-identical modulo leading/trailing whitespace and a single leading space that pure consistently adds: pure values start with `" "`).
  - 1 file is corrupted on disk at this revision: `def_tool/10.py` has `def cloud(path: str)` with docstring raw starting `"s\n    Before initiating…"` — the first character is `s` truncation (should be `Before…`). Its `tool_content` in pure (`FileSystem_10`) is the correct full string ` Before initiating…` (length 410 vs docstring raw 419 with the stray `s`). This is an upstream artifact bug at `f85189f`, not a local fetch error (verified by `git status` clean and hash `dfdfc4e5…`).

Conclusion: `pure_tool.json:tool_content` is the authoritative text for the Adapter; `def_tool/*.py` docstrings are a valid provenance spot-check but not a substitute due to the single truncation bug. No synthetic expansion, no LLM rewrite.

## 7. Clean controls — can we recover the claimed 353 authentic tools?

The paper claims 353 authentic tools underpinning the 45 servers. The repo does not ship a separate `clean_tools.json`. What it does ship is recoverable clean descriptions inside `response_all.json:servers[*].clean_system_promot` — the system prompt used for clean episodes.

Recomputed:

```
sum len tool_names across 45 servers:               353  (matches paper's 353)
distinct tool_names from that field:                 333  (19 names appear on 2 servers, e.g. read_file)
Tool blocks parsed from clean_system_promot:        362  (regex Tool: NAME + Description: + Arguments:)
  strict count (Tool: NAME \\n Description: pattern): 352
distinct clean names via that parse:                 342
```

Per-server mismatches between `tool_names` length and parsed blocks:

- `DoDo Payments`: `tool_names` lists 20 names but prompt parses to 10 Tool blocks
- `Apify`: lists 7 but prompt parses to 16 (the prompt includes generic browsing helpers like `apify-slash-rag-web-browser` not in the 7)

FileSystem example parses correctly: `tool_names` 11 and prompt contains exactly 11 blocks (`read_file`, `read_multiple_files`, `write_file`, `edit_file`, `create_directory`, `list_directory`, `directory_tree`, `move_file`, `search_files`, `get_file_info`, `list_allowed_directories`).

Assessment: a **server-level clean set is recoverable from the official artifact**, but it is not a per-case 1:1 clean counterpart to each poisoned definition, and the counts are not exactly 353 distinct definitions due to cross-server duplicates and the two servers above where the clean prompt listing diverges from the `tool_names` array. An ALLOW side for the benchmark could be built by projecting each clean Tool block as a normal `mcp_definition` (`expected_action=allow`), grouping by the same `mcptox:server:<server_name>`, and splitting together with the attacks from that server. However this requires a deliberate freeze decision and explicit provenance note; it is not already materialized as a ready-made `353 clean cases` file.

Per the guide's priority order, this recovery path is **P1 (official artifact embedded clean definitions)** — acceptable without hand-writing. What remains forbidden is deleting malicious sentences from a poisoned description, LLM-paraphrasing, or authoring synthetic benign tools. Until an explicit clean freeze is reviewed, the benchmark must be described as **attack-only with pending ALLOW** (TPR-only, `FPR = n/a`).

## 8. What must NOT enter the gateway payload

Verified that the only gateway-visible fields for `mcp_definition` are `server_name`, `tool.name`, `tool.description`. The following are metadata-only in both sources and must never be concatenated into the rendered request:

```
query, security risk / security_risk_description, paradigm, tool_address, wrong_data,
category_id, server_id, datas[*].system / response / label / online_result
```

`query` in both pure and response is the agent evaluation trigger (benign user request like `Read the content of '/data/project/documents/report.txt'`). It is not part of the MCP definition.

## 9. Group and split design

Recommended and to be enforced by the Adapter/tests:

```
group_id = mcptox:server:<server_name>   # 45 groups
```

45 servers → deterministic 20 / 60 / 20 server-level split (roughly 9 / 27 / 9 servers). Case counts will not be exactly balanced; group integrity outranks exact `n`. The same server's poisoned and clean Tool blocks, once frozen, must never be split across `dev / eval / holdout`. Flomo's valid 0 after exclusions means it would be an empty attack group — handle as a degenerate group that contributes no BLOCK cases but may still carry a clean block if we freeze one.

## 10. License and redistribution

- Repo contains no `LICENSE`, `LICENCE`, or `COPYING` file at `f85189f`.
- README is 9 bytes (`# AAAI26`). No dataset license is documented there.
- Publication at AAAI-26 proceedings does not itself grant a dataset license.

```
LICENSE_STATUS = UNRESOLVED
REDISTRIBUTION = NOT ASSUMED
```

Internal research use can proceed on the pinned clone. Any redistribution of `pure_tool.json`, `def_tool/` contents, or normalized derived cases that copy `tool_content` verbatim must be treated as **not authorized** until a license is added upstream or explicit permission is obtained. The source lock and raw SHA256 values, plus normalized case fingerprints, can be committed; the full `tool_content` strings should not be assumed publishable.

## 11. Scale once frozen — what the numbers will be

| view | BLOCK | ALLOW (if clean frozen) | total | note |
| --- | --- | --- | --- | --- |
| pure_tool only | 485 | up to ~352 clean blocks (distinct ~342) | ~837 | deduplicated definitions |
| response_all valid | 1312 | same clean pool | ~1664 | evaluation-episode scale |
| after wrong_data excluded | either 485 (pure) or 1312 (response valid) | — | — | must pick one primary and name it |

With 45 server groups, a 20/60/20 server split gives roughly:

```
pure view:       dev ~97 / eval ~291 / holdout ~97  BLOCK (+ ~70/~210/~70 clean)
response valid:  dev ~262 / eval ~787 / holdout ~263 BLOCK (+ same clean)
```

Smoke then samples 100–120 from dev; Standard runs full eval. No sampling bias correction needed beyond preserving group integrity.

## 12. Gates checklist for Phase 3B entry

| gate | condition | status |
| --- | --- | --- |
| G1 Source pin | repo pinned to `f85189f`, rev recorded, SHA256 for `pure_tool.json` and `response_all.json` | PASS |
| G2 Raw hash | `pure_tool.json` SHA `9a321dc4…`, `response_all.json` SHA `4f8177dc…` | PASS |
| G3 Count | response 1348 / 36 / 1312 recomputed; pure 485 recomputed; discrepancy documented | PASS (with open decision on primary) |
| G4 Projection | `server_name + tool_name + tool_content` identified as sole payload; query/risk/paradigm/address excluded | PASS |
| G5 No query contamination | verified `query` is trigger context, not definition | PASS |
| G6 Group split | `mcptox:server:<server_name>` defined, server never crosses split | PASS (design, not yet implemented) |
| G7 No template expansion | 0 synthetic expansion, 10 response duplicates noted as upstream, not generated | PASS |
| G8 Clean provenance | ALLOW recoverable from official clean prompts but not yet frozen; synthetic benign forbidden | PARTIAL — pending freeze decision |
| G9 Manifest | source lock to be bound at Adapter freeze | PENDING Phase 3B |
| G10 Proof E2E | 12-case proof with `structured` fidelity, byte-identical description | PENDING Phase 3B |
| G11 Holdout | sealed by server groups | PENDING freeze |
| G12 License | UNRESOLVED, redistribution not assumed, documented here | PASS |

## 13. What Phase 3B must do before any real LineMod run

- Choose and document the primary attack source (recommend **response_all valid 1312** for full scale, or explicitly **pure_tool 485** for deduplicated, with rationale). Whichever is chosen, the other SHA remains recorded for traceability.
- Implement `P3MCPToxAdapter 1.0.0` projecting only `server_name / tool_name / tool_content` (`channel=mcp_definition`, `operation=register_tool`, `expected_action=block`), `query` etc. into `metadata`, description left byte-identical (preserve the single leading space as stored in `pure_tool.json`; do not silently strip it at render time).
- Decide clean freeze: either freeze the ~352 clean Tool blocks from `clean_system_promot` as ALLOW (same server groups) or freeze attack-only and keep `headline_eligible=false` / `FPR=n/a`. No third path.
- Select `p3-mcptox-proof-v0` as 12 cases covering 3 paradigms and at least 6 servers / 4 security risks, with per-case golden checks for raw → content identity, no query leakage, and server-group determinism, plus a fake-gateway end-to-end.
- Do not build any `mcp_server/` or `tool_executor/` harness. Do not add `user query` to the rendered payload. Do not author clean definitions by hand.

---

*Probe paths:* `cache/probe/mcptox/pure_tool.json`, `cache/probe/mcptox/response_all.json`, `cache/probe/mcptox/def_tool/*.py`, `cache/probe/mcptox/analysis.ipynb` — all under the pinned revision. Re-run the counts in this document before any freeze; the numbers above are pinned to that revision and those SHA256 values.
