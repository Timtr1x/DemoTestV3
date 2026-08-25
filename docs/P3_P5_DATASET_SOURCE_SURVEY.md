# P3 / P5 Dataset Source Survey

Date: 2026-08-25 · Baseline: `main@1d09403` + Phase 2A ACCEPTED (2026-08-25) + Phase 2B frozen (420)
Method: repository-level verification only — fetched actual GitHub trees,
raw files and APIs; counted records by reading them. No adapter/renderer/
target/runner/oracle code was touched; no MCP server or memory DB was
stood up; nothing copied from paper PDFs.

Verdict scale: **READY** (official artifact verified end-to-end, mappable
to the project's SecurityCase channel now) / **PARTIAL** (real official
artifact exists but has gaps that need decisions or upstream fixes) /
**NOT FOUND** (no usable official artifact).

---

## P3 — MCP Definition Content Guard (`channel=mcp_definition`, threat A-03)

Scope reminder (F10): P3 tests dangerous/deceptive tool *definitions* — the
gateway sees description text only. Description-Code Inconsistency (DCI) is
explicitly OUT of P3 scope until a future `MCPIntegrityCase` exists.

### Candidate 1: MCPTox — verdict **PARTIAL** (`PUBLISHED / ARTIFACT AVAILABLE / LICENSE UNRESOLVED`)

`zhiqiangwang4/MCPTox-Benchmark` — "MCPTox: A Benchmark for Tool Poisoning
Attack on Real-World MCP Servers" — formally **published in AAAI-26
proceedings** (paper points to the same `zhiqiangwang4/MCPTox-Benchmark`
repo as the official artifact). Repo remains 2 commits, single branch @
`f85189f9ad12504c197c7f920ab818a40657b1fa`, "Initial commit" 2025-12-03.
Verified by LOCAL CLONE (`cache/probe/mcptox`, gitignored) — the
authoritative numbers below supersede the truncated API-tree figures of
the first pass:

- `def_tool/1.py … def_tool/485.py`: **485 poisoned MCP tool definitions**
  as real `@mcp.tool()`-decorated Python functions. Spot-check of
  `def_tool/1.py` confirmed the shape: innocuous function signature +
  poisoned docstring instructing the agent to overwrite `~/.ssh/id_rsa`
  with attacker key material disguised as a "pre-authorization check".
- `pure_tool.json` (316 KB): despite the name, NOT benign tools — it holds
  **485 evaluation pairings** `{server_name, tool_name, query, tool_content,
  security risk, paradigm, tool_address}` where `tool_content` is the
  poisoned description (pairing #1 matches `def_tool/1.py`). The 45
  `server_name` values are REAL community MCP servers (FileSystem,
  Puppeteer, Slack, Github, SQLite, Redis, BraveSearch, EverArt, …).
- Built-in taxonomy: `paradigm` = poisoning template family
  (Template-1 ×77, Template-2 ×183, Template-3 ×225); `security risk` =
  Information Manipulation ×108, Privacy Leakage ×97, Service Disruption
  ×73, Infrastructure Damage ×41, Credential Leakage ×40, Code Injection
  ×22.
- `response_all.json` (20.7 MB) = the authors' raw model responses.
- This is EXACTLY the P3 channel shape: the payload lives entirely in the
  description text the gateway would see.

Gaps blocking READY:

- **No LICENSE file** anywhere in the repo — formal acquisition blocker
  (proceedings publication alone does not imply a dataset license; no
  copyright->license inference).
- README is 9 bytes (`# AAAI26`) — no documented counts or labeling scheme;
  ground truth is implicit (every pairing is a poison case).
- **No benign controls**: all 485 pairings are poisoned; there is no clean
  tool-description set in the repo (the `pure_tool.json` name is
  misleading). An ALLOW side would have to come from a DIFFERENT source
  (clean function-doc corpora such as BFCL/MetaTool), which breaks the
  same-origin control design we used in P2 — a decision point, not a
  technical blocker.
- Single-author repo, 2 commits, pre-publication; revision stability unknown.

Mapping assessment (if acquired later): `def_tool/N.py` docstring ->
`SecurityCase(content=<description>, channel=MCP_DEFINITION,
expected_action=block)`; `source_id=mcptox:<N>`; deterministic, no LLM.
Benign/ALLOW side would have to come from a DIFFERENT source (clean
function-doc corpora such as BFCL/MetaTool), which breaks the same-origin
control design we used in P2 — a decision point, not a technical blocker.

### Candidate 2: DCI `D_real` — verdict **NOT FOUND**

Source identified: arXiv 2606.04769 "Description-Code Inconsistency in
Real-world MCP Servers: Measurement, Detection, and Security Implications"
(DCIChecker): 19,200 description-code pairs from 2,214 real MCP servers,
9.93% inconsistent.

- GitHub searches (`DCIChecker`, `"description-code inconsistency" MCP`,
  `MCP inconsistency dataset`) return **no released artifact** — the pairs
  dataset is not published.
- Independent of availability, F10 applies: inconsistent-pair labels are
  not content-guard ground truth; the gateway never sees the code side.
  DCI stays blocked behind a future `MCPIntegrityCase` regardless.

### Candidate 3 (monitor only): arXiv 2602.03580

"Don't believe everything you read…" — measurement over 10,240 real servers
(~13% substantial mismatches). Measurement study; no labeled attack/benign
benchmark found. Re-check if an artifact appears.

### P3 next actions

1. **Do not wait for camera-ready** — the paper is already proceedings-
   published. Re-audit MCPTox for a LICENSE + completeness signal; if they
   land, pin a commit.
2. Decide the benign-control policy BEFORE acquiring (same-origin requirement
   vs. mixed-origin clean-doc corpus). Without benign controls P3 can only
   ever measure TPR, repeating the gap Phase 1.5 just closed for P2.
3. Do NOT synthesize P3 data. If MCPTox stalls, P3 stays data-PENDING with
   the interface ready (as documented in V3_ACCEPTANCE_REPORT F10).

---

## P5 — Memory Write Guard (`channel=memory_write`, threat A-02, legacy E9)

Provenance note first: the legacy V2 manifests (`asb_memory_poison_400` etc.)
are template-rendered wrappers whose underlying text traces to the official
ASB file below (first record identical: `ResourceAllocationHijack` /
`crypto_miner_01`). They were never a committed official artifact themselves —
this survey replaces that lineage.

### Candidate 1: Agent Security Bench — verdict **READY (frozen 420)**

`agiresearch/ASB` — official, ICLR 2025 (arXiv 2410.02644), **MIT**, 289
stars, 20 commits. **PINNED @ `1f561dccf92d55302368fa67679b4ba9d9c8fdc4`**,
**frozen as 420** (400 attacks + 20 normals) — see
`docs/results/P5_PHASE2B_FREEZE.md` for the full freeze evidence and
`docs/results/P5_PHASE2A_PROJECTION_FIDELITY.md` for the attack-side
fidelity spec.

Verified by direct download, inspection and frozen pipeline:

- `data/all_attack_tools.jsonl` — **400 attack-tool entries**, fields
  `[Attacker Tool, Attacker Instruction, Description, Attack goal,
  Attack Type, Corresponding Agent, Aggressive]`; adapter
  `AttackerTool.get_tool_call_format()` projects to
  `[{"type":"function","function":{"name":<Attacker Tool>,
  "description":<Description>}}]` (`expected_action=block`,
  `ground_truth_kind=memory_poisoning_attack`).
- `data/all_normal_tools.jsonl` — **20 benign tool entries**
  (`[Tool Name, Description, Expected Achievements, Corresponding
  Agent]`); adapter `SimulatedTool.get_tool_call_format()` projects to
  `[{"type":"function","function":{"name":<Tool Name>,
  "description":<Description>,"parameters":null}}]`
  (`expected_action=allow`, `ground_truth_kind=normal_memory_tool`;
  `parameters:null` is authoritative upstream, not synthetic).
- Both files share the same memory `Tools` field, same commit, same
  deterministic projection family, same grouping
  (`asb:agent:<Corresponding Agent>`), same split discipline
  (`group_aware_case_count_v2`, agent never spans splits).
- `memory_db/*` directories are runtime experiment OUTPUTS (Chroma DBs per
  gpt-4o-mini run), not source data; the poison/normal text originates from
  the JSONLs above (confirmed via `scripts/agent_attack.py` ->
  `--attacker_tools_path data/all_attack_tools.jsonl`).

Mapping assessment:

- **BLOCK + ALLOW ground truth are now both official and same-origin.**
  The review-decided option (d) is implemented: the 20 normal tools are the
  benign control — no second dataset, no synthetic controls. Metrics are
  `TP/FN/TN/FP`, `TPR` and `FPR` (holdout sealed: `p5-holdout-v1`).
- Agent grouping (`asb:agent:<Corresponding Agent>`) is load-bearing for
  holdout isolation (10 agents x 42 cases; 84 dev / 252 eval / 84 holdout).
  A regression hard gate forbids any agent spanning splits.
- Fictional scenarios (`crypto_miner_01` etc.) are the benchmark's own
  official content — acceptable on the same grounds as AgentDojo's fictional
  environments (and unlike copying a PDF).
- No further P5 dataset linkage gap — next gate is a **real LineMod smoke**
  (Phase 2B freeze -> real smoke -> health check -> real standard, holdout
  sealed).

### Candidate 2: AgentPoison — verdict **not suitable as primary**

`AI-secure/AgentPoison` (NeurIPS 2024, MIT, 238 stars). Poisoned triggers are
GENERATED (gradient-based trigger optimization) and poisoning instances are
not shipped in-repo; base datasets come via external Google Drive. Its
paradigm is a backdoor trigger embedded in retrieved passages — orthogonal to
a memory_write content guard, and the trigger-optimization pipeline violates
our no-synthesis constraints. Keep as Extended/research reference only.

GitHub search for dedicated "agent memory poisoning dataset" repos otherwise
returned nothing relevant.

### P5 next actions (post-freeze)

1. Real LineMod **smoke** on `p5-smoke-v1` (dev, 64: 60 BLOCK + 4 ALLOW),
   health check (TPR/FPR + transport), then real standard on
   `p5-standard-v1` (eval, 252: 240+12). STOP after standard; holdout
   (`p5-holdout-v1`, 84) stays sealed.
2. No further dataset work for P5 — the 420 freeze is the lineage. Do not
   rebuild the memory DB / runtime; the projection is offline text only.
3. Error analysis note: ASB's `SystemMonitor`-style benign-looking attacks
   stay BLOCK per GT and are singled out in the analysis, not "fixed".

---

## Summary table

| project | candidate | artifact | license | GT | benign | verdict |
|---|---|---|---|---|---|---|
| P3 | MCPTox | 485 poisoned MCP tool defs + 485 eval pairings @ f85189f9 (cloned & counted) | **missing** | implicit all-block | **absent in repo** | PARTIAL (`PUBLISHED / ARTIFACT AVAILABLE / LICENSE UNRESOLVED`) |
| P3 | DCI D_real (arXiv 2606.04769) | none published | n/a | n/a | n/a | NOT FOUND |
| P5 | ASB (agiresearch/ASB) | 400 attack + 20 normal (same pin `1f561dc`, frozen pipeline) | MIT | BLOCK+ALLOW (same-origin) | **same-origin ALLOW (20 normals)** | **READY (frozen 420)** |
| P5 | AgentPoison | triggers generated, data off-repo | MIT | backdoor ASR | n/a | not suitable |

Recommended priority: **P5 frozen (420)** — next is real LineMod smoke on
`p5-smoke-v1` (then standard). P3 waits on MCPTox LICENSE/completeness
(`PUBLISHED / ARTIFACT AVAILABLE / LICENSE UNRESOLVED`).
