# P3 / P5 Dataset Source Survey (investigation-only round)

Date: 2026-08-24 · Baseline: `main@1e70bea` (Phase 1.5 ACCEPTED)
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

### Candidate 1: MCPTox — verdict **PARTIAL**

`zhiqiangwang4/MCPTox-Benchmark` — "MCPTox: A Benchmark for Tool Poisoning
Attack on Real-World MCP Servers" (README header says AAAI26; 11 stars,
2 commits, single branch @ `f85189f9`).

Verified by direct inspection:

- `def_tool/1.py … def_tool/477.py`: **477 poisoned MCP tool definitions**
  as real `@mcp.tool()`-decorated Python functions. Spot-check of
  `def_tool/1.py` confirmed the shape: innocuous function signature +
  poisoned docstring instructing the agent to overwrite `~/.ssh/id_rsa`
  with attacker key material disguised as a "pre-authorization check".
- This is EXACTLY the P3 channel shape: the payload lives entirely in the
  description text the gateway would see.

Gaps blocking READY:

- **No LICENSE file** anywhere in the repo — formal acquisition blocker.
- README is 9 bytes (`# AAAI26`) — no documented counts, taxonomy, or
  labeling scheme; ground truth is implicit (every file is a poison case).
- The benign counterpart `pure_tool.json` and `analysis.ipynb`'s inputs are
  referenced by name but `pure_tool.json` / `response_all.json` are absent
  from the main tree — i.e. **no benign controls shipped**.
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

1. Watch MCPTox through AAAI26 camera-ready: if a LICENSE + complete data
   (including benign set) land, re-audit and pin a commit.
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

### Candidate 1: Agent Security Bench — verdict **PARTIAL** (closest to READY)

`agiresearch/ASB` — official, ICLR 2025 (arXiv 2410.02644), **MIT**, 289
stars, 20 commits.

Verified by direct download and inspection:

- `data/all_attack_tools.jsonl` — **400 attack-tool entries**, fields
  `[Attacker Tool, Attacker Instruction, Description, Attack goal,
  Attack Type, Corresponding Agent, Aggressive]`; ~200 aggressive /
  ~200 non-aggressive (per sibling file sizes 105,518 / 104,118 B).
  These are the plans ASB's Memory-Poisoning scenario injects into the
  agent's memory DB at runtime.
- `data/all_normal_tools.jsonl` — **20 benign tool entries** (`[Tool Name,
  Description, Expected Achievements, Corresponding Agent]`).
- `memory_db/*` directories are runtime experiment OUTPUTS (Chroma DBs per
  gpt-4o-mini run), not source data; the poison text originates from the
  JSONL above (confirmed via `scripts/agent_attack.py` ->
  `--attacker_tools_path data/all_attack_tools.jsonl`).

Mapping assessment:

- BLOCK side maps cleanly: each entry's `Attacker Instruction` +
  `Description` is the malicious rule about to be persisted ->
  `SecurityCase(content=<instruction+description>, channel=MEMORY_WRITE,
  expected_action=block, quality_tier=B, derivation=deterministic_projection)`,
  `source_id=asb:mp:<n>`. Deterministic; no LLM; no runtime needed.
- Fictional scenarios (`crypto_miner_01` etc.) are the benchmark's own
  official content — acceptable on the same grounds as AgentDojo's fictional
  environments (and unlike copying a PDF).
- GAP (why not READY): **benign memory-write controls do not exist in ASB.**
  The 20 normal tools are tool definitions, not memories; projecting them as
  ALLOW memory-writes would fabricate a semantic. Options: (a) ship P5 with
  TPR-only and a documented no-FPR caveat (repeating the old P2 gap),
  (b) derive benign memory-writes deterministically from another official
  source (decision point), or (c) wait/ask upstream.

### Candidate 2: AgentPoison — verdict **not suitable as primary**

`AI-secure/AgentPoison` (NeurIPS 2024, MIT, 238 stars). Poisoned triggers are
GENERATED (gradient-based trigger optimization) and poisoning instances are
not shipped in-repo; base datasets come via external Google Drive. Its
paradigm is a backdoor trigger embedded in retrieved passages — orthogonal to
a memory_write content guard, and the trigger-optimization pipeline violates
our no-synthesis constraints. Keep as Extended/research reference only.

GitHub search for dedicated "agent memory poisoning dataset" repos otherwise
returned nothing relevant.

### P5 next actions

1. Acquire `agiresearch/ASB` at a pinned commit (MIT allows it), write the
   lock, project the 400 BLOCK cases — this alone unblocks E9->P5 attack
   coverage with a real official lineage.
2. Decide the benign-control option (a)/(b)/(c) above before any manifest
   claims FPR capability for P5.
3. Do not build the memory DB / runtime; the projection is offline text only.

---

## Summary table

| project | candidate | artifact | license | GT | benign | verdict |
|---|---|---|---|---|---|---|
| P3 | MCPTox | 477 poisoned MCP tool defs (verified) | **missing** | implicit all-block | **absent in repo** | PARTIAL |
| P3 | DCI D_real (arXiv 2606.04769) | none published | n/a | n/a | n/a | NOT FOUND |
| P5 | ASB (agiresearch/ASB) | 400 attack entries + 20 normal tools (downloaded & counted) | MIT | label=attack (all 400) | **no memory-write-shaped controls** | PARTIAL |
| P5 | AgentPoison | triggers generated, data off-repo | MIT | backdoor ASR | n/a | not suitable |

Recommended priority: **P5 first** (one commit-pin away from a real BLOCK
side; benign decision pending), P3 waits on MCPTox licensing/completeness.
