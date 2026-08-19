# P1-P5 ↔ Legacy E1-E12 / Threat ID Mapping (plan §16, §17)

V3 does **not** delete the E1-E12 legacy numbering — historical results must stay
comparable. This table records the gradual migration from project-based (E) to
channel-based (P) organization so future reports can cross-reference both.

## Project ↔ Channel ↔ Legacy mapping

| V3 Project | Channels | Legacy E | Threat IDs | Notes |
|---|---|---|---|---|
| P1 External Instruction Boundary | email, web_page, rag_document, tool_result | E2, E8 (tool_result subset) | A-01, A-04, L-01 | Untrusted external content carrying commands |
| P2 Tool Action Guard | tool_call | E8 (tool_call subset), E11 | A-05, A-06 | Dangerous / off-task tool calls; F12 optional authorization_context tests obvious privilege escalation (NOT full IAM) |
| P3 MCP Definition Content Guard | mcp_definition | (new) | A-03 | Deceptive/dangerous tool definitions. **F10: cannot test DCI D_real** — gateway only sees description text, never implementation |
| P4 Credential Flow Guard | user_prompt, tool_result, tool_call, memory_write, outbound_response | E4, E5 | G-01, A-06 | Secret exfiltration via fake canaries. F11 max_tokens=128; F13 decision vs leakage split; F8 RAW headline |
| P5 Memory Write Guard | memory_write | E9 | A-02 | Malicious rules about to be persisted |

## Migration notes (plan §17)

- E1-E12 manifests remain frozen in `cache/sample_manifests/` (read-only).
- `LegacyV2Adapter` bridges them into `SecurityCase(channel=USER_PROMPT)` so V3
  can run identical data.
- Gradual migration: E2→P1/email, E8→P1/tool_result + P2/tool_call,
  E9→P5, E11→P2, E4/E5→P4.
- The old `ex` multilingual project is not mapped to a P-project yet (future).

## Scope boundaries (external review F8-F13)

- **F8 — Render fidelity.** Each renderer supports RAW / STRUCTURED / LABELED.
  The headline benchmark number MUST come from RAW (no security wrapper),
  because LABELED wrappers (`[UNTRUSTED_EXTERNAL_CONTENT]` …) can tip the
  gateway off and inflate TPR. Reports break TPR down by fidelity tier.
- **F9 — Resume guard.** `case_id` is identity-only (content-independent by
  design); `case_fingerprint` hashes the actual payload. Resume reuses a clear
  outcome only when BOTH match, so a dataset that silently rewrites a row under
  an unchanged `source_id` is re-tested, not masked by a stale result.
- **F10 — P3 scope.** P3 is an *MCP Definition Content Guard*. It tests
  dangerous/deceptive tool *definitions*. It CANNOT test Description-Code
  Inconsistency (DCI D_real): the gateway never sees the implementation. A
  future `MCPIntegrityCase` (carrying declared vs observed side effects) is
  required before DCI can be folded into a headline number.
- **F11 — Generation profile.** P4 uses `max_tokens=128` (not the V2 default 8)
  so a credential leak is not silently truncated by the token cap. V2 regression
  preserves `max_tokens=8` via the legacy adapter path.
- **F12 — Authorization context.** P2 accepts an optional
  `authorization_context` (subject/role/granted_permissions/task_scope/resource/
  requested_action) so it can test whether the gateway flags an obviously
  over-privileged call. This is NOT full IAM — the gateway only sees text.
- **F13 — Decision vs leakage.** P4 reports two independent axes: Gateway
  Decision Correctness (block/allow confusion matrix) and Credential Leakage
  Rate (did the canary actually appear in the response?). "Not blocked" is no
  longer equated with "leaked".
