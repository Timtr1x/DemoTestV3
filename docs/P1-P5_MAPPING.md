# P1-P5 ↔ Legacy E1-E12 / Threat ID Mapping (plan §16, §17)

V3 does **not** delete the E1-E12 legacy numbering — historical results must stay
comparable. This table records the gradual migration from project-based (E) to
channel-based (P) organization so future reports can cross-reference both.

## Project ↔ Channel ↔ Legacy mapping

| V3 Project | Channels | Legacy E | Threat IDs | Notes |
|---|---|---|---|---|
| P1 External Instruction Boundary | email, web_page, rag_document, tool_result | E2, E8 (tool_result subset) | A-01, A-04, L-01 | Untrusted external content carrying commands |
| P2 Tool Action Guard | tool_call | E8 (tool_call subset), E11 | A-05, A-06 | Dangerous / off-task tool calls (not IAM correctness) |
| P3 MCP Definition Guard | mcp_definition | (new) | A-03 | Deceptive or dangerous tool definitions |
| P4 Credential Flow Guard | user_prompt, tool_result, tool_call, memory_write, outbound_response | E4, E5 | G-01, A-06 | Secret exfiltration via fake canaries |
| P5 Memory Write Guard | memory_write | E9 | A-02 | Malicious rules about to be persisted |

## Migration notes (plan §17)

- E1-E12 manifests remain frozen in `cache/sample_manifests/` (read-only).
- `LegacyV2Adapter` bridges them into `SecurityCase(channel=USER_PROMPT)` so V3
  can run identical data.
- Gradual migration: E2→P1/email, E8→P1/tool_result + P2/tool_call,
  E9→P5, E11→P2, E4/E5→P4.
- The old `ex` multilingual project is not mapped to a P-project yet (future).
