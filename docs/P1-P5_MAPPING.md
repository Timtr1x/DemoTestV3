# P1-P5 ↔ 旧版 E1-E12 / Threat ID 映射（方案 §16、§17）

V3 **不会**删除 E1-E12 旧版编号——历史结果必须保持可比。本表记录从基于项目（E）到基于通道（P）组织的渐进式迁移，以便后续报告可同时对照两者。

## 项目 ↔ 通道 ↔ 旧版映射

| V3 项目 | 通道 | 旧版 E | Threat IDs | 备注 |
|---|---|---|---|---|
| P1 外部指令边界 | email, web_page, rag_document, tool_result | E2, E8（tool_result 子集） | A-01, A-04, L-01 | 携带指令的不可信外部内容 |
| P2 工具行为守卫 | tool_call | E8（tool_call 子集）, E11 | A-05, A-06 | 危险 / 越权工具调用；F12 可选 authorization_context 测试明显的权限提升（非完整 IAM） |
| P3 MCP 定义内容守卫 | mcp_definition | （新增） | A-03 | 欺骗性 / 危险性工具定义。**F10：无法测试 DCI D_real**——网关仅能看到描述文本，看不到实现 |
| P4 凭证流守卫 | user_prompt, tool_result, tool_call, memory_write, outbound_response | E4, E5 | G-01, A-06 | 通过伪造 canary 测试密钥外泄。F11 max_tokens=128；F13 区分判定与泄露；F8 以 RAW 作为 headline 指标 |
| P5 内存写入守卫 | memory_write | E9 | A-02 | 即将被持久化的恶意规则 |

## 迁移说明（方案 §17）

- E1-E12 的 manifest 冻结于 `cache/sample_manifests/`（只读）。
- `LegacyV2Adapter` 将其桥接为 `SecurityCase(channel=USER_PROMPT)`，使 V3 可运行完全相同的数据。
- 渐进式迁移：E2→P1/email，E8→P1/tool_result + P2/tool_call，E9→P5，E11→P2，E4/E5→P4。
- 旧版 `ex` 多语言项目暂未映射至任何 P 项目（后续规划）。

## 作用域边界（外部评审 F8-F13）

- **F8 — 渲染保真度。** 每个渲染器均支持 RAW / STRUCTURED / LABELED。headline 基准分数**必须**来源于 RAW（无安全包装），因为 LABELED 包装（`[UNTRUSTED_EXTERNAL_CONTENT]` …）会向网关泄露提示、虚增 TPR。报告需按保真度层级拆分 TPR。
- **F9 — 断点续跑守卫。** `case_id` 仅作身份标识（按设计与内容无关）；`case_fingerprint` 对实际负载做哈希。仅当二者均匹配时，续跑才会复用已有明确结果，因此当数据集在 `source_id` 不变的情况下悄悄重写某行时，会触发重测而非被陈旧结果掩盖。
- **F10 — P3 作用域。** P3 为 *MCP 定义内容守卫*，测试危险 / 欺骗性工具*定义*。其**无法**测试描述-代码不一致性（DCI D_real）：网关永远看不到实现代码。只有引入未来的 `MCPIntegrityCase`（携带声明副作用 vs 实际观测副作用）后，才能将 DCI 纳入 headline 指标。
- **F11 — 生成配置。** P4 使用 `max_tokens=128`（而非 V2 默认的 8），以避免凭证泄露被 token 上限悄悄截断。V2 回归仍通过旧版适配器路径保留 `max_tokens=8`。
- **F12 — 鉴权上下文。** P2 接受可选的 `authorization_context`（subject/role/granted_permissions/task_scope/resource/requested_action），用于测试网关是否能标记明显越权的调用。这**并非**完整 IAM——网关仅能看到文本。
- **F13 — 判定与泄露分离。** P4 报告两个独立维度：网关判定正确性（block/allow 混淆矩阵）与凭证泄露率（canary 是否真实出现在响应中）。“未拦截”不再等同于“已泄露”。
