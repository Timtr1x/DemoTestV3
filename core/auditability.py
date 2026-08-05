"""T8 审计日志完备性 — 产品功能核验（非数据集、不占 E 编号）。

WASP/ASI Threats T8（抵赖与不可追溯）：测的是「日志记没记全」，
不是模型/规则 TPR。企业 ASI 审计会直接查这些字段。

本模块提供：
1. 标准 checklist 定义（合格标准）
2. 用测试侧 ResultRecord / jsonl **反向核验**「应具备的字段是否齐全」
3. 产品侧专属项（防篡改、留存导出）标记为 manual / unknown

可选烟雾：对已有结果 jsonl 抽最多 20 条做字段完备性装样子核验。
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

# ResultRecord 字段 ↔ 审计侧期望（测试框架可自动核验的部分）
RESULT_AUDIT_FIELDS = (
    "sample_id",
    "manifest_name",
    "run_version",
    "http_status",
    "outcome",
    "security_flag",
    "latency_ms",
    "attempts",
    "ts",
)

# 产品日志侧推荐字段（与 ResultRecord 对齐 + 企业扩展）
PRODUCT_LOG_RECOMMENDED = (
    "timestamp",
    "tenant_id",
    "prompt_hash",  # 非明文
    "decision",  # blocked/passed/...
    "rule_name",  # 命中规则
    "rationale",  # 判定依据
    "latency_ms",
    "request_id",  # 可回放关联
)


@dataclass
class ChecklistItem:
    id: str
    title: str
    criterion: str
    status: str  # pass | fail | partial | manual | n_a
    evidence: str = ""
    auto: bool = True  # False = 需人工/产品侧核验


@dataclass
class AuditabilityReport:
    """T8 可审计性核验结果。"""

    items: list[ChecklistItem] = field(default_factory=list)
    n_records_checked: int = 0
    n_records_total: int = 0
    field_coverage: dict[str, float] = field(default_factory=dict)
    overall: str = "N/A"  # PASS | FAIL | PARTIAL | MANUAL
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall": self.overall,
            "n_records_checked": self.n_records_checked,
            "n_records_total": self.n_records_total,
            "field_coverage": dict(self.field_coverage),
            "items": [
                {
                    "id": i.id,
                    "title": i.title,
                    "criterion": i.criterion,
                    "status": i.status,
                    "evidence": i.evidence,
                    "auto": i.auto,
                }
                for i in self.items
            ],
            "notes": list(self.notes),
        }


def prompt_hash(prompt_text: str, *, algo: str = "sha256") -> str:
    """日志应用哈希而非明文 prompt，避免日志本身成为泄漏源。"""
    h = hashlib.new(algo)
    h.update((prompt_text or "").encode("utf-8", errors="replace"))
    return f"{algo}:{h.hexdigest()[:16]}"


def _nonempty(v: Any) -> bool:
    if v is None:
        return False
    if isinstance(v, str) and not v.strip():
        return False
    return True


def evaluate_result_records(
    rows: Sequence[dict[str, Any]],
    *,
    max_check: int = 20,
    require_security_flag_on_block: bool = True,
) -> AuditabilityReport:
    """从测试 jsonl / ResultRecord 字典列表做 T8 字段完备性核验。

    max_check: 装样子抽检上限（默认 20）；0 = 全量。
    """
    rep = AuditabilityReport()
    rep.n_records_total = len(rows)
    if not rows:
        rep.notes.append("无结果记录：无法自动核验字段完备性（请先 run 或提供产品日志导出）")
        rep.items = _static_checklist(has_data=False)
        rep.overall = "MANUAL"
        return rep

    sample = list(rows[: max_check if max_check and max_check > 0 else len(rows)])
    rep.n_records_checked = len(sample)

    # per-field coverage
    coverage: dict[str, int] = {f: 0 for f in RESULT_AUDIT_FIELDS}
    missing_examples: dict[str, str] = {}
    block_without_flag = 0
    block_total = 0

    for r in sample:
        for f in RESULT_AUDIT_FIELDS:
            if _nonempty(r.get(f)):
                coverage[f] += 1
            elif f not in missing_examples:
                missing_examples[f] = str(r.get("sample_id") or "?")
        if r.get("outcome") == "blocked":
            block_total += 1
            if not _nonempty(r.get("security_flag")):
                block_without_flag += 1

    n = len(sample)
    rep.field_coverage = {f: (coverage[f] / n if n else 0.0) for f in RESULT_AUDIT_FIELDS}

    items: list[ChecklistItem] = []

    # 1. 完整记录
    required = ("sample_id", "ts", "outcome", "latency_ms", "run_version")
    req_ok = all(rep.field_coverage.get(f, 0) >= 1.0 for f in required)
    miss = [f for f in required if rep.field_coverage.get(f, 0) < 1.0]
    items.append(
        ChecklistItem(
            id="T8-R1",
            title="每条请求是否有完整记录",
            criterion="时间戳、关联 ID、判定结果、延迟、运行版本齐全",
            status="pass" if req_ok else "fail",
            evidence=(
                f"checked={n}/{rep.n_records_total}; "
                + (
                    "required fields 100%"
                    if req_ok
                    else f"missing/partial: {miss}; e.g. sample={missing_examples.get(miss[0] if miss else '', '')}"
                )
            ),
            auto=True,
        )
    )

    # 2. 命中规则可归因
    flag_cov = rep.field_coverage.get("security_flag", 0.0)
    if require_security_flag_on_block and block_total:
        flag_ok = block_without_flag == 0
        items.append(
            ChecklistItem(
                id="T8-R2",
                title="拦截事件是否带命中规则名",
                criterion="outcome=blocked 时 security_flag / rule_name 非空",
                status="pass" if flag_ok else "fail",
                evidence=f"blocked={block_total}, missing_flag={block_without_flag}",
                auto=True,
            )
        )
    else:
        items.append(
            ChecklistItem(
                id="T8-R2",
                title="拦截事件是否带命中规则名",
                criterion="outcome=blocked 时 security_flag / rule_name 非空",
                status="partial" if flag_cov > 0 else "n_a",
                evidence=f"security_flag coverage={flag_cov:.0%} (no blocked in sample)"
                if not block_total
                else f"coverage={flag_cov:.0%}",
                auto=True,
            )
        )

    # 3. 可回放（sample_id + run_version + manifest）
    replay_ok = all(
        rep.field_coverage.get(f, 0) >= 1.0
        for f in ("sample_id", "manifest_name", "run_version")
    )
    items.append(
        ChecklistItem(
            id="T8-R3",
            title="拦截事件是否可回放",
            criterion="凭 sample_id + manifest + run_version 能还原当时判定",
            status="pass" if replay_ok else "fail",
            evidence="sample_id/manifest_name/run_version present"
            if replay_ok
            else "缺关联字段",
            auto=True,
        )
    )

    # 4. prompt 不以明文进日志（测试侧我们存 manifest 外的明文；产品侧应 hash）
    items.append(
        ChecklistItem(
            id="T8-R4",
            title="日志是否避免 prompt 明文",
            criterion="存 prompt_hash（如 sha256 前缀），不落全文",
            status="manual",
            evidence=(
                "测试框架 ResultRecord 不落 prompt 明文（合格样板）；"
                "产品日志需人工确认是否使用 hash。"
                f" 参考: {prompt_hash('example-prompt')}"
            ),
            auto=False,
        )
    )

    # 5–7 产品侧
    items.append(
        ChecklistItem(
            id="T8-R5",
            title="租户 / 多租户隔离字段",
            criterion="每条记录含 tenant_id（或等价组织 ID）",
            status="manual",
            evidence="ResultRecord 无 tenant_id：产品侧扩展字段，需对接后核验",
            auto=False,
        )
    )
    items.append(
        ChecklistItem(
            id="T8-R6",
            title="日志防篡改",
            criterion="追加式存储 / 哈希链；运维不能静默删改",
            status="manual",
            evidence="需查产品存储与权限模型（WORM / 审计角色分离）",
            auto=False,
        )
    )
    items.append(
        ChecklistItem(
            id="T8-R7",
            title="留存与导出",
            criterion="满足企业合规留存期，可导出供 ASI 审计",
            status="manual",
            evidence="需查产品留存策略与导出 API",
            auto=False,
        )
    )

    rep.items = items
    auto = [i for i in items if i.auto]
    if not auto:
        rep.overall = "MANUAL"
    elif any(i.status == "fail" for i in auto):
        rep.overall = "FAIL"
    elif all(i.status == "pass" for i in auto):
        # 仍有 manual 项
        rep.overall = "PARTIAL" if any(i.status == "manual" for i in items) else "PASS"
    else:
        rep.overall = "PARTIAL"

    rep.notes.append(
        "T8 不是数据集测试：自动项仅核验测试侧/导出日志字段完备性；"
        "防篡改与留存须产品侧人工确认。"
    )
    rep.notes.append(
        "WASP ASI 映射：T8 抵赖与不可追溯；网关相对应用内护栏的差异化卖点是全局流量可审计。"
    )
    return rep


def _static_checklist(*, has_data: bool) -> list[ChecklistItem]:
    base = evaluate_result_records(
        [
            {
                "sample_id": "demo:0",
                "manifest_name": "demo",
                "run_version": "demo",
                "http_status": 403,
                "outcome": "blocked",
                "security_flag": "SECURITY_BLOCKED",
                "latency_ms": 12,
                "attempts": 1,
                "ts": "2026-01-01T00:00:00Z",
            }
        ]
        if not has_data
        else [],
        max_check=1,
    )
    # when no data, force first items to n_a
    if not has_data:
        return [
            ChecklistItem(
                id="T8-R1",
                title="每条请求是否有完整记录",
                criterion="时间戳、租户 ID、prompt 哈希、判定结果、命中规则、延迟",
                status="n_a",
                evidence="无结果 jsonl，跳过自动核验",
                auto=True,
            ),
            ChecklistItem(
                id="T8-R2",
                title="拦截事件是否带命中规则名",
                criterion="blocked 时 security_flag 非空",
                status="n_a",
                evidence="无结果",
                auto=True,
            ),
            ChecklistItem(
                id="T8-R3",
                title="拦截事件是否可回放",
                criterion="sample_id + run_version 可还原",
                status="n_a",
                evidence="无结果",
                auto=True,
            ),
            ChecklistItem(
                id="T8-R4",
                title="日志是否避免 prompt 明文",
                criterion="prompt_hash 而非全文",
                status="manual",
                evidence="产品侧确认",
                auto=False,
            ),
            ChecklistItem(
                id="T8-R5",
                title="租户字段",
                criterion="tenant_id",
                status="manual",
                evidence="产品侧确认",
                auto=False,
            ),
            ChecklistItem(
                id="T8-R6",
                title="日志防篡改",
                criterion="追加式 / 哈希链",
                status="manual",
                evidence="产品侧确认",
                auto=False,
            ),
            ChecklistItem(
                id="T8-R7",
                title="留存与导出",
                criterion="合规留存 + 可导出",
                status="manual",
                evidence="产品侧确认",
                auto=False,
            ),
        ]
    return base.items


def load_result_rows(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def render_auditability_markdown(rep: AuditabilityReport) -> str:
    lines = [
        "## 可审计性（T8 / ASI 抵赖与不可追溯）",
        "",
        "> 非数据集测试、不占 E 编号。自动项用 ResultRecord 字段反向核验；"
        "防篡改/留存/租户等为产品侧人工项。",
        "",
        f"- 总体：`{rep.overall}`",
        f"- 抽检记录：`{rep.n_records_checked}/{rep.n_records_total}`（上限 20 装样子）",
        "",
        "| ID | 核验项 | 状态 | 合格标准 | 证据 |",
        "|----|--------|------|----------|------|",
    ]
    for i in rep.items:
        crit = i.criterion.replace("|", "\\|")
        ev = (i.evidence or "").replace("|", "\\|").replace("\n", " ")
        lines.append(
            f"| `{i.id}` | {i.title} | **{i.status}** | {crit} | {ev} |"
        )
    if rep.field_coverage:
        lines.append("")
        lines.append("### ResultRecord 字段覆盖率（抽检）")
        lines.append("")
        for f, c in sorted(rep.field_coverage.items()):
            lines.append(f"- `{f}`: {c:.0%}")
    if rep.notes:
        lines.append("")
        lines.append("### 说明")
        lines.append("")
        for n in rep.notes:
            lines.append(f"- {n}")
    lines.append("")
    return "\n".join(lines)


def evaluate_results_path(path: Path, *, max_check: int = 20) -> AuditabilityReport:
    return evaluate_result_records(load_result_rows(path), max_check=max_check)
