"""Render SUMMARY.md from analyzer Report."""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.analyzer import Report
from paths import RESULTS_DIR


def _fmt_rate(x: float | None) -> str:
    if x is None:
        return "n/a"
    return f"{x:.2%}"


def render_summary(rep: Report, *, date: str | None = None) -> str:
    d = date or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    m = rep.metrics
    title = rep.project or rep.manifest_name
    lines = [
        f"# {title} 测试报告 — {rep.run_version or 'dev'} — {d}",
        "",
        f"- 样本：manifest=`{rep.manifest_name}` n=`{m.n_judged}/{m.n_total}` "
        f"unjudged=`{m.n_unjudged}` cooldown占比=`{_fmt_rate(m.cooldown_share)}`",
        f"- 总指标：TPR=`{_fmt_rate(m.tpr)}` FPR=`{_fmt_rate(m.fpr)}`",
    ]
    if m.oversize_reject_rate is not None:
        lines.append(
            f"- 超限正确拒绝率：`{_fmt_rate(m.oversize_reject_rate)}` "
            f"({m.oversize_reject_num}/{m.oversize_reject_den})"
        )
    if m.longdoc_fpr is not None:
        lines.append(
            f"- 长文档误拦：`{_fmt_rate(m.longdoc_fpr)}` "
            f"({m.longdoc_fpr_num}/{m.longdoc_fpr_den})"
        )
    if m.canary_echo_den > 0:
        lines.append(
            f"- canary回吐：`{m.canary_echo_num}/{m.canary_echo_den}` "
            f"(rate=`{_fmt_rate(m.canary_echo_rate)}`)"
        )
    lines.append(
        f"- 延迟：p50=`{m.latency_p50}` ms p95=`{m.latency_p95}` ms"
    )
    if rep.thresholds:
        th_parts = [f"{k}={v}" for k, v in rep.thresholds.items()]
        lines.append(f"- 合格线：{', '.join(th_parts)} → **{rep.pass_fail}**")
    else:
        lines.append(f"- 合格线判定：→ **{rep.pass_fail}**")

    if m.by_group:
        lines.append("")
        lines.append("## 分维度")
        lines.append("")
        lines.append("| group | n_judged | TPR | FPR |")
        lines.append("|---|---:|---:|---:|")
        for gkey, g in sorted(m.by_group.items()):
            lines.append(
                f"| {gkey} | {g['n_judged']} | {_fmt_rate(g['tpr'])} | {_fmt_rate(g['fpr'])} |"
            )

    if m.security_flag_counts:
        lines.append("")
        lines.append("## 命中规则分布 (security_flag)")
        lines.append("")
        for flag, cnt in list(m.security_flag_counts.items())[:20]:
            lines.append(f"- `{flag}`: {cnt}")

    if rep.caveats:
        lines.append("")
        lines.append("## 口径声明")
        lines.append("")
        for c in rep.caveats:
            lines.append(f"- {c}")

    lines.append("")
    lines.append("## 与上版本 diff")
    lines.append("")
    lines.append("- （样本集不变时才允许直接比；本报告未自动加载上一版）")
    lines.append("")
    return "\n".join(lines)


def write_summary(
    rep: Report,
    out_dir: Path,
    *,
    filename: str = "SUMMARY.md",
) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / filename
    path.write_text(render_summary(rep), encoding="utf-8")
    return path


def _cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m core.report")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--run-version", default="dev")
    args = parser.parse_args(argv)
    if args.all:
        print(f"Aggregate report placeholder for run_version={args.run_version}")
        print(f"Results root: {RESULTS_DIR}")
        return 0
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(_cli())
