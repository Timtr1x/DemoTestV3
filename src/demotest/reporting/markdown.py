"""Markdown report renderer (plan §53)."""
from __future__ import annotations

from pathlib import Path

from ..analysis.analyzer import AnalysisReport


def _fmt(x: float | None) -> str:
    if x is None:
        return "n/a"
    return f"{x:.2%}"


def _fmt_num(x: float | None) -> str:
    if x is None:
        return "n/a"
    return f"{x:.4f}"


def render_markdown(rep: AnalysisReport) -> str:
    m = rep.metrics
    # Phase 2.1: hard isolation — extended track must not be mistaken for headline
    track = str(getattr(rep, "benchmark_track", "core") or "core").lower()
    eligible = bool(getattr(rep, "headline_eligible", track == "core"))
    track_label = "Extended Synthetic" if track == "extended" else ("Core" if track == "core" else track)
    if track == "extended":
        title_suffix = " — Extended Synthetic (non-headline)"
    elif not eligible:
        title_suffix = " — Non-headline"
    else:
        title_suffix = ""
    title = (rep.project or rep.manifest_name or "V3") + title_suffix
    # decorate project display name for extended
    display_track = f"benchmark_track=`{track}` headline_eligible=`{str(eligible).lower()}`"
    if track == "extended":
        display_track += " — ⚠️ Extended track excluded from overall headline"
    lines = [
        f"# {title} — Gateway Security Report",
        "",
        f"- {display_track}",
    ]
    if track == "extended":
        lines.append(
            "- ⚠️ 本报告为 Extended Synthetic（非 headline）：分数不计入 overall，仅作对照；"
            " headline 以 `credential_dynamic_traces` 的 Core (A/B) 为准"
        )
    lines += [
        f"- run: `{rep.run_id}` target: `{rep.target}` manifest: `{rep.manifest_name}`",
        f"- samples: n=`{m.n_judged}/{rep.n_total}` unjudged=`{m.n_unjudged}` "
        f"cooldown占比=`{_fmt(m.cooldown_share)}`",
        f"- 混淆矩阵: TP=`{m.tp}` FP=`{m.fp}` TN=`{m.tn}` FN=`{m.fn}`",
        f"- 总指标: TPR=`{_fmt(m.tpr)}` FPR=`{_fmt(m.fpr)}` block_rate=`{_fmt(m.block_rate)}`",
    ]
    if m.canary_echo_den:
        lines.append(
            f"- canary泄露: `{m.canary_echo_num}/{m.canary_echo_den}` (rate=`{_fmt(m.canary_echo_rate)}`)"
        )
    # F13: decision correctness and credential leakage reported separately.
    if m.leakage_n_judged:
        lines.append(
            f"- 凭证泄露轴(F13): judged=`{m.leakage_n_judged}` leakage_rate=`{_fmt(m.leakage_rate)}` "
            f"(决策正确率与泄露率分开，不把\"未拦截\"等同于\"已泄露\")"
        )
    lines.append(f"- 延迟: p50=`{m.latency_p50}`ms p95=`{m.latency_p95}`ms")

    if rep.thresholds:
        parts = [f"{k}={v}" for k, v in rep.thresholds.items()]
        lines.append(f"- 合格线: {', '.join(parts)} → **{rep.pass_fail}**")
    else:
        lines.append(f"- 合格线判定: → **{rep.pass_fail}**")

    # Channel breakdown (plan §32)
    if m.by_channel:
        lines += ["", "## 按 Channel 分 TPR (plan §32)", "",
                  "| channel | n | TP | FN | TPR |", "|---|---:|---:|---:|---:|"]
        for ch, g in sorted(m.by_channel.items()):
            lines.append(f"| {ch} | {g['n_judged']} | {g['tp']} | {g['fn']} | {_fmt(g['tpr'])} |")

    # Scanner breakdown (plan §33)
    if m.by_scanner:
        lines += ["", "## 按 Scanner 分 (plan §33)", "",
                  "| scanner | n | TP | TPR |", "|---|---:|---:|---:|"]
        for sc, g in sorted(m.by_scanner.items()):
            lines.append(f"| {sc} | {g['n_judged']} | {g['tp']} | {_fmt(g['tpr'])} |")

    # Style breakdown (plan §35)
    if m.by_style:
        lines += ["", "## 按 Presentation Style 分 (plan §35)", "",
                  "| style | n | TP | FN | TPR |", "|---|---:|---:|---:|---:|"]
        for st, g in sorted(m.by_style.items()):
            lines.append(f"| {st} | {g['n_judged']} | {g['tp']} | {g['fn']} | {_fmt(g['tpr'])} |")

    # Fidelity breakdown (F8) — RAW must be the headline; LABELED is enhancement.
    if m.by_fidelity:
        lines += ["", "## 按 Render Fidelity 分 (F8)", "",
                  "> RAW=主分（无安全标签，最接近真实流量）；STRUCTURED=真实传输信封；",
                  "> LABELED=显式安全标签（增强实验，不得作为头条分数）。", "",
                  "| fidelity | n | TP | FN | TPR |", "|---|---:|---:|---:|---:|"]
        # RAW first, then STRUCTURED, then LABELED
        order = ["raw", "structured", "labeled"]
        keys = sorted(m.by_fidelity.keys(), key=lambda k: order.index(k) if k in order else 99)
        for fi, g in [(k, m.by_fidelity[k]) for k in keys]:
            lines.append(f"| {fi} | {g['n_judged']} | {g['tp']} | {g['fn']} | {_fmt(g['tpr'])} |")

    # Score distribution (plan §34)
    if m.score_distribution and any(v is not None for v in m.score_distribution.values()):
        lines += ["", "## Score 分布 (plan §34)", ""]
        for k in ("min", "p10", "p25", "p50", "p75", "p90", "max"):
            v = m.score_distribution.get(k)
            lines.append(f"- {k}: {_fmt_num(v)}")

    if rep.caveats:
        lines += ["", "## 口径声明", ""]
        for c in rep.caveats:
            lines.append(f"- {c}")

    lines += ["", "## 与上版本 diff", "",
              "- （样本集不变时才允许直接比；本报告未自动加载上一版）", ""]
    return "\n".join(lines)


def write_markdown(rep: AnalysisReport, out_dir: Path, *, filename: str = "SUMMARY.md") -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / filename
    path.write_text(render_markdown(rep), encoding="utf-8")
    return path
