"""demotest run — run cases against a target (plan §28, §29)."""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from ..cases import load_cases
from ..config import get_project, get_target
from ..core.ids import compute_run_id, config_hash, dataset_snapshot_hash
from ..paths import RESULTS_DIR
from ..renderers import get_renderer
from ..runtime import build_runner, build_target, resolve_renderer_name


def add_parser(sub) -> None:
    p = sub.add_parser("run", help="Run cases against a target")
    p.add_argument("--project", required=True)
    p.add_argument("--target", default="linemod")
    p.add_argument("--source", required=True)
    p.add_argument("--run-version", default=None)
    p.add_argument("--gap", type=float, default=0.5)
    p.add_argument("--dry-run", action="store_true",
                   help="render + validate + serialize but do NOT call the API")
    p.add_argument("--max-attempts", type=int, default=6)
    p.add_argument("--fidelity", default="auto",
                   choices=["auto", "raw", "structured", "labeled"],
                   help="render fidelity tier (F8): auto=project default, "
                        "raw=headline, structured=transport, labeled=enhancement")
    p.set_defaults(func=run)


def _resolve_fidelity(project, channel: str, requested: str) -> str:
    """Map 'auto' to the project's per-channel primary fidelity (review P0-3)."""
    if requested != "auto":
        return requested
    # per-channel primary fidelity: structured for channels where RAW drops
    # critical security context, raw otherwise (review P0-3)
    primary = getattr(project, "primary_fidelity", None) or {}
    if channel in primary:
        return primary[channel]
    # sensible defaults: tool_call/tool_result/mcp_definition/memory_write need
    # structured (raw drops args/schema); email/web/rag/user_prompt use raw
    defaults = {
        "tool_call": "structured",
        "tool_result": "structured",
        "mcp_definition": "structured",
        "memory_write": "structured",
        "email": "raw",
        "web_page": "raw",
        "rag_document": "raw",
        "user_prompt": "raw",
        "outbound_response": "raw",
    }
    return defaults.get(channel, "structured")


def run(args) -> int:
    project = get_project(args.project)
    tcfg = get_target(args.target)
    target = build_target(tcfg)
    cases = load_cases(args.source, project=args.project)

    # P0-1: enforce project ↔ channel ↔ case consistency BEFORE running.
    from ..cases import validate_cases_for_project
    validate_cases_for_project(cases, args.project, project.channels)

    # group cases by channel — each channel uses one renderer
    by_channel: dict[str, list] = defaultdict(list)
    for c in cases:
        by_channel[c.channel.value].append(c)

    # P0-2: real provenance for run_id — not channel name strings.
    target_cfg_hash = config_hash({
        "name": tcfg.name,
        "type": tcfg.type,
        "url_env": tcfg.url_env,
        "model_env": tcfg.model_env,
        "timeout": tcfg.timeout,
        "benchmark_mode": tcfg.benchmark_mode,
        "headers": tcfg.headers,
        "request": tcfg.request,
        "classification": tcfg.classification,
    })
    project_cfg_hash = config_hash({
        "project_id": project.project_id,
        "oracle": project.oracle,
        "channels": sorted(project.channels),
        "thresholds": project.thresholds,
        "renderer": project.renderer,
    })
    ds_hash = dataset_snapshot_hash(cases)
    fidelity_blob = "|".join(
        f"{ch}:{_resolve_fidelity(project, ch, args.fidelity)}"
        for ch in sorted(by_channel.keys())
    )
    run_version = args.run_version or compute_run_id(
        target.target_name,
        target_cfg_hash,
        fidelity_blob,
        ds_hash,
    )

    total_ran = 0
    total_skipped = 0
    for channel, group in sorted(by_channel.items()):
        rname = resolve_renderer_name(project, channel)
        fidelity = _resolve_fidelity(project, channel, args.fidelity)
        renderer = get_renderer(rname, fidelity=fidelity)
        store_path = RESULTS_DIR / args.project / args.target / run_version / f"{channel}.jsonl"
        runner = build_runner(
            project, target, renderer, store_path, run_version,
            request_gap=args.gap, target_cfg=tcfg,
        )
        runner.max_attempts = args.max_attempts
        rr = runner.run(group, dry_run=args.dry_run)
        total_ran += rr.ran
        total_skipped += rr.skipped
        label = "dry-run" if args.dry_run else "ran"
        print(f"[run] {channel} ({rname}/{fidelity}): {label}={rr.ran} skipped={rr.skipped} written={rr.written}")

    print(f"[run] total: ran={total_ran} skipped={total_skipped} "
          f"run_version={run_version} dry_run={args.dry_run} fidelity={args.fidelity}")
    print(f"[run] results: {RESULTS_DIR / args.project / args.target / run_version}")
    return 0
