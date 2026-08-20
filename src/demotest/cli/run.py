"""demotest run — run cases against a target (plan §28, §29)."""
from __future__ import annotations

import json
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
    primary = getattr(project, "primary_fidelity", None) or {}
    if channel in primary:
        return primary[channel]
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

    from ..cases import validate_cases_for_project
    validate_cases_for_project(cases, args.project, project.channels)

    by_channel: dict[str, list] = defaultdict(list)
    for c in cases:
        by_channel[c.channel.value].append(c)

    target_cfg_hash = config_hash({
        "name": target.target_name,
        "type": tcfg.type,
        "url": getattr(target, "url", ""),
        "model": getattr(target, "model", ""),
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
        "renderer": project.renderer,
        "primary_fidelity": project.primary_fidelity,
        "generation": project.generation,
    })
    ds_hash = dataset_snapshot_hash(cases)
    fidelity_blob = "|".join(
        f"{ch}:{_resolve_fidelity(project, ch, args.fidelity)}"
        for ch in sorted(by_channel.keys())
    )
    experiment_hash = config_hash({
        "target": target_cfg_hash,
        "project": project_cfg_hash,
        "dataset": ds_hash,
        "fidelity": fidelity_blob,
    })
    run_version = args.run_version or compute_run_id(
        target.target_name,
        experiment_hash,
        "v3",
        ds_hash,
    )

    # P1: provenance — resolve benchmark context BEFORE running (fail-closed on invalid track)
    from ..datasets.context import resolve_benchmark_context
    ctx = resolve_benchmark_context(args.source, project=args.project)

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

    # Write _run_meta.json for provenance chain Run → Manifest → Track
    try:
        source_type = "manifest" if args.source.startswith("manifest:") else ("fixture" if args.source.startswith("fixture:") else ("legacy" if args.source.startswith("legacy:") else "unknown"))
        meta = {
            "source": args.source,
            "source_type": source_type,
            "manifest": ctx.manifest_path,
            "manifest_sha256": ctx.manifest_sha256,
            "benchmark_track": ctx.benchmark_track,
            "headline_eligible": ctx.headline_eligible,
            "dataset_snapshot_hash": ds_hash,
            "project_config_hash": project_cfg_hash,
            "target_config_hash": target_cfg_hash,
            "run_version": run_version,
            "project": args.project,
            "target": args.target,
        }
        meta_path = RESULTS_DIR / args.project / args.target / run_version / "_run_meta.json"
        meta_path.parent.mkdir(parents=True, exist_ok=True)
        meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except Exception as e:
        print(f"[run] WARN: failed to write _run_meta.json: {e}")

    print(f"[run] total: ran={total_ran} skipped={total_skipped} "
          f"run_version={run_version} dry_run={args.dry_run} fidelity={args.fidelity}")
    print(f"[run] results: {RESULTS_DIR / args.project / args.target / run_version}")
    return 0
