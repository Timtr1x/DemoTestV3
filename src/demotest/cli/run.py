"""demotest run — run cases against a target (plan §28, §29)."""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from ..cases import load_cases
from ..config import get_project, get_target
from ..core.ids import compute_run_id, config_hash
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
    p.add_argument("--fidelity", default="labeled",
                   choices=["raw", "structured", "labeled"],
                   help="render fidelity tier (F8): raw=headline, structured=transport, labeled=enhancement")
    p.set_defaults(func=run)


def run(args) -> int:
    project = get_project(args.project)
    tcfg = get_target(args.target)
    target = build_target(tcfg)
    cases = load_cases(args.source, project=args.project)

    # group cases by channel — each channel uses one renderer
    by_channel: dict[str, list] = defaultdict(list)
    for c in cases:
        by_channel[c.channel.value].append(c)

    run_version = args.run_version or compute_run_id(
        target.target_name,
        config_hash({"p": args.project, "t": args.target, "f": args.fidelity}),
        "multi",
        ",".join(sorted(by_channel.keys())),
    )

    total_ran = 0
    total_skipped = 0
    for channel, group in sorted(by_channel.items()):
        rname = resolve_renderer_name(project, channel)
        renderer = get_renderer(rname, fidelity=args.fidelity)
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
        print(f"[run] {channel} ({rname}/{args.fidelity}): {label}={rr.ran} skipped={rr.skipped} written={rr.written}")

    print(f"[run] total: ran={total_ran} skipped={total_skipped} "
          f"run_version={run_version} dry_run={args.dry_run} fidelity={args.fidelity}")
    print(f"[run] results: {RESULTS_DIR / args.project / args.target / run_version}")
    return 0
