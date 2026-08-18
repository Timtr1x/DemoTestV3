"""demotest render — show the request that would be sent (plan §27)."""
from __future__ import annotations

import json

from ..cases import load_cases
from ..config import get_project, get_target
from ..runtime import build_target, resolve_renderer_name
from ..renderers import get_renderer


def add_parser(sub) -> None:
    p = sub.add_parser("render", help="Render a case -> request (no API call)")
    p.add_argument("--project", required=True)
    p.add_argument("--source", required=True)
    p.add_argument("--case-id", default=None, help="render only this case_id")
    p.add_argument("--limit", type=int, default=1)
    p.add_argument("--show-request", action="store_true",
                   help="also show the full GatewayRequest json_body")
    p.set_defaults(func=run)


def run(args) -> int:
    project = get_project(args.project)
    cases = load_cases(args.source, project=args.project)
    if args.case_id:
        cases = [c for c in cases if c.case_id == args.case_id]
    cases = cases[: args.limit]
    for c in cases:
        rname = resolve_renderer_name(project, c.channel.value)
        renderer = get_renderer(rname)
        text = renderer.render(c)
        print(f"=== case {c.case_id} | channel={c.channel.value} | {renderer.full_version} ===")
        print(text)
        if args.show_request:
            tcfg = get_target("linemod")
            target = build_target(tcfg)
            req = target.build_request(rendered_text=text)
            print("--- request json_body ---")
            print(json.dumps(req.json_body, ensure_ascii=False, indent=2))
            print(f"request_hash: {req.request_hash()}")
        print()
    return 0
