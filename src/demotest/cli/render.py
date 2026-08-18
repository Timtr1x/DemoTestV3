"""demotest render — show the request that would be sent (plan §27).

All printed output is passed through SecretRedactor so canary markers in the
rendered text or request body never leak to stdout/logs (plan §24, §43).
"""
from __future__ import annotations

import json

from ..cases import load_cases
from ..config import get_project, get_target
from ..core.redactor import SecretRedactor
from ..runtime import build_target, resolve_renderer_name
from ..renderers import get_renderer


def add_parser(sub) -> None:
    p = sub.add_parser("render", help="Render a case -> request (no API call)")
    p.add_argument("--project", required=True)
    p.add_argument("--source", required=True)
    p.add_argument("--case-id", default=None, help="render only this case_id")
    p.add_argument("--limit", type=int, default=1)
    p.add_argument("--target", default="linemod",
                   help="target to build the request for (default: linemod)")
    p.add_argument("--fidelity", default="labeled",
                   choices=["raw", "structured", "labeled"],
                   help="render fidelity tier (F8): raw / structured / labeled")
    p.add_argument("--show-request", action="store_true",
                   help="also show the full GatewayRequest json_body")
    p.add_argument("--no-redact", action="store_true",
                   help="disable secret redaction (debugging only — never use in CI)")
    p.set_defaults(func=run)


def run(args) -> int:
    project = get_project(args.project)
    cases = load_cases(args.source, project=args.project)
    if args.case_id:
        cases = [c for c in cases if c.case_id == args.case_id]
    cases = cases[: args.limit]
    tcfg = get_target(args.target)
    target = build_target(tcfg)
    for c in cases:
        rname = resolve_renderer_name(project, c.channel.value)
        renderer = get_renderer(rname, fidelity=args.fidelity)
        text = renderer.render_for_fidelity(c)
        redactor = SecretRedactor(extra_markers=c.credential_markers) if not args.no_redact else None
        def _out(s: str) -> str:
            return redactor.redact_text(s) if redactor else s
        print(f"=== case {c.case_id} | channel={c.channel.value} | {renderer.full_version} | fidelity={args.fidelity} ===")
        print(_out(text))
        if args.show_request:
            gen = project.generation_profile(tcfg)
            req = target.build_request(rendered_text=text, temperature=gen["temperature"], max_tokens=gen["max_tokens"])
            print("--- request json_body ---")
            body = req.json_body
            if redactor:
                body = redactor.redact_dict(body)
            print(json.dumps(body, ensure_ascii=False, indent=2))
            print(f"request_hash: {req.request_hash()}")
        print()
    return 0
