"""demotest validate — fail-fast checks (plan §26)."""
from __future__ import annotations

import argparse
import os
import sys

from ..cases import load_cases, validate_case_ids_unique
from ..config import load_projects, load_targets
from ..core.exceptions import ConfigError, ValidationError


def add_parser(sub) -> None:
    p = sub.add_parser("validate", help="Fail-fast config / case validation")
    p.add_argument("--project", required=True)
    p.add_argument("--target", default="linemod")
    p.add_argument("--source", required=True,
                   help="fixture:<name> or legacy:<manifest>")
    p.add_argument("--no-key-check", action="store_true",
                   help="skip API key presence check (for offline validation)")
    p.set_defaults(func=run)


def run(args) -> int:
    errors: list[str] = []
    # 1. target config exists + type known
    targets = load_targets()
    if args.target not in targets:
        errors.append(f"target {args.target!r} not in config/v3/targets.yaml")
    else:
        tcfg = targets[args.target]
        # 2. API key present (unless --no-key-check)
        if not args.no_key_check:
            key = os.environ.get(tcfg.key_env, "").strip()
            if not key:
                errors.append(f"env {tcfg.key_env} is not set (use --no-key-check to skip)")
        # 3. No-Failover enforced in benchmark mode (plan §10)
        if tcfg.benchmark_mode:
            nf = (tcfg.headers or {}).get("X-LineMod-No-Failover", "")
            if nf.lower() != "true":
                errors.append(
                    "benchmark_mode=True requires X-LineMod-No-Failover=true "
                    "explicitly in target headers (plan §10)"
                )
    # 4. project config exists
    projects = load_projects()
    if args.project not in projects:
        errors.append(f"project {args.project!r} not in config/v3/projects.yaml")
    else:
        pcfg = projects[args.project]
        # 5. oracle / renderer references valid
        try:
            from ..runtime import build_oracle, resolve_renderer_name
            build_oracle(pcfg.oracle)
            for ch in pcfg.channels:
                resolve_renderer_name(pcfg, ch)
        except ConfigError as e:
            errors.append(str(e))
    # 6. cases load + case_id unique + project/channel consistency
    try:
        cases = load_cases(args.source, project=args.project)
        validate_case_ids_unique(cases)
        if not cases:
            errors.append("case source produced 0 cases")
        # P0-1: enforce project ↔ channel ↔ case consistency
        if args.project in projects:
            from ..cases import validate_cases_for_project
            try:
                validate_cases_for_project(cases, args.project, projects[args.project].channels)
            except ValidationError as e:
                errors.append(str(e))
    except (FileNotFoundError, ValidationError, Exception) as e:
        errors.append(f"case load failed: {e}")

    if errors:
        for e in errors:
            print(f"FAIL: {e}", file=sys.stderr)
        return 1
    print(f"OK: target={args.target} project={args.project} cases={len(cases)}")
    return 0
