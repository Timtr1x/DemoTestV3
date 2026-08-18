"""V3 CLI entry point (plan §25-28)."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .. import __version__
from ..paths import RESULTS_DIR, REPORTS_DIR
from . import analyze as analyze_cmd
from . import compare as compare_cmd
from . import render as render_cmd
from . import report as report_cmd
from . import run as run_cmd
from . import validate as validate_cmd


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="demotest",
        description="DemoTest V3 — Gateway Security Benchmark Framework",
    )
    parser.add_argument("--version", action="version", version=f"demotest {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    validate_cmd.add_parser(sub)
    render_cmd.add_parser(sub)
    run_cmd.add_parser(sub)
    analyze_cmd.add_parser(sub)
    report_cmd.add_parser(sub)
    compare_cmd.add_parser(sub)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
