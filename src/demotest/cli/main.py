"""V3 CLI entry point (plan §25-28)."""
from __future__ import annotations

import argparse
import json
import sys
import traceback
from pathlib import Path

from .. import __version__
from ..core.redactor import SecretRedactor
from ..paths import RESULTS_DIR, REPORTS_DIR
from . import analyze as analyze_cmd
from . import compare as compare_cmd
from . import render as render_cmd
from . import report as report_cmd
from . import run as run_cmd
from . import validate as validate_cmd

# F1/F43: every uncaught exception that reaches the CLI boundary is redacted
# before it touches stderr, so a canary or API key in an exception message can
# never leak through the process boundary (external review doc-fix 3).
_REDACTOR = SecretRedactor()


def _redact_exc_text(exc: BaseException) -> str:
    """Redact the full traceback text of an exception before printing to stderr."""
    tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    return _REDACTOR.redact_text(tb)


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
    try:
        return args.func(args)
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 — boundary redaction at CLI edge
        # Redact the exception + traceback so no secret reaches stderr.
        sys.stderr.write(_redact_exc_text(exc))
        return 1


if __name__ == "__main__":
    sys.exit(main())
