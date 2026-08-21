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
from . import dataset as dataset_cmd
from . import manifest as manifest_cmd
from . import render as render_cmd
from . import report as report_cmd
from . import run as run_cmd
from . import validate as validate_cmd

# NOTE: the `dynamic` subparser is intentionally NOT imported at module top.
# `dynamic` is OPTIONAL DATASET ACQUISITION tooling (docs/PROJECT_SCOPE.md §3):
# a normal benchmark invocation (validate/render/run/analyze/report/manifest/
# dataset) must never load datasets.dynamic.* — the frozen P4 dataset is the
# formal benchmark input. The dynamic subcommand is registered lazily, only
# when the user actually runs `demotest dynamic ...`.

# F1/F43: every uncaught exception that reaches the CLI boundary is redacted
# before it touches stderr, so a canary or API key in an exception message can
# never leak through the process boundary (external review doc-fix 3).
_REDACTOR = SecretRedactor()


def _redact_exc_text(exc: BaseException) -> str:
    """Redact the full traceback text of an exception before printing to stderr."""
    tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    return _REDACTOR.redact_text(tb)


def _add_dynamic_parser(sub) -> None:
    """Register the acquisition subparser on demand (kept out of every CLI run)."""
    from . import dynamic as dynamic_cmd

    dynamic_cmd.add_parser(sub)


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
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
    dataset_cmd.add_parser(sub)
    manifest_cmd.add_parser(sub)
    # Lazy acquisition CLI: import + register ONLY when the user actually
    # invoked `demotest dynamic ...`. Any other invocation (validate/render/
    # run/analyze/report/compare/dataset/manifest) must never load
    # demotest.datasets.dynamic.* (docs/PROJECT_SCOPE.md §3).
    first = next((a for a in argv if not a.startswith("-")), None)
    if first == "dynamic":
        _add_dynamic_parser(sub)

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
