"""Project-level summary aggregation."""
from __future__ import annotations

from pathlib import Path

from ..analysis.analyzer import AnalysisReport
from .markdown import write_markdown


def project_summary(rep: AnalysisReport, out_dir: Path) -> Path:
    return write_markdown(rep, out_dir, filename="SUMMARY.md")
