"""Analysis — aggregate results into reports (plan §31-35)."""
from __future__ import annotations

from .analyzer import AnalysisReport, analyze
from .compare import compare_runs

__all__ = ["AnalysisReport", "analyze", "compare_runs"]
