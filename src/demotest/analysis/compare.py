"""Cross-run comparison (plan §38, §53)."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from ..core.models import SecurityCase
from ..storage.results import ResultStore
from .analyzer import analyze


def compare_runs(
    cases: list[SecurityCase],
    stores: dict[str, Path | ResultStore],
    *,
    project: str = "",
) -> dict[str, Any]:
    """Compare the same case set across targets/runs (e.g. LineMod vs QwenGuard).

    Each entry in ``stores`` is label -> result path/store. The report keeps
    them side by side but does NOT claim the targets have equivalent security
    responsibilities (plan §39).
    """
    out: dict[str, Any] = {"project": project, "runs": {}}
    for label, s in stores.items():
        rep = analyze(cases, s, project=project)
        out["runs"][label] = rep.to_dict()
    # per-case alignment for divergence detection
    per_case: dict[str, dict[str, str]] = {}
    for label, s in stores.items():
        store = ResultStore(s) if isinstance(s, Path) else s
        resolved = store.resolved()
        for cid, rec in resolved.items():
            per_case.setdefault(cid, {})[label] = str(rec.get("outcome") or "")
    divergent = {
        cid: vals
        for cid, vals in per_case.items()
        if len(set(vals.values())) > 1
    }
    out["n_divergent"] = len(divergent)
    out["divergent"] = divergent
    return out
