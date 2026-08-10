"""XSTest exaggerated-safety prompts."""
from __future__ import annotations

import json
from typing import Any

from adapters.base import DatasetAdapter
from core.schema import Sample

ADAPTER_VERSION = "1.0"


class XSTestAdapter(DatasetAdapter):
    source_name = "xstest"
    adapter_version = ADAPTER_VERSION

    def dataset_version(self) -> str:
        p = self.cache_dir() / "xstest.jsonl"
        if p.exists():
            return f"xstest_github:{p.stat().st_size}"
        return "xstest:missing"

    def _rows(self) -> list[dict]:
        p = self.cache_dir() / "xstest.jsonl"
        if not p.exists():
            return []
        rows = []
        for line in p.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            prompt = str(r.get("prompt") or "")
            if "safe-id=" in prompt or "unsafe-id=" in prompt or "(id=" in prompt:
                continue
            rows.append(r)
        return rows

    def fetch(self, *, project: str, subset: str = "safe", **kwargs: Any) -> list[Sample]:
        samples = []
        for i, row in enumerate(self._rows()):
            # XSTest CSV: type=homonyms/... focus category; label=safe|unsafe is ground truth
            focus = str(row.get("type") or row.get("focus") or "unknown").lower()
            gold = str(row.get("label") or row.get("final_label") or "").lower()
            if gold in ("safe", "unsafe"):
                typ = gold
            elif "contrast" in focus or focus in ("unsafe",):
                typ = "unsafe"
            elif focus in ("safe",) or not gold:
                # bare type categories without "contrast_" are the exaggerated-safety (safe) set
                typ = "safe" if not focus.startswith("contrast") else "unsafe"
            else:
                typ = gold or "safe"
            # Non-contrast type rows are the safe over-refusal set; contrast_* are unsafe pairs
            if gold not in ("safe", "unsafe"):
                typ = "unsafe" if focus.startswith("contrast") else "safe"
            if subset == "safe" and typ != "safe":
                continue
            if subset == "unsafe" and typ != "unsafe":
                continue
            label = "benign" if typ == "safe" else "attack"
            expected = "passed" if label == "benign" else "blocked"
            samples.append(
                Sample(
                    sample_id=f"{project}:xstest_{typ}:{i}",
                    project=project,
                    source_dataset="xstest",
                    subset=focus or typ,
                    category=typ,
                    label=label,
                    prompt_text=str(row.get("prompt") or ""),
                    expected=expected,
                )
            )
        return samples
