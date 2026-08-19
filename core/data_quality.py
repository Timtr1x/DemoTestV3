"""Dataset authenticity / diversity checks (no synthetic padding)."""
from __future__ import annotations

import re
from collections import Counter
from typing import Iterable, Sequence


_DIGIT_RE = re.compile(r"\d+")
_HEX_RE = re.compile(r"[0-9a-f]{8,}", re.I)
_WS_RE = re.compile(r"\s+")


def normalize_template(text: str) -> str:
    """Collapse digit/hex variance so near-duplicates of the same payload group together."""
    t = (text or "").strip().lower()
    t = _HEX_RE.sub("<hex>", t)
    t = _DIGIT_RE.sub("<n>", t)
    t = _WS_RE.sub(" ", t)
    return t


def diversity_stats(prompts: Sequence[str]) -> dict:
    n = len(prompts)
    if n == 0:
        return {
            "n": 0,
            "unique_literal": 0,
            "unique_templates": 0,
            "max_template_share": 0.0,
            "template_ratio": 0.0,
        }
    literals = [str(p or "") for p in prompts]
    templates = [normalize_template(p) for p in literals]
    lit_u = len(set(literals))
    tpl_u = len(set(templates))
    counts = Counter(templates)
    max_share = counts.most_common(1)[0][1] / n
    return {
        "n": n,
        "unique_literal": lit_u,
        "unique_templates": tpl_u,
        "max_template_share": max_share,
        "template_ratio": tpl_u / n,
    }


def is_low_diversity(prompts: Sequence[str], *, min_template_ratio: float = 0.35) -> bool:
    """True when most rows are the same template with only digit/id changes."""
    st = diversity_stats(prompts)
    if st["n"] == 0:
        return True
    if st["n"] <= 3:
        return False  # tiny curated sets OK
    return st["template_ratio"] < min_template_ratio or st["max_template_share"] > 0.5


def assert_real_prompts(
    prompts: Iterable[str],
    *,
    name: str,
    allow_boundary: bool = False,
    min_template_ratio: float = 0.35,
) -> dict:
    """Raise if empty or (non-boundary) low diversity."""
    plist = [str(p or "") for p in prompts]
    if not plist:
        raise ValueError(f"{name}: empty pool (no real cases)")
    if any(not p.strip() for p in plist):
        raise ValueError(f"{name}: blank prompt present")
    st = diversity_stats(plist)
    if not allow_boundary and is_low_diversity(plist, min_template_ratio=min_template_ratio):
        raise ValueError(
            f"{name}: low diversity — unique_templates={st['unique_templates']}/{st['n']} "
            f"max_share={st['max_template_share']:.2f}. Refuse synthetic/padded pool."
        )
    return st
