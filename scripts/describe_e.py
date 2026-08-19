"""Print all E projects, sub-manifests, n, and brief metadata."""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.registry import load_projects_yaml  # noqa: E402
from paths import MANIFEST_DIR  # noqa: E402


def main() -> None:
    cfg = load_projects_yaml()
    order = [
        "e1",
        "e2",
        "e3",
        "e4",
        "e5",
        "e6",
        "e7",
        "e8",
        "e9",
        "e10",
        "e11",
        "e12",
        "ex",
    ]
    grand = 0
    for pid in order:
        sec = cfg[pid]
        print("=" * 72)
        print(f"{pid.upper()}  {sec.get('name')}")
        print(f"thresholds: {sec.get('thresholds')}")
        print(f"group_by:   {sec.get('group_by')}")
        for c in sec.get("caveats") or []:
            print(f"caveat:     {c}")
        total = 0
        for m in sec.get("manifests") or []:
            p = MANIFEST_DIR / f"{m['name']}.json"
            d = json.loads(p.read_text(encoding="utf-8"))
            n = len(d["samples"])
            total += n
            labs = Counter(s.get("label") for s in d["samples"])
            exp = Counter(s.get("expected") for s in d["samples"])
            detail = (
                m.get("subset")
                or m.get("legacy_name")
                or m.get("pool")
                or m.get("filter")
                or "-"
            )
            print(
                f"  • {m['name']}"
                f"  n={n}"
                f"  weight={m.get('weight')}"
                f"  adapter={m.get('adapter')}"
                f"  detail={detail}"
            )
            print(f"      label={dict(labs)}  expected={dict(exp)}  seed={d.get('seed')}")
            if d["samples"]:
                snip = d["samples"][0]["prompt_text"][:100].replace("\n", " ")
                print(f"      e.g. {snip!r}")
        print(f"  PROJECT TOTAL n={total}")
        grand += total
    print("=" * 72)
    print(f"GRAND TOTAL n={grand}  ({len(order)} projects × 500 expected)")


if __name__ == "__main__":
    main()
