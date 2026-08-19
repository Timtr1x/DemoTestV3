"""Verify standard suite manifests exist and re-sample is deterministic (seed=42)."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("SAMPLE_SEED", "42")
os.environ.setdefault("LEGACY_DEMOTEST_ROOT", str(ROOT))
os.environ.setdefault("ENABLE_WMDP", "1")
os.environ.setdefault("ENABLE_WILDGUARD", "1")

from core.registry import PROJECTS, ensure_projects_imported, load_projects_yaml  # noqa: E402
from paths import MANIFEST_DIR  # noqa: E402

ORDER = ["e1", "e2", "e3", "e4", "e5", "e6", "e7", "e8", "e9", "e10", "e11", "e12", "ex"]


def main() -> int:
    ensure_projects_imported()
    cfg = load_projects_yaml()
    assert cfg["defaults"].get("seed") == 42
    assert cfg["defaults"].get("samples_per_project") in (None, "", 0)

    # inventory
    grand = 0
    missing = []
    print("=== STANDARD MANIFEST INVENTORY ===")
    for pid in ORDER:
        nsum = 0
        for spec in cfg[pid]["manifests"]:
            name = spec["name"]
            p = MANIFEST_DIR / f"{name}.json"
            if not p.exists():
                missing.append(name)
                print(f"  {pid}/{name}: MISSING")
                continue
            d = json.loads(p.read_text(encoding="utf-8"))
            n = len(d["samples"])
            nsum += n
            print(
                f"  {pid}/{name}: n={n} seed={d.get('seed')} "
                f"src={d.get('source_dataset')}"
            )
        print(f"  >> {pid} TOTAL {nsum}")
        grand += nsum
    print(f"GRAND_TOTAL {grand}")
    if missing:
        print("MISSING", missing)
        return 1

    # retest e8/e9 only (fast)
    print("=== RETEST e8/e9 sample_ids ===")
    before = {}
    for pid in ("e8", "e9"):
        for spec in cfg[pid]["manifests"]:
            name = spec["name"]
            d = json.loads((MANIFEST_DIR / f"{name}.json").read_text(encoding="utf-8"))
            before[name] = [s["sample_id"] for s in d["samples"]]
    PROJECTS["e8"](cfg["e8"]).sample(force=True)
    PROJECTS["e9"](cfg["e9"]).sample(force=True)
    ok = True
    for name, ids in before.items():
        d = json.loads((MANIFEST_DIR / f"{name}.json").read_text(encoding="utf-8"))
        ids2 = [s["sample_id"] for s in d["samples"]]
        eq = ids == ids2
        print(f"  {name}: equal={eq} n={len(ids2)}")
        if not eq:
            ok = False
    if not ok:
        print("RETEST_FAIL")
        return 2
    print("ALL_OK retestable standard suite")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
