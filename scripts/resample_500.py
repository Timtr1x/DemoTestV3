"""Force re-sample all projects under samples_per_project=500; verify totals + retest ids."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ.setdefault("ENABLE_WILDGUARD", "1")
os.environ.setdefault("ENABLE_WMDP", "1")
os.environ.setdefault("SAMPLE_SEED", "42")

from core.registry import PROJECTS, ensure_projects_imported, load_projects_yaml  # noqa: E402
from core.sampler import load_manifest  # noqa: E402
from paths import MANIFEST_DIR  # noqa: E402


def main() -> int:
    ensure_projects_imported()
    cfg = load_projects_yaml()
    assert int(cfg["defaults"]["samples_per_project"]) == 500
    assert int(cfg["defaults"]["seed"]) == 42

    order = ["e1", "e2", "e3", "e4", "e5", "e6", "e7", "e8", "e9", "e10", "e11", "e12", "ex"]
    for pid in order:
        print("===", pid, "===")
        PROJECTS[pid](cfg.get(pid, {})).sample(force=True)

    print()
    print("=== PROJECT TOTALS ===")
    grand = 0
    bad = []
    for pid in order:
        nsum = 0
        for spec in cfg[pid]["manifests"]:
            p = MANIFEST_DIR / f"{spec['name']}.json"
            d = json.loads(p.read_text(encoding="utf-8"))
            n = len(d["samples"])
            nsum += n
            extra = d.get("extra") or {}
            print(
                f"  {pid} {spec['name']}: n={n} seed={d.get('seed')} "
                f"alloc={extra.get('allocated_n')} weight={extra.get('weight')}"
            )
        grand += nsum
        flag = "OK" if nsum == 500 else f"BAD({nsum})"
        if nsum != 500:
            bad.append((pid, nsum))
        print(f"  >> {pid} TOTAL {nsum} {flag}")
    print("GRAND", grand)

    # retestability: re-sample e6 → identical sample_ids
    ids1 = [s.sample_id for s in load_manifest("mitre_400").samples]
    PROJECTS["e6"](cfg["e6"]).sample(force=True)
    ids2 = [s.sample_id for s in load_manifest("mitre_400").samples]
    print("e6 mitre retest ids equal", ids1 == ids2, "n", len(ids1))

    if bad:
        print("FAILED projects:", bad)
        return 1
    if ids1 != ids2:
        print("FAILED retestability")
        return 1
    print("ALL OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
