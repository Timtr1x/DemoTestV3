"""Force re-sample all projects from real pools (no pad-to-500)."""
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
os.environ.setdefault("LEGACY_DEMOTEST_ROOT", str(ROOT))

from core.data_quality import diversity_stats  # noqa: E402
from core.registry import PROJECTS, ensure_projects_imported, load_projects_yaml  # noqa: E402
from core.sampler import load_manifest  # noqa: E402
from paths import MANIFEST_DIR  # noqa: E402


def main() -> int:
    ensure_projects_imported()
    cfg = load_projects_yaml()
    assert cfg["defaults"].get("samples_per_project") in (None, "", 0)

    order = ["e1", "e2", "e3", "e4", "e5", "e6", "e7", "e8", "e9", "e10", "e11", "e12", "ex"]
    for pid in order:
        print("===", pid, "===")
        PROJECTS[pid](cfg.get(pid, {})).sample(force=True)

    print()
    print("=== PROJECT TOTALS (real n) ===")
    grand = 0
    low = []
    for pid in order:
        nsum = 0
        for spec in cfg[pid]["manifests"]:
            p = MANIFEST_DIR / f"{spec['name']}.json"
            if not p.exists():
                print(f"  {pid} {spec['name']}: MISSING")
                continue
            d = json.loads(p.read_text(encoding="utf-8"))
            samples = d.get("samples") or []
            n = len(samples)
            nsum += n
            st = diversity_stats([s.get("prompt_text") or "" for s in samples])
            flag = ""
            if n > 5 and st["template_ratio"] < 0.35 and pid != "e10":
                flag = " LOW_DIV"
                low.append(spec["name"])
            print(
                f"  {pid} {spec['name']}: n={n} uniq_tpl={st['unique_templates']} "
                f"ratio={st['template_ratio']:.2f}{flag}"
            )
        grand += nsum
        print(f"  >> {pid} TOTAL {nsum}")
    print("GRAND", grand)

    # retestability
    if (MANIFEST_DIR / "mitre_400.json").exists():
        ids1 = [s.sample_id for s in load_manifest("mitre_400").samples]
        PROJECTS["e6"](cfg["e6"]).sample(force=True)
        ids2 = [s.sample_id for s in load_manifest("mitre_400").samples]
        print("e6 mitre retest ids equal", ids1 == ids2, "n", len(ids1))
        if ids1 != ids2:
            return 1

    if low:
        print("WARN low diversity:", low)
        return 2
    print("ALL OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
