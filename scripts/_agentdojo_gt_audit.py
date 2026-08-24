"""AgentDojo ground-truth audit (Phase 1.5 steps 3+4).

Against the PINNED clone (cache/datasets_v3/raw/agentdojo):

  Step 3 — enumeration gate: the adapter's UserTask x InjectionTask pairing
           must equal the official security matrix from
           agentdojo.benchmark.benchmark_suite_with_injections
           (= every suite: all user_tasks x all injection_tasks,
           security_results keyed by (user_task, injection_task)).
           Gate: missing == 0 and extra == 0.

  Step 4 — per-call ground-truth dump: EVERY unique InjectionTask
           ground_truth() call (clean default environment) plus EVERY
           UserTask ground_truth() call, exported for the human BLOCK /
           exclude review that backs the v1.2.0 projection.

Read-only w.r.t. raw/ and normalized/; writes only cache/exports/.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

OUT_JSON = ROOT / "cache" / "exports" / "agentdojo_ground_truth_audit.json"
OUT_MD = ROOT / "cache" / "exports" / "agentdojo_ground_truth_audit.md"


def main() -> int:
    from demotest.config import get_dataset

    from demotest.datasets.adapters.agentdojo import AgentDojoAdapter

    ad = AgentDojoAdapter(source_config=get_dataset("agentdojo"))
    src = str(ad.raw_dir / "src")
    if src not in sys.path:
        sys.path.insert(0, src)
    from agentdojo.task_suite.load_suites import get_suites  # type: ignore

    version = ad.benchmark_version
    suites = get_suites(version)

    inventory: dict[str, dict] = {}
    official_pairs: set[tuple[str, str, str]] = set()
    inj_calls: list[dict] = []
    user_calls: list[dict] = []
    user_gt_empty: list[str] = []
    inj_gt_errors: list[dict] = []

    for name in sorted(suites):
        if name not in ad.suites:
            continue
        suite = suites[name]
        try:
            env = suite.load_and_inject_default_environment({})  # clean env
        except Exception as e:  # pragma: no cover
            env = None
            print(f"WARN: {name} env build failed: {e}")
        n_ugt = n_igt = 0
        for ut_id, ut in sorted(suite.user_tasks.items()):
            for it_id in suite.injection_tasks:
                official_pairs.add((name, str(ut_id), str(it_id)))
            try:
                calls = ut.ground_truth(env) if env is not None else []
            except Exception as e:
                calls = []
                user_gt_empty.append(f"{name}:{ut_id} (ground_truth raised: {type(e).__name__}: {e})")
                continue
            if not calls:
                user_gt_empty.append(f"{name}:{ut_id} (ground_truth returned [])")
            for step, c in enumerate(calls or [], start=1):
                n_ugt += 1
                user_calls.append({
                    "suite": name, "user_task_id": str(ut_id), "step": step,
                    "function": getattr(c, "function", "") or "",
                    "args": dict(getattr(c, "args", {}) or {}),
                    "prompt_excerpt": (getattr(ut, "PROMPT", "") or "")[:160],
                })
        for it_id, it in sorted(suite.injection_tasks.items()):
            try:
                calls = it.ground_truth(env) if env is not None else []
            except Exception as e:
                calls = []
                inj_gt_errors.append({
                    "suite": name, "injection_task_id": str(it_id),
                    "error": f"{type(e).__name__}: {e}",
                })
            if not calls and not any(x["suite"] == name and x["injection_task_id"] == str(it_id)
                                    for x in inj_gt_errors):
                inj_gt_errors.append({"suite": name, "injection_task_id": str(it_id),
                                      "error": "ground_truth returned []"})
            for step, c in enumerate(calls or [], start=1):
                n_igt += 1
                inj_calls.append({
                    "suite": name, "injection_task_id": str(it_id), "step": step,
                    "function": getattr(c, "function", "") or "",
                    "args": dict(getattr(c, "args", {}) or {}),
                    "goal": (getattr(it, "GOAL", "") or "")[:200],
                })
        inventory[name] = {
            "user_tasks": len(suite.user_tasks),
            "injection_tasks": len(suite.injection_tasks),
            "user_ground_truth_calls": n_ugt,
            "injection_ground_truth_calls": n_igt,
        }

    # ---- step 3 gate: adapter pairs vs official matrix -----------------
    adapter_pairs = {(p.suite, p.user_task_id, p.injection_task_id)
                     for p in ad._load_real_pairs()}
    missing = sorted(official_pairs - adapter_pairs)
    extra = sorted(adapter_pairs - official_pairs)

    report = {
        "audit": "agentdojo_official_enumeration_and_ground_truth_v1",
        "benchmark_version": version,
        "pinned_revision": ad._lock_revision(),
        "official_enumeration_definition": (
            "agentdojo.benchmark.benchmark_suite_with_injections: all user_tasks "
            "x all injection_tasks per suite; security_results keyed by "
            "(user_task_id, injection_task_id)"
        ),
        "inventory": inventory,
        "enumeration_gate": {
            "official_pairs": len(official_pairs),
            "adapter_pairs": len(adapter_pairs),
            "missing": [{"suite": s, "user_task": u, "injection_task": i}
                        for s, u, i in missing],
            "extra": [{"suite": s, "user_task": u, "injection_task": i}
                      for s, u, i in extra],
        },
        "injection_gt_calls": inj_calls,
        "user_gt_calls": user_calls,
        "user_gt_empty_or_error": user_gt_empty,
        "injection_gt_empty_or_error": inj_gt_errors,
        "unique_injection_tasks_audited": len({(c["suite"], c["injection_task_id"]) for c in inj_calls}),
    }
    OUT_JSON.write_text(json.dumps(report, indent=1, ensure_ascii=False), encoding="utf-8")

    # markdown review sheet ------------------------------------------------
    lines = [
        "# AgentDojo Ground-Truth Audit (pinned {})".format(version),
        "",
        "Enumeration gate: official={} adapter={} missing={} extra={}".format(
            len(official_pairs), len(adapter_pairs), len(missing), len(extra)),
        "",
        "## Injection ground-truth sequences (human BLOCK/exclude review)",
        "",
        "| suite | inj_task | step | tool | args | goal |",
        "|---|---|---|---|---|---|",
    ]
    last_key = None
    for c in inj_calls:
        key = (c["suite"], c["injection_task_id"])
        tid = c["injection_task_id"] if key != last_key else ""
        if key != last_key:
            lines.append(f"| {c['suite']} | {tid} | {c['step']} | {c['function']} | "
                         f"`{json.dumps(c['args'], ensure_ascii=False)[:120]}` | {c['goal'][:90]} |")
            last_key = key
        else:
            lines.append(f"| | | {c['step']} | {c['function']} | "
                         f"`{json.dumps(c['args'], ensure_ascii=False)[:120]}` | {c['goal'][:90]} |")
    lines += ["", "## User ground-truth sequences (ALLOW candidates)", "",
              "| suite | user_task | step | tool | args |", "|---|---|---|---|---|"]
    last_key = None
    for c in user_calls:
        key = (c["suite"], c["user_task_id"])
        tid = c["user_task_id"] if key != last_key else ""
        lines.append(f"| {c['suite']} | {tid} | {c['step']} | {c['function']} | "
                     f"`{json.dumps(c['args'], ensure_ascii=False)[:110]}` |")
        last_key = key
    if user_gt_empty:
        lines += ["", "## UserTasks with empty/erroring ground_truth (excluded from ALLOW)", ""]
        lines += [f"- {x}" for x in user_gt_empty]
    if inj_gt_errors:
        lines += ["", "## InjectionTasks with empty/erroring ground_truth", ""]
        lines += [f"- `{x['suite']}:{x['injection_task_id']}` — {x['error']}" for x in inj_gt_errors]
    OUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"wrote {OUT_JSON}")
    print(f"wrote {OUT_MD}")
    g = report["enumeration_gate"]
    print(f"ENUMERATION GATE: official={g['official_pairs']} adapter={g['adapter_pairs']} "
          f"missing={len(missing)} extra={len(extra)} -> "
          + ("PASS" if not missing and not extra else "FAIL"))
    print(f"injection GT calls dumped: {len(inj_calls)} across "
          f"{report['unique_injection_tasks_audited']} unique injection tasks")
    print(f"user GT calls dumped: {len(user_calls)}; empty/errored user tasks: {len(user_gt_empty)}")
    print(f"injection GT empty/errored: {len(inj_gt_errors)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
