"""Project registry: decorator registration + shared CLI lifecycle."""
from __future__ import annotations

import argparse
import importlib
import json
import os
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Callable, Type

import yaml

from core.analyzer import analyze
from core.report import write_summary
from core.runner import retest_cooldown, run_manifest
from core.sampler import (
    allocate_proportional,
    build_manifest,
    deterministic_subsample,
    load_manifest,
    save_manifest,
    stratified_sample,
)
from core.schema import Manifest, Sample
from paths import CONFIG_DIR, MANIFEST_DIR, RESULTS_DIR, REPO_ROOT


def _load_manifest_for_run(name: str, directory: Path | None = None) -> Manifest:
    """Load manifest; auto-repair legacy placeholder prompts on the real run path."""
    try:
        from adapters.legacy import LEGACY_META, load_manifest_repaired

        if name in LEGACY_META:
            return load_manifest_repaired(name, directory=directory)
    except Exception:
        pass
    return load_manifest(name, directory=directory)

PROJECTS: dict[str, Type["BaseProject"]] = {}


def register(project_id: str) -> Callable[[Type["BaseProject"]], Type["BaseProject"]]:
    def deco(cls: Type["BaseProject"]) -> Type["BaseProject"]:
        cls.project_id = project_id
        PROJECTS[project_id] = cls
        return cls

    return deco


def load_projects_yaml(path: Path | None = None) -> dict[str, Any]:
    p = path or (CONFIG_DIR / "projects.yaml")
    if not p.exists():
        return {}
    return yaml.safe_load(p.read_text(encoding="utf-8")) or {}


def load_templates(path: Path | None = None) -> dict[str, Any]:
    p = path or (CONFIG_DIR / "templates.yaml")
    if not p.exists():
        return {"version": "none", "templates": {}}
    return yaml.safe_load(p.read_text(encoding="utf-8")) or {
        "version": "none",
        "templates": {},
    }


def render_template(template_name: str, payload: str, templates: dict | None = None) -> str:
    data = templates if templates is not None else load_templates()
    tpl = (data.get("templates") or {}).get(template_name)
    if not tpl:
        return payload
    return tpl.format(payload=payload)


def template_version_string(templates: dict | None = None) -> str:
    data = templates if templates is not None else load_templates()
    ver = data.get("version") or "unknown"
    return f"templates.yaml@{ver}"


class BaseProject(ABC):
    project_id: str = ""
    module_name: str = ""

    def __init__(self, config: dict[str, Any] | None = None):
        all_cfg = load_projects_yaml()
        self.config = config if config is not None else all_cfg.get(self.project_id, {})
        self.templates = load_templates()

    def project_name(self) -> str:
        return str(self.config.get("name") or self.project_id)

    def thresholds(self) -> dict[str, Any]:
        return dict(self.config.get("thresholds") or {})

    def caveats(self) -> list[str]:
        return list(self.config.get("caveats") or [])

    def group_by(self) -> list[str]:
        return list(self.config.get("group_by") or ["subset"])

    def manifest_specs(self) -> list[dict[str, Any]]:
        return list(self.config.get("manifests") or [])

    @abstractmethod
    def build_samples_for_manifest(self, spec: dict[str, Any]) -> tuple[list[Sample], dict[str, str]]:
        """Return (samples, provenance dict with dataset_version/adapter_version/...)."""
        raise NotImplementedError

    def sample(self, *, force: bool = False, manifest_dir: Path | None = None) -> list[Path]:
        """Generate manifests for all specs (refuse overwrite unless force).

        Real-data policy:
          - Never pad beyond available real pool size.
          - ``weight`` / ``quota`` / ``max_n`` are optional **caps** (shrink only).
          - ``samples_per_project`` if set does proportional allocation capped by
            pool sizes (sum may be < target when real data is short).
        """
        written: list[Path] = []
        mdir = manifest_dir or MANIFEST_DIR
        all_cfg = load_projects_yaml()
        defaults = all_cfg.get("defaults") or {}
        seed = int(os.environ.get("SAMPLE_SEED") or defaults.get("seed") or 42)
        target_total = defaults.get("samples_per_project")
        if target_total is not None and target_total != "":
            target_total = int(target_total)
        else:
            target_total = None

        specs = self.manifest_specs()
        # Phase 1: materialize full pools (adapter may already apply strata_mode)
        built: list[tuple[dict[str, Any], list[Sample], dict[str, str]]] = []
        for spec in specs:
            samples, prov = self.build_samples_for_manifest(spec)
            quotas = spec.get("quotas")
            if quotas and samples:
                samples = stratified_sample(samples, quotas, seed=seed)
            built.append((spec, list(samples), prov))

        def _cap_of(spec: dict[str, Any], pool_n: int) -> int:
            raw = spec.get("max_n", spec.get("quota", spec.get("weight")))
            if raw is None:
                return pool_n
            return min(int(raw), pool_n)

        # Phase 2: allocation — never exceed real pool
        if target_total is not None and built:
            weights: list[int] = []
            caps: list[int] = []
            for spec, samples, _prov in built:
                pool_n = len(samples)
                cap = _cap_of(spec, pool_n)
                w = spec.get("weight", spec.get("quota", spec.get("max_n")))
                if w is None:
                    w = cap
                weights.append(int(w))
                caps.append(cap)
            allocs = allocate_proportional(weights, target_total, caps)
            print(
                f"[sample] {self.project_id} target={target_total} "
                f"weights={weights} caps={caps} allocs={allocs} sum={sum(allocs)}"
            )
        else:
            # per-spec cap only (default): use all real cases up to max_n
            allocs = []
            for spec, samples, _prov in built:
                allocs.append(_cap_of(spec, len(samples)))
            print(
                f"[sample] {self.project_id} real-n-only "
                f"allocs={allocs} sum={sum(allocs)}"
            )

        # Phase 3: subsample + write
        for (spec, samples, prov), n_take in zip(built, allocs):
            name = spec["name"]
            pool_n = len(samples)
            if n_take < pool_n:
                samples = deterministic_subsample(samples, n_take, seed=seed)
            elif n_take == 0:
                samples = []
            else:
                samples = sorted(samples, key=lambda s: s.sample_id)

            m = build_manifest(
                name,
                samples,
                seed=seed,
                source_dataset=prov.get("source_dataset")
                or (samples[0].source_dataset if samples else "unknown"),
                dataset_version=prov.get("dataset_version", "unknown"),
                adapter_version=prov.get("adapter_version", "unknown"),
                template_version=prov.get(
                    "template_version", template_version_string(self.templates)
                ),
                extra={
                    "project": self.project_id,
                    "spec": {k: v for k, v in spec.items() if k != "name"},
                    "samples_per_project": target_total,
                    "allocated_n": int(n_take),
                    "pool_n": pool_n,
                    "max_n": spec.get("max_n", spec.get("quota", spec.get("weight"))),
                    "real_only": True,
                },
            )
            path = save_manifest(m, directory=mdir, force=force)
            written.append(path)
            print(f"[sample] wrote {path} n={len(samples)} pool={pool_n}")
        return written

    def results_path(self, manifest_name: str, run_version: str) -> Path:
        return RESULTS_DIR / self.project_id / run_version / f"{manifest_name}.jsonl"

    def _default_client(self) -> Callable:
        """Live client with client-side throttle OFF — runner owns REQUEST_GAP once."""
        from linemod_guard_client import test_linemod

        def _client(prompt: str) -> dict:
            return test_linemod(prompt, do_throttle=False)

        return _client

    def run(
        self,
        *,
        run_version: str = "dev",
        client: Callable | None = None,
        request_gap: float | None = None,
        manifest_dir: Path | None = None,
        max_attempts: int | None = None,
        sleep_fn=None,
    ) -> None:
        client = client or self._default_client()
        kwargs: dict[str, Any] = {
            "client": client,
            "run_version": run_version,
        }
        if request_gap is not None:
            kwargs["request_gap"] = request_gap
        if max_attempts is not None:
            kwargs["max_attempts"] = max_attempts
        if sleep_fn is not None:
            kwargs["sleep_fn"] = sleep_fn

        for spec in self.manifest_specs():
            name = spec["name"]
            # Legacy adapters: re-bridge if on-disk file still has placeholders
            if spec.get("adapter") == "legacy" and spec.get("legacy_name"):
                try:
                    from adapters.legacy import ensure_bridged_local

                    ensure_bridged_local(
                        spec["legacy_name"], directory=manifest_dir
                    )
                except Exception as e:
                    print(f"[run] legacy repair warn {spec.get('legacy_name')}: {e}")
            try:
                manifest = _load_manifest_for_run(name, directory=manifest_dir)
            except FileNotFoundError:
                print(f"[run] skip missing manifest {name}")
                continue
            out = self.results_path(name, run_version)
            stats = run_manifest(manifest, out, **kwargs)
            print(f"[run] {name} -> {out} {stats}")

    def retest_cooldown_cmd(
        self,
        *,
        run_version: str = "dev",
        client: Callable | None = None,
        request_gap: float | None = None,
        manifest_dir: Path | None = None,
        sleep_fn=None,
    ) -> None:
        client = client or self._default_client()
        for spec in self.manifest_specs():
            name = spec["name"]
            if spec.get("adapter") == "legacy" and spec.get("legacy_name"):
                try:
                    from adapters.legacy import ensure_bridged_local

                    ensure_bridged_local(
                        spec["legacy_name"], directory=manifest_dir
                    )
                except Exception:
                    pass
            try:
                manifest = _load_manifest_for_run(name, directory=manifest_dir)
            except FileNotFoundError:
                continue
            out = self.results_path(name, run_version)
            kwargs: dict[str, Any] = {
                "client": client,
                "run_version": run_version,
            }
            if request_gap is not None:
                kwargs["request_gap"] = request_gap
            if sleep_fn is not None:
                kwargs["sleep_fn"] = sleep_fn
            stats = retest_cooldown(manifest, out, **kwargs)
            print(f"[retest-cooldown] {name} {stats}")

    def analyze_cmd(
        self,
        *,
        run_version: str = "dev",
        group_by: list[str] | None = None,
        manifest_dir: Path | None = None,
    ) -> list:
        reports = []
        gb = group_by if group_by is not None else self.group_by()
        for spec in self.manifest_specs():
            name = spec["name"]
            if spec.get("adapter") == "legacy" and spec.get("legacy_name"):
                try:
                    from adapters.legacy import ensure_bridged_local

                    ensure_bridged_local(
                        spec["legacy_name"], directory=manifest_dir
                    )
                except Exception:
                    pass
            try:
                manifest = _load_manifest_for_run(name, directory=manifest_dir)
            except FileNotFoundError:
                print(f"[analyze] missing {name}")
                continue
            results = self.results_path(name, run_version)
            rep = analyze(
                manifest,
                results,
                group_by=gb,
                run_version=run_version,
                thresholds=self.thresholds(),
                caveats=self.caveats(),
                project=self.project_name(),
            )
            reports.append(rep)
            print(
                f"[analyze] {name} TPR={rep.metrics.tpr} FPR={rep.metrics.fpr} "
                f"judged={rep.metrics.n_judged}/{rep.metrics.n_total} {rep.pass_fail}"
            )
        return reports

    def report_cmd(
        self,
        *,
        run_version: str = "dev",
        group_by: list[str] | None = None,
        manifest_dir: Path | None = None,
    ) -> list[Path]:
        reports = self.analyze_cmd(
            run_version=run_version, group_by=group_by, manifest_dir=manifest_dir
        )
        paths = []
        for rep in reports:
            out_dir = RESULTS_DIR / self.project_id / run_version
            p = write_summary(rep, out_dir, filename=f"SUMMARY_{rep.manifest_name}.md")
            # also write aggregate SUMMARY.md for last / primary
            paths.append(p)
            print(f"[report] {p}")
        if reports:
            # combined SUMMARY
            out_dir = RESULTS_DIR / self.project_id / run_version
            write_summary(reports[0], out_dir, filename="SUMMARY.md")
        return paths


def default_cli(project: BaseProject, argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog=f"python -m projects.{project.module_name or project.project_id}"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_sample = sub.add_parser("sample", help="Build manifests (refuse overwrite)")
    p_sample.add_argument("--force", action="store_true")

    p_run = sub.add_parser("run", help="Run manifests against LineMod")
    p_run.add_argument("--run-version", default="dev")
    p_run.add_argument("--gap", type=float, default=None)

    p_re = sub.add_parser("retest-cooldown", help="Retest cooldown outcomes")
    p_re.add_argument("--run-version", default="dev")

    p_an = sub.add_parser("analyze", help="Compute metrics")
    p_an.add_argument("--run-version", default="dev")
    p_an.add_argument("--group-by", nargs="*", default=None)

    p_rep = sub.add_parser("report", help="Write SUMMARY.md")
    p_rep.add_argument("--run-version", default="dev")
    p_rep.add_argument("--group-by", nargs="*", default=None)

    args = parser.parse_args(argv)

    if args.cmd == "sample":
        project.sample(force=args.force)
    elif args.cmd == "run":
        project.run(run_version=args.run_version, request_gap=args.gap)
    elif args.cmd == "retest-cooldown":
        project.retest_cooldown_cmd(run_version=args.run_version)
    elif args.cmd == "analyze":
        project.analyze_cmd(run_version=args.run_version, group_by=args.group_by)
    elif args.cmd == "report":
        project.report_cmd(run_version=args.run_version, group_by=args.group_by)
    return 0


def ensure_projects_imported() -> None:
    """Import all project modules so @register runs."""
    for mod in (
        "projects.e1_direct_injection",
        "projects.e2_indirect_injection",
        "projects.e3_encoding_evasion",
        "projects.e4_system_leak",
        "projects.e5_exfiltration",
        "projects.e6_weaponized",
        "projects.e7_interpreter_abuse",
        "projects.e8_tool_misuse",
        "projects.e9_memory_poison",
        "projects.e10_resource_abuse",
        "projects.e11_privilege_induce",
        "projects.e12_overrefusal",
        "projects.ex_multilingual",
    ):
        try:
            importlib.import_module(mod)
        except Exception as e:
            print(f"warn: failed to import {mod}: {e}", file=sys.stderr)
