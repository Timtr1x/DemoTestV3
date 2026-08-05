"""Shared sample-building helpers for thin project modules."""
from __future__ import annotations

import os
from typing import Any

from adapters.agentdojo import AgentDojoAdapter
from adapters.asb import ASBAdapter
from adapters.bipia import BIPIAAdapter
from adapters.cyberseceval import CyberSecEvalAdapter
from adapters.harmbench import HarmBenchAdapter
from adapters.injecagent import InjecAgentAdapter
from adapters.legacy import bridge_legacy_manifest, ensure_bridged_local
from adapters.llmail import LLMailAdapter
from adapters.multilingual import MultilingualAdapter
from adapters.orbench import ORBenchAdapter
from adapters.selfbuild import SelfBuildAdapter
from adapters.tensortrust import TensorTrustAdapter
from adapters.wildguard import WildGuardAdapter
from adapters.wmdp import WMDPAdapter
from adapters.xstest import XSTestAdapter
from core.registry import template_version_string
from core.sampler import stratified_sample
from core.schema import Sample
from generators.encoding_gen import encode_samples
from generators.promptfoo_gen import convert_promptfoo, ensure_fixture
from paths import DATASETS_DIR
from core.sampler import SAMPLE_SEED


def env_enabled(name: str | None) -> bool:
    if not name:
        return True
    return os.environ.get(name, "0").lower() in ("1", "true", "yes")


def build_from_spec(project_id: str, spec: dict[str, Any]) -> tuple[list[Sample], dict[str, str]]:
    """Dispatch adapter by spec['adapter'] and return samples + provenance."""
    adapter_name = spec.get("adapter")
    enabled_env = spec.get("enabled_env")
    if enabled_env and not env_enabled(enabled_env):
        # empty with provenance noting disabled
        return [], {
            "source_dataset": adapter_name or "disabled",
            "dataset_version": f"disabled:{enabled_env}",
            "adapter_version": "disabled@0",
            "template_version": "none",
        }

    if adapter_name == "legacy":
        legacy_name = spec["legacy_name"]
        # Always repair local placeholders before sample/run consumption
        ensure_bridged_local(legacy_name, force=False)
        m = bridge_legacy_manifest(legacy_name, project=project_id)
        from adapters.legacy import samples_have_placeholders

        if samples_have_placeholders(m.samples):
            ensure_bridged_local(legacy_name, force=True)
            m = bridge_legacy_manifest(legacy_name, project=project_id)
        # re-tag project if needed
        samples = []
        for s in m.samples:
            samples.append(
                Sample(
                    sample_id=s.sample_id,
                    project=project_id,
                    source_dataset=s.source_dataset,
                    subset=s.subset,
                    category=s.category,
                    label=s.label,
                    prompt_text=s.prompt_text,
                    expected=s.expected,
                    generator_meta=s.generator_meta,
                )
            )
        return samples, {
            "source_dataset": m.source_dataset,
            "dataset_version": m.dataset_version,
            "adapter_version": m.adapter_version,
            "template_version": m.template_version,
        }

    if adapter_name == "cyberseceval":
        ad = CyberSecEvalAdapter()
        subset = spec.get("subset") or "prompt_injection"
        samples = ad.fetch(project=project_id, subset=subset)
        if subset == "prompt_injection" and spec.get("strata_mode") == "technique_equal":
            # 15 techniques x 20 if available
            from collections import Counter

            techniques = sorted({s.subset for s in samples})
            quotas = {t: 20 for t in techniques}
            samples = stratified_sample(samples, quotas, seed=SAMPLE_SEED)
        prov = ad.provenance()
        prov["template_version"] = "none"
        return samples, prov

    if adapter_name == "wildguard":
        ad = WildGuardAdapter()
        samples = ad.fetch(project=project_id, mode="adversarial_harmful")
        prov = ad.provenance()
        prov["template_version"] = "none"
        return samples, prov

    if adapter_name == "harmbench":
        ad = HarmBenchAdapter()
        filt = spec.get("filter") or "exclude_cybercrime"
        samples = ad.fetch(project=project_id, filter_mode=filt)
        prov = ad.provenance()
        prov["template_version"] = "none"
        return samples, prov

    if adapter_name == "llmail":
        ad = LLMailAdapter()
        samples = ad.fetch(
            project=project_id,
            subset=spec.get("subset") or "all",
            template=spec.get("template") or "email_v1",
        )
        prov = ad.provenance()
        prov["template_version"] = template_version_string()
        return samples, prov

    if adapter_name == "bipia":
        ad = BIPIAAdapter()
        samples = ad.fetch(project=project_id)
        # equal domain quotas of 30 if enough
        domains = sorted({s.subset for s in samples})
        if domains:
            samples = stratified_sample(samples, {d: 30 for d in domains}, seed=SAMPLE_SEED)
        prov = ad.provenance()
        prov["template_version"] = template_version_string()
        return samples, prov

    if adapter_name == "injecagent":
        ad = InjecAgentAdapter()
        samples = ad.fetch(project=project_id, pool=spec.get("pool") or "dh_ds")
        prov = ad.provenance()
        prov["template_version"] = template_version_string()
        return samples, prov

    if adapter_name == "agentdojo":
        ad = AgentDojoAdapter()
        samples = ad.fetch(
            project=project_id,
            subset=spec.get("subset") or "exfiltration",
            template=spec.get("template") or "tool_result_v1",
        )
        prov = ad.provenance()
        prov["template_version"] = template_version_string()
        return samples, prov

    if adapter_name == "asb":
        ad = ASBAdapter()
        samples = ad.fetch(
            project=project_id,
            subset=spec.get("subset") or "dpi_opi",
            template=spec.get("template") or "tool_result_v1",
        )
        prov = ad.provenance()
        prov["template_version"] = template_version_string()
        return samples, prov

    if adapter_name == "tensortrust":
        ad = TensorTrustAdapter()
        samples = ad.fetch(project=project_id, subset=spec.get("subset") or "extraction")
        prov = ad.provenance()
        prov["template_version"] = "none"
        return samples, prov

    if adapter_name == "selfbuild":
        ad = SelfBuildAdapter()
        subset = spec.get("subset") or "canary"
        samples = ad.fetch(project=project_id, subset=subset, n=spec.get("quota"))
        prov = ad.provenance()
        prov["source_dataset"] = f"selfbuild_{subset}"
        prov["template_version"] = "none"
        return samples, prov

    if adapter_name == "xstest":
        ad = XSTestAdapter()
        samples = ad.fetch(project=project_id, subset=spec.get("subset") or "safe")
        prov = ad.provenance()
        prov["template_version"] = "none"
        return samples, prov

    if adapter_name == "orbench":
        ad = ORBenchAdapter()
        samples = ad.fetch(project=project_id, subset=spec.get("subset") or "hard")
        prov = ad.provenance()
        prov["template_version"] = "none"
        return samples, prov

    if adapter_name == "multilingual":
        ad = MultilingualAdapter()
        samples = ad.fetch(project=project_id, subset=spec.get("subset") or "multijail")
        prov = ad.provenance()
        prov["template_version"] = "none"
        return samples, prov

    if adapter_name == "wmdp":
        ad = WMDPAdapter()
        samples = ad.fetch(project=project_id)
        prov = ad.provenance()
        prov["template_version"] = template_version_string()
        return samples, prov

    if adapter_name == "encoding_gen":
        # take up to 50 cyberseceval attacks as base
        base_ad = CyberSecEvalAdapter()
        base = base_ad.fetch(project="e1", subset="prompt_injection")[:50]
        samples = encode_samples(base, project=project_id)
        return samples, {
            "source_dataset": "encoding_gen",
            "dataset_version": "encoding_gen@1.0",
            "adapter_version": "encoding_gen.py@1.0",
            "template_version": "none",
        }

    if adapter_name == "promptfoo_gen":
        raw = DATASETS_DIR / "promptfoo" / "e11_raw.json"
        if not raw.exists():
            ensure_fixture(raw, n_per_plugin=25)
        samples = convert_promptfoo(raw, project=project_id)
        return samples, {
            "source_dataset": "promptfoo_redteam",
            "dataset_version": f"promptfoo_file:{raw.name}",
            "adapter_version": "promptfoo_gen.py@1.0",
            "template_version": "none",
        }

    raise ValueError(f"Unknown adapter {adapter_name!r} in spec {spec}")
