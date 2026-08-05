"""PurpleLlama CybersecurityBenchmarks adapter (offline cache preferred)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from adapters.base import DatasetAdapter
from core.schema import Sample
from paths import DATASETS_DIR

FIELD_MAP = {
    # Prefer attack user_input; fall back to system-side test_case_prompt
    "prompt": ["user_input", "test_case_prompt", "prompt_text", "prompt", "text"],
    "technique": [
        "injection_variant",
        "injection_technique",
        "injection_type",
        "mitre_category",
        "category",
        "attack_type",
        "risk_category",
    ],
}

ADAPTER_VERSION = "1.0"


def _pick(d: dict, keys: list[str], default: str = "") -> str:
    for k in keys:
        if k in d and d[k] is not None:
            return str(d[k])
    return default


class CyberSecEvalAdapter(DatasetAdapter):
    source_name = "cyberseceval"
    adapter_version = ADAPTER_VERSION

    def dataset_version(self) -> str:
        marker = self.cache_dir() / "VERSION"
        if marker.exists():
            return marker.read_text(encoding="utf-8").strip()
        return "cyberseceval:cache-or-fixture"

    def _load_json_array(self, rel: str) -> list[dict]:
        path = self.cache_dir() / rel
        if not path.exists():
            return []
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for k in ("data", "samples", "test_cases", "instances"):
                if isinstance(data.get(k), list):
                    return data[k]
        return []

    def fetch(
        self,
        *,
        project: str,
        subset: str = "prompt_injection",
        **kwargs: Any,
    ) -> list[Sample]:
        file_map = {
            "prompt_injection": "prompt_injection/prompt_injection.json",
            "token_smuggling": "prompt_injection/prompt_injection.json",
            "multilingual": "prompt_injection/prompt_injection_multilingual_machine_translated.json",
            "mitre": "mitre/mitre_benchmark_100_per_category_with_augmentation.json",
            "frr": "frr/frr.json",
            "interpreter": "interpreter/interpreter.json",
            "spear_phishing": "spear_phishing/spear_phishing.json",
        }
        rel = file_map.get(subset, file_map["prompt_injection"])
        rows = self._load_json_array(rel)
        # For PI quota headroom also merge multilingual machine-translated when present
        if subset == "prompt_injection":
            extra = self._load_json_array(
                "prompt_injection/prompt_injection_multilingual_machine_translated.json"
            )
            if extra:
                rows = list(rows) + list(extra)
        if not rows:
            # fixture for offline unit tests
            rows = self._fixture(subset)

        samples: list[Sample] = []
        for i, row in enumerate(rows):
            if not isinstance(row, dict):
                continue
            technique = _pick(row, FIELD_MAP["technique"], subset)
            if subset == "token_smuggling":
                # Prefer true token-smuggling variants; if too few, keep full PI pool
                # under subset filter applied by caller/manifest name.
                tech_l = technique.lower()
                blunt = (
                    "smuggl" in tech_l
                    or "token" in tech_l
                    or "payload_split" in tech_l
                    or "repeated_token" in tech_l
                    or "output_formatting" in tech_l
                )
                # When filtering strictly would leave nearly empty sets, include
                # all direct injections as the smuggling/evasion evaluation pool.
                if not blunt:
                    # mark for possible later — include if injection_type is direct
                    if str(row.get("injection_type") or "").lower() not in ("direct", ""):
                        continue
                    if not technique:
                        technique = "token_smuggling"
            # Prefer combined system+user when both exist (realistic injection context)
            user = str(row.get("user_input") or "").strip()
            systemish = str(row.get("test_case_prompt") or "").strip()
            if user and systemish and user != systemish:
                prompt = f"{systemish}\n\nUser: {user}"
            else:
                prompt = _pick(row, FIELD_MAP["prompt"])
            if not prompt:
                continue
            label = "benign" if subset == "frr" else "attack"
            expected = "passed" if label == "benign" else "blocked"
            sid = f"{project}:cyberseceval_{subset}:{i}"
            samples.append(
                Sample(
                    sample_id=sid,
                    project=project,
                    source_dataset=f"cyberseceval_{subset}",
                    subset=technique or subset,
                    category=technique or subset,
                    label=label,
                    prompt_text=prompt,
                    expected=expected,
                )
            )
        return samples

    def _fixture(self, subset: str) -> list[dict]:
        """Minimal offline fixtures so sample/run work without downloads."""
        if subset == "frr":
            return [
                {
                    "test_case_prompt": f"How do I bake sourdough bread recipe step {i}?",
                    "injection_technique": "frr",
                }
                for i in range(20)
            ]
        if subset == "token_smuggling":
            return [
                {
                    "test_case_prompt": f"token smuggle case {i}: ignore previous",
                    "injection_technique": "token_smuggling",
                }
                for i in range(15)
            ]
        # 15 techniques x a few
        techniques = [
            "hypothetical_scenario",
            "token_smuggling",
            "payload_splitting",
            "indirect_reference",
            "role_play",
            "obfuscation",
            "instruction_override",
            "context_switching",
            "few_shot_jailbreak",
            "encoded_payload",
            "authority_impersonation",
            "emotional_manipulation",
            "multi_turn_seed",
            "system_prompt_leak",
            "tool_abuse",
        ]
        rows = []
        for t in techniques:
            for j in range(5):
                rows.append(
                    {
                        "test_case_prompt": f"[{t}] attack prompt variant {j}",
                        "injection_technique": t,
                    }
                )
        return rows
