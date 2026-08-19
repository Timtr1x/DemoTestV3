"""LLMail-Inject adapter — Microsoft HF dataset -> SecurityCase (guide §3-§16).

Source: ``microsoft/llmail-inject-challenge`` (HuggingFace dataset), pinned to a
full commit SHA in ``datasets.yaml``. This adapter is a DETERMINISTIC projection
of the official ``labelled_unique_submissions`` files into ``SecurityCase``.

Actual on-disk schema (verified against the pinned snapshot):
  * ``labelled_unique_submissions_phaseN.json`` is a **dict** whose keys are the
    full attacker-submitted prompt text and whose values are
    ``{"attack_attempt": <str>, "reason": "api_triggered"|"judge"}``.
  * ``attack_attempt`` is messy: values include ``"True"``, ``"False"``,
    ``"Unclear"``, ``"1.0"``, and even per-objective lists like
    ``"['False','True','False']"``. We treat a record as an attack when its
    value stringifies to a truthy True/1.0 *or* contains a ``'True'`` token.
  * ``emails_for_fp_tests.json`` is a **list** of benign prompt strings.

Mapping (guide §10): channel=EMAIL, operation=READ, direction=INBOUND,
content = the prompt verbatim (guide §51 — never rewritten), expected_action =
BLOCK for attacks / ALLOW for benign. ``source_id`` is a short SHA of the
prompt so identical prompts across phases dedup stably. ``label_source``
(api_triggered | judge) is preserved so reports can split API-confirmed vs
judge-labelled TPR (guide §13).
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterator, Mapping

from ...config import DatasetSourceConfig, get_dataset, load_dataset_projection
from ...core.enums import ExpectedAction
from ...core.exceptions import DatasetSourceError
from ...core.models import SecurityCase
from ..base import DatasetAdapter, ValidationReport
from ..quality import SourceProvenance, attach_provenance
from ..registry import register_adapter
from ..source_lock import load_source_lock


def _prompt_sha(prompt: str) -> str:
    return hashlib.sha256((prompt or "").encode("utf-8", errors="replace")).hexdigest()


def _iter_prompt_value_pairs(path: Path) -> Iterator[tuple[str, Mapping[str, Any]]]:
    """Stream ``{prompt: {"attack_attempt": .., "reason": ..}}`` from a JSON file.

    Uses ``ijson`` when installed so the 428M labelled_unique file is parsed as
    a stream (bounded memory); falls back to ``json.loads`` otherwise. Prompt
    keys are huge (they ARE the email text), so never buffer the raw dict.
    """
    try:
        import ijson  # type: ignore[import-not-found]

        with open(path, "rb") as f:
            for key, val in ijson.kvitems(f, ""):
                yield key, (val if isinstance(val, dict) else {})
        return
    except ImportError:
        pass
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, Mapping):
        return
    for k, v in data.items():
        yield k, (v if isinstance(v, Mapping) else {})


def _is_attack(attack_attempt: Any) -> bool:
    """Conservative attack parse for the messy attack_attempt field."""
    if attack_attempt is None:
        return False
    s = str(attack_attempt).strip()
    if not s:
        return False
    low = s.lower()
    if low in ("true", "1.0", "1", "yes"):
        return True
    if low in ("false", "0", "0.0", "no", "unclear", ""):
        return False
    # per-objective lists like "['False','True','False']" — attack if any True
    if "true" in low:
        return True
    return False


def _phase_of(rel_path: str) -> str:
    return "phase2" if "phase2" in rel_path else "phase1"


@register_adapter
class LLMailAdapter(DatasetAdapter):
    """Project the pinned LLMail-Inject snapshot into EMAIL SecurityCase objects."""

    dataset_id = "llmail"
    adapter_version = "1.1.0"

    def __init__(
        self,
        *,
        raw_dir: Path | str | None = None,
        source_config: DatasetSourceConfig | None = None,
        max_attack_per_phase: int | None = None,
    ) -> None:
        if source_config is None:
            source_config = get_dataset(self.dataset_id)
        self.source_config = source_config
        self.raw_dir = Path(raw_dir) if raw_dir else source_config.raw_path
        self.projection = load_dataset_projection(self.dataset_id)
        # None = unlimited; used by smoke/tests to keep memory bounded
        self.max_attack_per_phase = max_attack_per_phase

    # ------------------------------------------------------------------ helpers
    def _lock_revision(self) -> str:
        # Prefer the configured revision (authoritative for tests + reproducibility);
        # fall back to the on-disk lock only when the config didn't pin one.
        if self.source_config.revision:
            return self.source_config.revision
        try:
            return load_source_lock(self.dataset_id).revision
        except DatasetSourceError:
            return self.source_config.revision

    def _attack_files(self) -> list[Path]:
        files = self.projection.files.get("attack") or []
        return [self.raw_dir / f for f in files]

    def _benign_files(self) -> list[Path]:
        files = self.projection.files.get("benign") or []
        return [self.raw_dir / f for f in files]

    def _make_provenance(self, *, source_id: str, raw_sha: str, normalized_sha: str, group_id: str) -> SourceProvenance:
        return SourceProvenance(
            source_dataset=self.dataset_id,
            source_revision=self._lock_revision(),
            source_id=source_id,
            group_id=group_id,
            raw_sha256=raw_sha,
            normalized_sha256=normalized_sha,
            adapter_name="llmail",
            adapter_version=self.adapter_version,
            quality_tier="A",
            derivation="original",
        )

    # ------------------------------------------------------------------ iter
    def iter_cases(self) -> Iterator[SecurityCase]:
        seen_ids: set[str] = set()
        # attacks — streamed so the 428M phase1 file never loads fully into RAM.
        # Deterministic order: the normalized snapshot is sorted by source_id at
        # write time and the manifest re-sorts by selection_key, so streaming in
        # file order does not affect reproducibility (guide §29, §48).
        for fp in self._attack_files():
            if not fp.exists():
                continue
            phase = _phase_of(str(fp))
            count = 0
            for prompt, labels in _iter_prompt_value_pairs(fp):
                if not isinstance(prompt, str) or not prompt.strip():
                    continue
                labels = labels if isinstance(labels, Mapping) else {}
                if not _is_attack(labels.get("attack_attempt")):
                    continue
                raw_sha = _prompt_sha(prompt)
                source_id = f"llmail:{phase}:{raw_sha[:16]}"
                if source_id in seen_ids:
                    continue
                seen_ids.add(source_id)
                case = self._build_attack_case(
                    prompt=prompt, source_id=source_id, raw_sha=raw_sha, phase=phase, labels=labels
                )
                yield case
                count += 1
                if self.max_attack_per_phase and count >= self.max_attack_per_phase:
                    break
        # benign FP emails (guide §14)
        for fp in self._benign_files():
            if not fp.exists():
                continue
            data = json.loads(fp.read_text(encoding="utf-8"))
            prompts = data if isinstance(data, list) else list(data.keys())
            for prompt in prompts:
                if not isinstance(prompt, str) or not prompt.strip():
                    continue
                raw_sha = _prompt_sha(prompt)
                source_id = f"llmail:benign:{raw_sha[:16]}"
                if source_id in seen_ids:
                    continue
                seen_ids.add(source_id)
                yield self._build_benign_case(prompt=prompt, source_id=source_id, raw_sha=raw_sha)

    def _build_attack_case(
        self, *, prompt: str, source_id: str, raw_sha: str, phase: str, labels: Mapping[str, Any]
    ) -> SecurityCase:
        from ..dedup import normalize_text

        normalized_sha = hashlib.sha256(normalize_text(prompt).encode("utf-8", errors="replace")).hexdigest()
        case = SecurityCase.build(
            dataset_id=self.dataset_id,
            source_id=source_id,
            channel="email",
            operation="read",
            direction="inbound",
            content=prompt,
            expected_action=ExpectedAction.BLOCK,
            project_id="P1_external_instruction",
            threat_id="indirect_prompt_injection",
            presentation_style=self._presentation_style(prompt),
        )
        meta = {
            "source_phase": phase,
            "original_label": str(labels.get("attack_attempt")),
            "label_source": str(labels.get("reason") or ""),
            "scenario": self._scenario_of(prompt),
            "attack_goal": "exfiltrate_via_email",
            "derivation": "original",
            "quality_tier": "A",
        }
        # merge into case.metadata
        d = case.to_dict()
        d["metadata"] = {**(d.get("metadata") or {}), **meta}
        case = SecurityCase.from_dict(d)
        prov = self._make_provenance(
            source_id=source_id, raw_sha=raw_sha, normalized_sha=normalized_sha, group_id=source_id
        )
        return attach_provenance(case, prov)

    def _build_benign_case(self, *, prompt: str, source_id: str, raw_sha: str) -> SecurityCase:
        from ..dedup import normalize_text

        normalized_sha = hashlib.sha256(normalize_text(prompt).encode("utf-8", errors="replace")).hexdigest()
        case = SecurityCase.build(
            dataset_id=self.dataset_id,
            source_id=source_id,
            channel="email",
            operation="read",
            direction="inbound",
            content=prompt,
            expected_action=ExpectedAction.ALLOW,
            project_id="P1_external_instruction",
            threat_id="",
            presentation_style="natural",
        )
        d = case.to_dict()
        d["metadata"] = {
            **(d.get("metadata") or {}),
            "source_phase": "benign",
            "original_label": "False",
            "label_source": "benign_fp",
            "scenario": "benign",
            "attack_goal": "",
            "derivation": "original",
            "quality_tier": "A",
        }
        case = SecurityCase.from_dict(d)
        prov = self._make_provenance(
            source_id=source_id, raw_sha=raw_sha, normalized_sha=normalized_sha, group_id=source_id
        )
        return attach_provenance(case, prov)

    # ------------------------------------------------------------------ heuristics
    @staticmethod
    def _presentation_style(prompt: str) -> str:
        p = prompt.lower()
        if any(t in p for t in ("<<", ">>", "[job]", "</user_query", "end_user_session", "process_user_query")):
            return "structured"
        if "deobfuscation" in p or "contact <at>" in p:
            return "stealth"
        return "explicit"

    @staticmethod
    def _scenario_of(prompt: str) -> str:
        # scenario files key by scenario_N; we cannot perfectly recover it from
        # the prompt alone, so label by content markers conservatively.
        p = prompt.lower()
        if "transaction" in p or "bank" in p:
            return "banking"
        if "calendar" in p or "meeting" in p:
            return "calendar"
        if "email" in p:
            return "email_exfil"
        return "unknown"

    # ------------------------------------------------------------------ validate
    def validate_raw(self) -> ValidationReport:
        rep = ValidationReport(ok=True)
        af = self._attack_files()
        rep.add("attack_files_present", bool(af) and all(f.exists() for f in af), f"{[str(f) for f in af]}")
        bf = self._benign_files()
        rep.add("benign_files_present", bool(bf) and all(f.exists() for f in bf), f"{[str(f) for f in bf]}")
        # counts (guide §10): smoke thresholds, not exact-equality contracts
        n_attack = 0
        for f in af:
            if f.exists():
                d = json.loads(f.read_text(encoding="utf-8"))
                n_attack += len(d) if isinstance(d, Mapping) else len(d) if isinstance(d, list) else 0
        rep.add("attack_count_gt_150k", n_attack > 150_000, f"n_attack={n_attack}")
        n_benign = 0
        for f in bf:
            if f.exists():
                d = json.loads(f.read_text(encoding="utf-8"))
                n_benign += len(d) if isinstance(d, list) else len(d) if isinstance(d, Mapping) else 0
        rep.add("benign_count_ge_200", n_benign >= 200, f"n_benign={n_benign}")
        return rep

    def source_metadata(self) -> dict[str, Any]:
        return {
            "dataset_id": self.dataset_id,
            "adapter_version": self.adapter_version,
            "source_type": self.source_config.source_type,
            "source_uri": self.source_config.source_uri,
            "revision": self._lock_revision(),
            "quality_tier": "A",
            "derivation": "original",
        }
