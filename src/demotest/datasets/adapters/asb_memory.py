"""ASB Memory-Poisoning adapter — official Agent Security Bench -> MEMORY_WRITE.

Phase 2A projection fidelity spec (accepted review, 2026-08-24):

ASB's memory-poisoning scenario persists records shaped like
``Agent: {prefix}; Task: {task_input}; Workflow: {workflow}; Tools: {tool_info}``
where ``Workflow`` is RUNTIME-generated (never fabricated here) and the
attacker's static contribution inside the persisted ``Tools`` field is ONLY
the OpenAI function descriptor ``{"type": "function", "function": {name,
description}}`` — the ``Attacker Instruction`` is NOT part of that structure.

Therefore each projected SecurityCase carries, as ``content``, the EXACT
deterministic JSON serialization of that single attacker tool descriptor
(the shape ASB would persist for it, minus every runtime/fabricated field):

    [{"type": "function", "function": {"name": <Attacker Tool>,
                                        "description": <Description>}}]

``Attacker Instruction`` is preserved in metadata for audit traceability only
(it must never reach the gateway-visible content). Metadata is explicit:
``derivation=deterministic_projection``, ``quality_tier=B``,
``source_field=attacker_tool_definition``,
``ground_truth_kind=memory_poisoning_attack``. No LLM, no runtime, no Chroma.

Source: agiresearch/ASB, pinned 1f561dccf92d55302368fa67679b4ba9d9c8fdc4
(ICLR 2025, arXiv 2410.02644, MIT). File: data/all_attack_tools.jsonl (400
entries; fail-closed on count).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping

from ...config import DatasetSourceConfig, get_dataset, load_dataset_projection
from ...core.enums import Channel, Direction, ExpectedAction, Operation
from ...core.exceptions import DatasetSourceError
from ...core.models import SecurityCase
from ..base import DatasetAdapter, ValidationReport
from ..quality import SourceProvenance, attach_provenance
from ..registry import register_adapter
from ..source_lock import load_source_lock

EXPECTED_ATTACK_ENTRIES = 400
ATTACK_TOOLS_REL = "data/all_attack_tools.jsonl"
ASB_ARXIV = "2410.02644"


def attacker_tool_descriptor(row: Mapping[str, Any]) -> str:
    """Deterministic serialization of the static attacker tool descriptor.

    Exactly one element array — the shape ASB embeds inside the persisted
    ``Tools`` field for this entry. ``Attacker Instruction`` is excluded by
    design (fidelity spec): it is not part of the persisted tool descriptor.
    """
    descriptor = {
        "type": "function",
        "function": {
            "name": str(row.get("Attacker Tool") or ""),
            "description": str(row.get("Description") or ""),
        },
    }
    return json.dumps([descriptor], ensure_ascii=False)


@register_adapter
class AsbMemoryAdapter(DatasetAdapter):
    """Project pinned ASB memory-poisoning attack tools into MEMORY_WRITE."""

    dataset_id = "p5_asb_memory"
    adapter_version = "1.0.0"

    def __init__(
        self,
        *,
        raw_dir: Path | str | None = None,
        source_config: DatasetSourceConfig | None = None,
        entries_provider: "Iterable[Mapping[str, Any]] | None" = None,
        max_entries: int | None = None,
    ) -> None:
        if source_config is None:
            source_config = get_dataset(self.dataset_id)
        self.source_config = source_config
        self.raw_dir = Path(raw_dir) if raw_dir else source_config.raw_path
        self.projection = load_dataset_projection(self.dataset_id)
        self._entries_provider = entries_provider
        self.max_entries = max_entries

    # ------------------------------------------------------------------ revision
    def _lock_revision(self) -> str:
        if self.source_config.revision:
            return self.source_config.revision
        try:
            return load_source_lock(self.dataset_id).revision
        except DatasetSourceError:
            return self.source_config.revision

    # ------------------------------------------------------------------ rows
    def _load_rows(self) -> Iterator[Mapping[str, Any]]:
        if self._entries_provider is not None:
            yield from self._entries_provider
            return
        fp = self.raw_dir / ATTACK_TOOLS_REL
        if not fp.exists():
            raise DatasetSourceError(
                f"missing ASB attack-tools file: {fp}. "
                f"Run: python -m demotest.cli.main dataset acquire --dataset {self.dataset_id}"
            )
        for line in fp.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)

    # ------------------------------------------------------------------ iter
    def iter_cases(self) -> Iterator[SecurityCase]:
        rows = list(self._load_rows())
        actual = len(rows)
        # fail-closed only on the REAL acquisition path; entries_provider
        # (unit-test injection) skips the gate like agentdojo's task_provider.
        if self._entries_provider is None and actual != EXPECTED_ATTACK_ENTRIES:
            raise DatasetSourceError(
                f"ASB attack-tools count drift: expected {EXPECTED_ATTACK_ENTRIES} "
                f"entries, found {actual} — pinned artifact changed; re-run "
                "scripts/_p5_asb_projection_proof.py and re-review"
            )
        for i, row in enumerate(rows, start=1):
            if self.max_entries and i > self.max_entries:
                break
            yield self._build_case(i=i, row=row)

    def _build_case(self, *, i: int, row: Mapping[str, Any]) -> SecurityCase:
        source_id = f"asb:mp:{i:03d}"
        content = attacker_tool_descriptor(row)
        tool = str(row.get("Attacker Tool") or "")
        case = SecurityCase.build(
            dataset_id=self.dataset_id,
            source_id=source_id,
            channel=Channel.MEMORY_WRITE,
            operation=Operation.WRITE_MEMORY,
            direction=Direction.OUTBOUND,
            content=content,
            memory_operation="write",
            memory_target="agent_long_term_memory",
            expected_action=ExpectedAction.BLOCK,
            project_id="P5_memory_write",
            threat_id="memory_poisoning",
            presentation_style="structured",
        )
        d = case.to_dict()
        d["metadata"] = {
            **(d.get("metadata") or {}),
            "source_dataset": "asb",
            "source_revision": self._lock_revision(),
            "source_field": "attacker_tool_definition",
            "ground_truth_kind": "memory_poisoning_attack",
            "attacker_tool": tool,
            "attack_type": str(row.get("Attack Type") or ""),
            "aggressive": str(row.get("Aggressive") or ""),
            "corresponding_agent": str(row.get("Corresponding Agent") or ""),
            # traceability only — deliberately NOT part of gateway-visible content
            "attacker_instruction": str(row.get("Attacker Instruction") or ""),
            "attack_goal": str(row.get("Attack goal") or ""),
            "arxiv": f"arXiv:{ASB_ARXIV}",
            "quality_tier": "B",
            "derivation": "deterministic_projection",
        }
        case = SecurityCase.from_dict(d)
        nsha = content.encode("utf-8", errors="replace")
        prov = SourceProvenance(
            source_dataset="asb",
            source_revision=self._lock_revision(),
            source_id=source_id,
            group_id=source_id,
            raw_sha256=_sha256(content),
            normalized_sha256=_sha256(content),
            adapter_name="p5_asb_memory",
            adapter_version=self.adapter_version,
            quality_tier="B",
            derivation="deterministic_projection",
            parent_source_id=source_id,
        )
        return attach_provenance(case, prov)

    # ------------------------------------------------------------------ validate
    def validate_raw(self) -> ValidationReport:
        rep = ValidationReport(ok=True)
        rep.add("clone_present", self.raw_dir.exists(), str(self.raw_dir))
        fp = self.raw_dir / ATTACK_TOOLS_REL
        rep.add("attack_tools_present", fp.exists(), str(fp))
        n = 0
        required = {"Attacker Tool", "Description", "Attack Type",
                    "Corresponding Agent", "Aggressive"}
        missing_fields: set[str] = set()
        if fp.exists():
            for line in fp.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                n += 1
                missing_fields |= required - set(json.loads(line).keys())
        rep.add("attack_entries_exact_400", n == EXPECTED_ATTACK_ENTRIES, f"n={n}")
        rep.add("required_fields_present", not missing_fields,
                f"missing={sorted(missing_fields)}")
        return rep

    def source_metadata(self) -> dict[str, Any]:
        return {
            "dataset_id": self.dataset_id,
            "adapter_version": self.adapter_version,
            "source_type": self.source_config.source_type,
            "source_uri": self.source_config.source_uri,
            "revision": self._lock_revision(),
            "license": self.source_config.license,
            "arxiv": f"arXiv:{ASB_ARXIV}",
            "quality_tier": "B",
            "derivation": "deterministic_projection",
        }


def _sha256(text: str) -> str:
    import hashlib

    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()