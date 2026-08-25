"""ASB Memory-Poisoning adapter — official Agent Security Bench -> MEMORY_WRITE.

Phase 2B (real-controls extension): same pinned revision, two official files

  * data/all_attack_tools.jsonl  -> 400 BLOCK (attacker tool descriptor)
  * data/all_normal_tools.jsonl  ->  20 ALLOW (normal  tool descriptor)

Both are ASB-official OpenAI function descriptors that ASB embeds inside the
persisted memory ``Tools`` field (``Agent+Task+Workflow+Tools``). ``Workflow``
is runtime-generated and never fabricated; ``Attacker Instruction`` /
``Expected Achievements`` stay metadata-only, never gateway-visible.

Attack descriptor (AttackerTool.get_tool_call_format):
  [{"type":"function","function":{"name": <Attacker Tool>,
                                  "description": <Description>}}]

Normal descriptor (SimulatedTool.get_tool_call_format) — the authoritative
shape includes ``parameters: null`` (must be preserved):
  [{"type":"function","function":{"name": <Tool Name>,
                                  "description": <Description>,
                                  "parameters": null}}]

Split leak-proofing: every case's grouping key is
``asb:agent:<Corresponding Agent>`` so one agent's attack+normal tools never
span splits (DEV/EVAL/HOLDOUT isolation). See split_group in
config/v3/datasets/p5_asb_memory.yaml.

Source: agiresearch/ASB, pinned 1f561dccf92d55302368fa67679b4ba9d9c8fdc4
(ICLR 2025, arXiv 2410.02644, MIT). fail-closed on both counts (400/20)
outside entries_provider injection.
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
EXPECTED_NORMAL_ENTRIES = 20
ATTACK_TOOLS_REL = "data/all_attack_tools.jsonl"
NORMAL_TOOLS_REL = "data/all_normal_tools.jsonl"
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


def normal_tool_descriptor(row: Mapping[str, Any]) -> str:
    """Deterministic serialization of the official normal tool descriptor.

    The real upstream shape is SimulatedTool.get_tool_call_format() which emits
    ``parameters: null`` alongside name/description. That null is AUTH-pinned
    behavior and must not be dropped or rewritten.
    """
    descriptor = {
        "type": "function",
        "function": {
            "name": str(row.get("Tool Name") or ""),
            "description": str(row.get("Description") or ""),
            "parameters": None,
        },
    }
    return json.dumps([descriptor], ensure_ascii=False)


def agent_group_id(corresponding_agent: str) -> str:
    """Canonical split group so one agent never spans splits."""
    ag = (corresponding_agent or "").strip()
    if not ag:
        return "asb:agent:unknown"
    return f"asb:agent:{ag}"


@register_adapter
class AsbMemoryAdapter(DatasetAdapter):
    """Project pinned ASB attack+normal tools into MEMORY_WRITE (420)."""

    dataset_id = "p5_asb_memory"
    adapter_version = "1.1.0"

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
    def _load_attack_rows(self) -> list[Mapping[str, Any]]:
        if self._entries_provider is not None:
            return list(self._entries_provider)
        fp = self.raw_dir / ATTACK_TOOLS_REL
        if not fp.exists():
            raise DatasetSourceError(
                f"missing ASB attack-tools file: {fp}. "
                f"Run: python -m demotest.cli.main dataset acquire --dataset {self.dataset_id}"
            )
        rows: list[Mapping[str, Any]] = []
        for line in fp.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
        return rows

    def _load_normal_rows(self) -> list[Mapping[str, Any]]:
        # entries_provider is attack-only by contract (Phase 2A tests). Real
        # path reads the pinned file directly; provider injection never fakes
        # normal tools.
        if self._entries_provider is not None:
            return []
        fp = self.raw_dir / NORMAL_TOOLS_REL
        if not fp.exists():
            raise DatasetSourceError(
                f"missing ASB normal-tools file: {fp}. "
                f"Run: python -m demotest.cli.main dataset acquire --dataset {self.dataset_id}"
            )
        rows: list[Mapping[str, Any]] = []
        for line in fp.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
        return rows

    # ------------------------------------------------------------------ iter
    def iter_cases(self) -> Iterator[SecurityCase]:
        attack_rows = self._load_attack_rows()
        normal_rows = self._load_normal_rows()
        # fail-closed only on the REAL path; provider injection skips it
        if self._entries_provider is None:
            if len(attack_rows) != EXPECTED_ATTACK_ENTRIES:
                raise DatasetSourceError(
                    f"ASB attack-tools count drift: expected {EXPECTED_ATTACK_ENTRIES} "
                    f"entries, found {len(attack_rows)} — pinned artifact changed; re-run "
                    "scripts/_p5_asb_projection_proof.py and re-review"
                )
            if len(normal_rows) != EXPECTED_NORMAL_ENTRIES:
                raise DatasetSourceError(
                    f"ASB normal-tools count drift: expected {EXPECTED_NORMAL_ENTRIES} "
                    f"entries, found {len(normal_rows)} — pinned artifact changed; re-review"
                )
        yielded = 0
        for idx, row in enumerate(attack_rows, start=1):
            if self.max_entries and yielded >= self.max_entries:
                break
            yield self._build_attack_case(seq=idx, row=row)
            yielded += 1
        for jdx, row in enumerate(normal_rows, start=1):
            if self.max_entries and yielded >= self.max_entries:
                break
            yield self._build_normal_case(seq=jdx, row=row)
            yielded += 1

    def _build_attack_case(self, *, seq: int, row: Mapping[str, Any]) -> SecurityCase:
        source_id = f"asb:mp:attack:{seq:03d}"
        content = attacker_tool_descriptor(row)
        tool = str(row.get("Attacker Tool") or "")
        corresponding_agent = str(row.get("Corresponding Agent") or "")
        gid = agent_group_id(corresponding_agent)
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
            "corresponding_agent": corresponding_agent,
            "group_id": gid,
            # traceability only — deliberately NOT part of gateway-visible content
            "attacker_instruction": str(row.get("Attacker Instruction") or ""),
            "attack_goal": str(row.get("Attack goal") or ""),
            "arxiv": f"arXiv:{ASB_ARXIV}",
            "quality_tier": "B",
            "derivation": "deterministic_projection",
        }
        case = SecurityCase.from_dict(d)
        prov = SourceProvenance(
            source_dataset="asb",
            source_revision=self._lock_revision(),
            source_id=source_id,
            group_id=gid,
            raw_sha256=_sha256(content),
            normalized_sha256=_sha256(content),
            adapter_name="p5_asb_memory",
            adapter_version=self.adapter_version,
            quality_tier="B",
            derivation="deterministic_projection",
            parent_source_id=source_id,
        )
        return attach_provenance(case, prov)

    def _build_normal_case(self, *, seq: int, row: Mapping[str, Any]) -> SecurityCase:
        source_id = f"asb:mp:normal:{seq:03d}"
        content = normal_tool_descriptor(row)
        tool = str(row.get("Tool Name") or "")
        corresponding_agent = str(row.get("Corresponding Agent") or "")
        gid = agent_group_id(corresponding_agent)
        case = SecurityCase.build(
            dataset_id=self.dataset_id,
            source_id=source_id,
            channel=Channel.MEMORY_WRITE,
            operation=Operation.WRITE_MEMORY,
            direction=Direction.OUTBOUND,
            content=content,
            memory_operation="write",
            memory_target="agent_long_term_memory",
            expected_action=ExpectedAction.ALLOW,
            project_id="P5_memory_write",
            threat_id="memory_poisoning",
            presentation_style="structured",
        )
        d = case.to_dict()
        d["metadata"] = {
            **(d.get("metadata") or {}),
            "source_dataset": "asb",
            "source_revision": self._lock_revision(),
            "source_field": "normal_tool_definition",
            "ground_truth_kind": "normal_memory_tool",
            "attacker_tool": tool,
            "corresponding_agent": corresponding_agent,
            "group_id": gid,
            # provenance only — not gateway-visible
            "expected_achievements": str(row.get("Expected Achievements") or ""),
            "arxiv": f"arXiv:{ASB_ARXIV}",
            "quality_tier": "B",
            "derivation": "deterministic_projection",
        }
        case = SecurityCase.from_dict(d)
        prov = SourceProvenance(
            source_dataset="asb",
            source_revision=self._lock_revision(),
            source_id=source_id,
            group_id=gid,
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
        fp_a = self.raw_dir / ATTACK_TOOLS_REL
        fp_n = self.raw_dir / NORMAL_TOOLS_REL
        rep.add("attack_tools_present", fp_a.exists(), str(fp_a))
        rep.add("normal_tools_present", fp_n.exists(), str(fp_n))
        n_a = n_n = 0
        required_a = {"Attacker Tool", "Description", "Attack Type",
                      "Corresponding Agent", "Aggressive"}
        required_n = {"Tool Name", "Description", "Corresponding Agent"}
        missing_a: set[str] = set()
        missing_n: set[str] = set()
        if fp_a.exists():
            for line in fp_a.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                n_a += 1
                missing_a |= required_a - set(json.loads(line).keys())
        if fp_n.exists():
            for line in fp_n.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                n_n += 1
                missing_n |= required_n - set(json.loads(line).keys())
        rep.add("attack_entries_exact_400", n_a == EXPECTED_ATTACK_ENTRIES, f"n={n_a}")
        rep.add("normal_entries_exact_20", n_n == EXPECTED_NORMAL_ENTRIES, f"n={n_n}")
        rep.add("required_fields_present_attack", not missing_a,
                f"missing={sorted(missing_a)}")
        rep.add("required_fields_present_normal", not missing_n,
                f"missing={sorted(missing_n)}")
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
