"""MCPTox adapter — pinned zhiqiangwang4/MCPTox-Benchmark -> MCP_DEFINITION.

Case unit: one poisoned MCP tool definition.
Primary source: pure_tool.json (485 poisoned definitions, deduped, one per def_tool/*.py).
  Each entry maps "<Server>_<N>" -> {server_name, tool_name, query, tool_content,
  security risk, paradigm, tool_address}.  tool_content is the poisoned description
  the gateway would see.

Projection (guide Phase 3A + requirement):
  * gateway-visible: only server_name + tool_name + tool_content (byte-identical)
    -> SecurityCase(mcp_server, mcp_tool, mcp_description)
  * metadata-only: query, security risk, paradigm, tool_address, dataset,
    source_case_id, derivation, quality_tier.  These must never be concatenated
    into the rendered payload (content / mcp_description).

The adapter does not synthesize, paraphrase, or expand benign data.  It also
does not execute MCP servers or evaluate Agent susceptibility.  That belongs to
response_all.json's agent study, not this gateway content guard.

Revision: f85189f9ad12504c197c7f920ab818a40657b1fa
  pure_tool.json   SHA256 9a321dc4ecf4869883cf2a29ea8189e1f7663720a9c41a3e5ce2323d580e31c1  (485 flat)
  response_all.json  SHA256 4f8177dcbe3718ce3d6ea6a0eec8fa27813158179bd30afe340fe854e886fdf5  (1348 raw / 36 wrong / 1312 valid, not yet frozen as BLOCK)
  def_tool/: 485 files cross-checked (484 exact strip-equality, 1 upstream truncation at def_tool/10.py).

The 1312 number lives in response_all.json, not pure_tool.json.  Until a separate
freeze decision chooses the response valid set as BLOCK, the adapter's iterable
is pure_tool's 485 deduplicated definitions (attack-only).  Both SHAs are recorded
for traceability even though only pure drives cases today.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterator, Mapping

from ...config import DatasetSourceConfig, get_dataset, load_dataset_projection
from ...core.enums import Channel, ExpectedAction, Operation
from ...core.exceptions import DatasetSourceError
from ...core.models import SecurityCase
from ..base import DatasetAdapter, ValidationReport
from ..quality import SourceProvenance, attach_provenance
from ..registry import register_adapter
from ..source_lock import load_source_lock

EXPECTED_PURE_ENTRIES = 485
EXPECTED_SERVERS = 45
# Pin provenance for the current audit; the adapter still reads the live files
# so re-pinning requires re-running the audit and bumping adapter_version.
MCPTOX_REVISION = "f85189f9ad12504c197c7f920ab818a40657b1fa"
MCPTOX_PURE_SHA256 = "9a321dc4ecf4869883cf2a29ea8189e1f7663720a9c41a3e5ce2323d580e31c1"
MCPTOX_RESPONSE_SHA256 = "4f8177dcbe3718ce3d6ea6a0eec8fa27813158179bd30afe340fe854e886fdf5"


def mcptox_group_id(server_name: str) -> str:
    """Canonical split group so one server never spans splits."""
    s = (server_name or "").strip()
    if not s:
        return "mcptox:server:unknown"
    return f"mcptox:server:{s}"


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


@register_adapter
class P3MCPToxAdapter(DatasetAdapter):
    """Project pinned MCPTox poisoned definitions into MCP_DEFINITION (BLOCK)."""

    dataset_id = "p3_mcptox"
    adapter_version = "1.0.0"

    def __init__(
        self,
        *,
        raw_dir: Path | str | None = None,
        source_config: DatasetSourceConfig | None = None,
        entries_provider: "list[Mapping[str, Any]] | None" = None,
        max_entries: int | None = None,
    ) -> None:
        if source_config is None:
            try:
                source_config = get_dataset(self.dataset_id)
            except Exception:
                # Until datasets.yaml registers p3_mcptox, synthesize a config
                # pointing at the probe clone — tests and proof use this path.
                source_config = DatasetSourceConfig(
                    name=self.dataset_id,
                    adapter="p3_mcptox",
                    adapter_version=self.adapter_version,
                    source_type="github",
                    source_uri="https://github.com/zhiqiangwang4/MCPTox-Benchmark",
                    revision=MCPTOX_REVISION,
                    license="UNRESOLVED",
                    raw_dir="cache/probe/mcptox",
                    normalized_dir="cache/datasets_v3/normalized/p3_mcptox",
                )
        self.source_config = source_config
        # raw_dir override wins; otherwise use configured raw_path / probe fallback
        if raw_dir is not None:
            self.raw_dir = Path(raw_dir)
        else:
            try:
                self.raw_dir = Path(source_config.raw_path)  # type: ignore[attr-defined]
            except Exception:
                self.raw_dir = Path(getattr(source_config, "raw_dir", "cache/probe/mcptox"))
        try:
            self.projection = load_dataset_projection(self.dataset_id)
        except Exception:
            self.projection = None  # type: ignore[assignment]
        self._entries_provider = entries_provider
        self.max_entries = max_entries

    # ------------------------------------------------------------------ revision
    def _lock_revision(self) -> str:
        if getattr(self.source_config, "revision", None):
            return str(self.source_config.revision)
        try:
            return load_source_lock(self.dataset_id).revision
        except DatasetSourceError:
            return MCPTOX_REVISION

    # ------------------------------------------------------------------ rows
    def _load_flat(self) -> dict[str, Mapping[str, Any]]:
        """Load pure_tool.json as flat {case_key: row} dict (485 entries)."""
        if self._entries_provider is not None:
            # Test injection: treat provider as flat dict values keyed by any id
            # Callers pass a list of already-shaped rows or a dict; normalize here.
            if isinstance(self._entries_provider, dict):  # type: ignore[arg-type]
                return dict(self._entries_provider)  # type: ignore[return-value]
            # list[Mapping]: synthesize keys from server_name+tool_name if needed
            out: dict[str, Mapping[str, Any]] = {}
            for idx, row in enumerate(self._entries_provider):  # type: ignore[arg-type]
                key = str(row.get("_key") or row.get("source_case_id") or f"injected_{idx}")
                out[key] = row
            return out
        fp = self.raw_dir / "pure_tool.json"
        if not fp.exists():
            raise DatasetSourceError(
                f"missing MCPTox pure_tool.json: {fp}. "
                f"Expected probe clone at {self.raw_dir} (revision {self._lock_revision()}). "
                f"Run: git clone https://github.com/zhiqiangwang4/MCPTox-Benchmark {self.raw_dir} && git -C {self.raw_dir} checkout {MCPTOX_REVISION}"
            )
        data = json.loads(fp.read_text(encoding="utf-8"))
        # pure_tool.json is a list of 45 dicts: [{FileSystem_1: {...}, ...}, ...]
        flat: dict[str, Mapping[str, Any]] = {}
        if isinstance(data, dict):
            flat.update(data)
        elif isinstance(data, list):
            for group in data:
                if isinstance(group, dict):
                    flat.update(group)
        return flat

    # ------------------------------------------------------------------ iter
    def iter_cases(self) -> Iterator[SecurityCase]:
        flat = self._load_flat()
        if self._entries_provider is None:
            if len(flat) != EXPECTED_PURE_ENTRIES:
                raise DatasetSourceError(
                    f"MCPTox pure_tool count drift: expected {EXPECTED_PURE_ENTRIES}, "
                    f"found {len(flat)} — pinned artifact changed; re-run Phase 3A audit"
                )
        # Deterministic order by source key so case_id ordering is stable pre-split
        yielded = 0
        for key in sorted(flat.keys()):
            if self.max_entries and yielded >= self.max_entries:
                break
            row = flat[key]
            yield self._build_case(source_case_id=key, row=row)
            yielded += 1

    def _build_case(self, *, source_case_id: str, row: Mapping[str, Any]) -> SecurityCase:
        server_name = str(row.get("server_name") or "")
        tool_name = str(row.get("tool_name") or "")
        # Gateway-visible: byte-identical tool_content as stored in pure_tool.json
        # Do not strip the leading space that pure consistently carries; the audit
        # records that pure values start with " " (e.g. " Initiates...").
        tool_content = str(row.get("tool_content") or "")
        # Metadata-only
        query = str(row.get("query") or "")
        security_risk = str(row.get("security risk") or row.get("security_risk") or "")
        paradigm = str(row.get("paradigm") or "")
        tool_address = str(row.get("tool_address") or "")
        gid = mcptox_group_id(server_name)
        source_id = f"mcptox:{server_name}:{source_case_id}"
        # mcp_description carries the poisoned definition verbatim
        case = SecurityCase.build(
            dataset_id=self.dataset_id,
            source_id=source_id,
            channel=Channel.MCP_DEFINITION,
            operation=Operation.REGISTER_TOOL,
            content=tool_content,
            expected_action=ExpectedAction.BLOCK,
            project_id="P3_mcp_definition",
            threat_id="mcp_definition_poisoning",
            presentation_style="structured",
            mcp_server=server_name,
            mcp_tool=tool_name,
            mcp_description=tool_content,
            mcp_schema={},
        )
        d = case.to_dict()
        d["metadata"] = {
            **(d.get("metadata") or {}),
            "source_dataset": "mcptox",
            "source_revision": self._lock_revision(),
            "source_case_id": source_case_id,
            "server_name": server_name,
            "tool_name": tool_name,
            "tool_address": tool_address,
            "security_risk": security_risk,
            "paradigm": paradigm,
            "quality_tier": "B",
            "derivation": "deterministic_projection",
            "group_id": gid,
            # Traceability only — never gateway-visible; renderer must not emit these
            "query": query,
            "pure_sha256": MCPTOX_PURE_SHA256,
            "response_sha256": MCPTOX_RESPONSE_SHA256,
        }
        case = SecurityCase.from_dict(d)
        # Provenance: raw is the exact description text hence content-addressable
        prov = SourceProvenance(
            source_dataset="mcptox",
            source_revision=self._lock_revision(),
            source_id=source_id,
            group_id=gid,
            raw_sha256=_sha256_text(tool_content),
            normalized_sha256=_sha256_text(tool_content),
            adapter_name="p3_mcptox",
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
        fp_pure = self.raw_dir / "pure_tool.json"
        fp_resp = self.raw_dir / "response_all.json"
        rep.add("pure_tool_present", fp_pure.exists(), str(fp_pure))
        # response_all is not required for the adapter's iteration, but the
        # audit's 1312 number is pinned there, so flag its presence.
        rep.add("response_all_present", fp_resp.exists(), str(fp_resp))
        # def_tool count
        def_dir = self.raw_dir / "def_tool"
        def_count = len(list(def_dir.glob("*.py"))) if def_dir.exists() else 0
        rep.add("def_tool_count_485", def_count == 485, f"n={def_count}")
        if fp_pure.exists():
            try:
                data = json.loads(fp_pure.read_text(encoding="utf-8"))
                flat: dict[str, Any] = {}
                if isinstance(data, dict):
                    flat.update(data)
                elif isinstance(data, list):
                    for g in data:
                        if isinstance(g, dict):
                            flat.update(g)
                rep.add("pure_flat_485", len(flat) == EXPECTED_PURE_ENTRIES, f"n={len(flat)}")
                # field completeness
                missing = 0
                for v in flat.values():
                    if not v.get("server_name") or not v.get("tool_name") or not v.get("tool_content") or not v.get("tool_address"):
                        missing += 1
                rep.add("required_fields_present", missing == 0, f"missing_rows={missing}")
                servers = {str(v.get("server_name") or "") for v in flat.values()}
                rep.add("servers_45", len(servers) == EXPECTED_SERVERS, f"n={len(servers)}")
                # wrong_data absent in pure (1312 lives in response_all)
                has_wrong = sum(1 for v in flat.values() if "wrong_data" in v)
                rep.add("pure_has_no_wrong_data", has_wrong == 0, f"n={has_wrong}")
            except Exception as e:
                rep.add("pure_parse_ok", False, str(e))
        if fp_resp.exists():
            try:
                data = json.loads(fp_resp.read_text(encoding="utf-8"))
                total = sum(len(obj.get("malicious_instance") or []) for obj in (data.get("servers") or {}).values())
                wrong = sum(1 for obj in (data.get("servers") or {}).values() for mal in (obj.get("malicious_instance") or []) if mal.get("wrong_data"))
                rep.add("response_total_1348", total == 1348, f"n={total}")
                rep.add("response_wrong_36", wrong == 36, f"n={wrong}")
                rep.add("response_valid_1312", (total - wrong) == 1312, f"n={total - wrong}")
            except Exception as e:
                rep.add("response_parse_ok", False, str(e))
        # license explicitly unresolved (F10 / source audit gate)
        rep.add("license_unresolved", True, "zhiqiangwang4/MCPTox-Benchmark has no LICENSE at f85189f — REDISTRIBUTION NOT ASSUMED")
        return rep

    def source_metadata(self) -> dict[str, Any]:
        return {
            "dataset_id": self.dataset_id,
            "adapter_version": self.adapter_version,
            "source_type": getattr(self.source_config, "source_type", "github"),
            "source_uri": getattr(self.source_config, "source_uri", "https://github.com/zhiqiangwang4/MCPTox-Benchmark"),
            "revision": self._lock_revision(),
            "license": "UNRESOLVED",
            "pure_sha256": MCPTOX_PURE_SHA256,
            "response_sha256": MCPTOX_RESPONSE_SHA256,
            "quality_tier": "B",
            "derivation": "deterministic_projection",
        }
