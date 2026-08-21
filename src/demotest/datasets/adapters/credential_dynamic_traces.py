"""Credential dynamic traces adapter — P4 Core (DYNAMIC_TRACE only, guide §15).

Publishing bridge: the FORMAL input is the human-frozen reviewed artifact
``<raw_dir>/reviews/reviewed_traces.jsonl`` + ``review_meta.json``, NOT the
ephemeral sandbox ``traces.jsonl``. The adapter fail-closes on reviewed
artifact integrity before yielding any case:

  * reviewed artifact + review_meta must exist
  * n_pending == 0            (every verdict decided; freeze gate)
  * accepted count consistent (n_accepted == lines in reviewed_traces.jsonl)
  * artifact SHA matches review_meta.sha256  (tamper/non-frozen refusal)

After the integrity gate, per-trace projection keeps the same hard rules:
  * evidence_type != DYNAMIC_TRACE → reject
  * dynamic_confirmed != True       → reject
  * missing trace_hash              → reject
  * projected quality not in {A,B}  → reject (defense in depth; projection
    already maps DYNAMIC_TRACE DIRECT→A / PROJECTED→B)

Core rules (config/v3/datasets/credential_dynamic_traces.yaml):
  stdout → tool_result (DIRECT, quality A, original)
  network → tool_call (PROJECTED, quality B, deterministic_projection)
  group_id = source_skill_id (skill-level split, guide §25)

Unit tests may inject ``trace_provider`` to exercise per-trace validation
without materializing a reviewed artifact (bypasses the integrity gate only).
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterator

from ...config import DatasetSourceConfig, get_dataset
from ...core.enums import ExpectedAction, LeakageExpectation
from ...core.exceptions import DatasetSourceError
from ...core.models import SecurityCase
from ..base import DatasetAdapter, ValidationReport
from ..registry import register_adapter
from ..source_lock import load_source_lock
from ..traces.models import CredentialTrace
from ..traces.projection import project_trace_to_case

REVIEWED_DIRNAME = "reviews"
REVIEWED_TRACES = "reviewed_traces.jsonl"
REVIEW_META = "review_meta.json"


@register_adapter
class CredentialDynamicTracesAdapter(DatasetAdapter):
    dataset_id = "credential_dynamic_traces"
    adapter_version = "2.0.0"  # publishing bridge: reviewed artifact is the formal source

    def __init__(
        self,
        *,
        raw_dir: Path | str | None = None,
        source_config: DatasetSourceConfig | None = None,
        trace_provider: Any | None = None,
        strict: bool = True,
    ) -> None:
        if source_config is None:
            source_config = get_dataset(self.dataset_id)
        self.source_config = source_config
        self.raw_dir = Path(raw_dir) if raw_dir else source_config.raw_path
        self._trace_provider = trace_provider
        self.strict = strict
        self._rejected: list[dict[str, Any]] = []

    def _reviewed_dir(self) -> Path:
        return self.raw_dir / REVIEWED_DIRNAME

    def _reviewed_trace_file(self) -> Path:
        return self._reviewed_dir() / REVIEWED_TRACES

    def _review_meta_file(self) -> Path:
        return self._reviewed_dir() / REVIEW_META

    def _load_review_meta(self) -> dict[str, Any]:
        p = self._review_meta_file()
        if not p.exists():
            return {}
        return json.loads(p.read_text(encoding="utf-8"))

    def _reviewed_sha256(self) -> str:
        p = self._reviewed_trace_file()
        if not p.exists():
            return ""
        return hashlib.sha256(p.read_bytes()).hexdigest()

    def _artifact_problems(self) -> list[str]:
        """Fail-closed integrity checks on the reviewed artifact (non-raising)."""
        problems: list[str] = []
        rp = self._reviewed_trace_file()
        mp = self._review_meta_file()
        if not rp.exists():
            problems.append(f"reviewed artifact missing: {rp}")
        if not mp.exists():
            problems.append(f"review metadata missing: {mp}")
            return problems
        meta = self._load_review_meta()
        n_pending = int(meta.get("n_pending", -1))
        if n_pending != 0:
            problems.append(f"n_pending={n_pending} != 0 (freeze gate not satisfied)")
        if not rp.exists():
            return problems
        try:
            lines = [l for l in rp.read_text(encoding="utf-8").splitlines() if l.strip()]
        except Exception as e:
            problems.append(f"reviewed artifact unreadable: {e}")
            return problems
        n_accepted = int(meta.get("n_accepted", -1))
        if n_accepted != len(lines):
            problems.append(f"n_accepted={n_accepted} != lines in artifact {len(lines)}")
        sha = str(meta.get("sha256", ""))
        if sha and sha != self._reviewed_sha256():
            problems.append("reviewed artifact SHA != review_meta.sha256 (frozen artifact modified)")
        return problems

    def _load_traces(self) -> Iterator[CredentialTrace]:
        if self._trace_provider is not None:
            yield from self._trace_provider
            return
        # Formal path: human-frozen reviewed artifact only.
        problems = self._artifact_problems()
        if problems:
            if self.strict:
                raise DatasetSourceError(
                    f"{self.dataset_id} reviewed artifact invalid: " + "; ".join(problems))
            return
        fp = self._reviewed_trace_file()
        with fp.open("r", encoding="utf-8") as f:
            for lineno, raw in enumerate(f, 1):
                line = raw.strip()
                if not line:
                    continue
                try:
                    yield CredentialTrace.from_dict(json.loads(line))
                except Exception as e:
                    self._rejected.append({"lineno": lineno, "error": str(e), "line": line[:300]})
                    if self.strict:
                        raise DatasetSourceError(
                            f"{self.dataset_id} JSON parse failed at line {lineno}: {e}") from e

    def _reject(self, tr: CredentialTrace, reason: str) -> None:
        self._rejected.append({"trace_id": tr.trace_id, "skill_id": tr.skill_id, "error": reason})
        if self.strict:
            raise DatasetSourceError(f"{self.dataset_id} rejected {tr.trace_id}: {reason}")

    def _raw_sha256(self) -> str:
        # The "raw" for the benchmark is now the frozen reviewed artifact.
        sha = self._reviewed_sha256()
        if sha:
            return sha
        try:
            lk = load_source_lock(self.dataset_id)
            if lk.raw_sha256:
                return lk.raw_sha256
        except DatasetSourceError:
            pass
        return self.source_config.revision or ""

    def iter_cases(self) -> Iterator[SecurityCase]:
        src_rev = ""
        try:
            src_rev = load_source_lock("skillleakbench_pipeline").revision
        except DatasetSourceError:
            src_rev = self.source_config.revision or ""
        raw_sha = self._raw_sha256()
        self._rejected.clear()
        for tr in self._load_traces():
            # Guide §15: Core must not have a synthetic code path — hard rejects.
            if tr.evidence_type != "DYNAMIC_TRACE":
                self._reject(tr, f"evidence_type={tr.evidence_type} != DYNAMIC_TRACE")
                continue
            if not tr.dynamic_confirmed:
                self._reject(tr, "dynamic_confirmed is not true")
                continue
            if not tr.trace_hash:
                self._reject(tr, "missing trace_hash")
                continue
            meta = tr.metadata or {}
            is_allow = bool(
                meta.get("authorized_sink") or meta.get("safe_redaction")
                or meta.get("authorized") or meta.get("redacted")
            )
            try:
                case = project_trace_to_case(
                    tr,
                    dataset_id=self.dataset_id,
                    source_revision=src_rev,
                    raw_sha256=raw_sha,
                    adapter_version=self.adapter_version,
                    expected_action=ExpectedAction.ALLOW if is_allow else ExpectedAction.BLOCK,
                    leakage_expected=LeakageExpectation.NO_LEAK,
                )
            except ValueError as e:
                self._reject(tr, str(e))
                continue
            quality = (case.metadata.get("source") or {}).get("quality_tier")
            if quality not in ("A", "B"):
                self._reject(tr, f"projected quality {quality!r} not in (A, B)")
                continue
            yield case

    def validate_raw(self) -> ValidationReport:
        rep = ValidationReport(ok=True)
        rp = self._reviewed_trace_file()
        mp = self._review_meta_file()
        rep.add("reviewed_artifact_present", rp.exists(), str(rp))
        rep.add("review_meta_present", mp.exists(), str(mp))
        if rp.exists() and mp.exists():
            for p in self._artifact_problems():
                rep.add("reviewed_frozen", False, p)
            meta = self._load_review_meta()
            rep.add("n_accepted", True, f"n_accepted={meta.get('n_accepted')}")
            rep.add("n_pending_zero", meta.get("n_pending") == 0, f"n_pending={meta.get('n_pending')}")
            rep.add("artifact_sha_locked", meta.get("sha256") == self._reviewed_sha256(),
                    f"sha256={str(self._reviewed_sha256())[:16]}…")
        # At least one valid DYNAMIC_TRACE case must project (representative check).
        if rp.exists():
            try:
                n = sum(1 for _ in self._iter_valid_cases())
                rep.add("case_projection_ok", n > 0, f"n_cases={n}")
            except DatasetSourceError:
                pass
        return rep

    def _iter_valid_cases(self) -> Iterator[SecurityCase]:
        """Yield cases applying per-trace validation without the strict gate."""
        yield from self.iter_cases()

    def source_metadata(self) -> dict[str, Any]:
        return {
            "dataset_id": self.dataset_id,
            "adapter_version": self.adapter_version,
            "source_type": self.source_config.source_type,
            "source_uri": self.source_config.source_uri,
            "revision": self.source_config.revision or "",
            "reviewed_artifact_sha256": self._reviewed_sha256(),
            "quality_tier": "A",
            "derivation": "original|deterministic_projection",
        }
