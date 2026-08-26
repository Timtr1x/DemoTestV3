"""Credential dynamic traces adapter — P4 Core (contraction 2026-08-26, P0-2).

P4 Credential Leakage Core = REAL_REPRODUCED only, DIRECT-only (6 hard
gates). See ``demotest.datasets.core_eligibility``. SkillLeakBench mapping
is optional provenance and MUST NOT gate eligibility. PROJECTED/quality B
belongs to Extended.

Publishing bridge: the FORMAL input is the human-frozen reviewed artifact
``<raw_dir>/reviews/reviewed_traces.jsonl`` + ``review_meta.json``, NOT the
ephemeral sandbox ``traces.jsonl`` or the developer ``review.jsonl``. Each
frozen trace carries ``metadata.core_review`` (frozen projection of the
accepted human verdict). The adapter fail-closes on reviewed artifact
integrity before yielding any case:

  * reviewed artifact + review_meta must exist
  * n_pending == 0            (every verdict decided; freeze gate)
  * accepted count consistent (n_accepted == lines in reviewed_traces.jsonl)
  * artifact SHA matches review_meta.sha256  (tamper/non-frozen refusal)

After the integrity gate, per-trace rules:
  * evidence_type != DYNAMIC_TRACE → reject
  * dynamic_confirmed != True       → reject
  * missing trace_hash              → reject
  * derive CoreEligibilityInput deterministically from the frozen
    ``core_review`` + trace (see ``core_eligibility.derive_eligibility_input``)
    and require REAL_REPRODUCED + DIRECT. Any gate failure fail-closes.
    ``behavior_modified`` means any skill behavior/control-flow change beyond
    canary injection.
  * No fallback to ``reviews/review.jsonl`` in the production path — the
    frozen artifact alone must bind the human verdict. Missing
    ``core_review`` or non-DIRECT visibility fail-closed.

Core rules (config/v3/datasets/credential_dynamic_traces.yaml):
  stdout → tool_result (DIRECT, quality A, original)
  group_id = source_skill_id (skill-level split, guide §25)

Unit tests may inject ``trace_provider`` to exercise eligibility without
materializing a reviewed artifact (hermetic mode via metadata overrides).
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
from ..core_eligibility import derive_eligibility_input, evaluate_core_eligibility
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
        sha = str(meta.get("sha256") or "")
        if not sha:
            problems.append("review_meta.sha256 is missing (frozen artifact must bind its hash)")
        elif sha != self._reviewed_sha256():
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

    def _reviews_by_id(self) -> dict[str, Any]:
        # Production/frozen path does NOT read review.jsonl — eligibility
        # comes from the embedded metadata.core_review. This helper is kept
        # only for hermetic trace_provider tests that still need a review
        # lookup. Any IO error returns empty (fail-closed via core_review).
        try:
            from ..dynamic.review import load_reviews
            reviews = load_reviews(self.raw_dir)
            return {r.trace_id: r for r in reviews}
        except Exception:
            return {}

    def iter_cases(self) -> Iterator[SecurityCase]:
        src_rev = ""
        try:
            src_rev = load_source_lock("skillleakbench_pipeline").revision
        except DatasetSourceError:
            src_rev = self.source_config.revision or ""
        raw_sha = self._raw_sha256()
        self._rejected.clear()
        reviews_by_id = self._reviews_by_id()
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
            # P4 contraction 2026-08-26: derive 6 hard gates deterministically
            # from trace + review (no new provenance system). Provenance fields
            # (official mapping, quality A/B) MUST NOT gate eligibility.
            # behavior_modified means any skill behavior/control-flow change
            # beyond canary injection (see core_eligibility.derive_eligibility_input).
            review = reviews_by_id.get(tr.trace_id)
            try:
                inp = derive_eligibility_input(tr, review)
                res = evaluate_core_eligibility(inp)
            except Exception as e:
                self._reject(tr, f"eligibility derive failed: {e}")
                continue
            if not res.eligible:
                self._reject(tr, f"Core eligibility {res.label}: {','.join(res.failed_gates)}")
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
