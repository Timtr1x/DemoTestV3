"""AgentDojo adapter — ETH Zurich benchmark -> SecurityCase (guide §17-§29).

AgentDojo is an *executable* benchmark: ground truth (UserTask / InjectionTask /
environment injection vectors / ground-truth tool calls) lives in the suite/task
code at the pinned commit. This adapter imports the official suite objects and
projects them **deterministically** into SecurityCase — it does NOT regex-parse
source, does NOT ask an LLM to (re)write attacks (guide §21, §24, §25, §52).

One original security case (a UserTask x InjectionTask pairing) yields ONE
derived case in core:

  * tool_call    (channel=TOOL_CALL, project P2) — the dangerous tool call the
    injection would induce, taken from InjectionTask.ground_truth (guide §19).

P1 tool_result from default injection vectors was removed from core (guide P0-2):
get_injection_vector_defaults() is environment content, not an attacker payload;
the constructed content also leaked the attacker goal. AgentDojo P1 may return
only as an Extended/Regression track.
(guide §22). Each gets an independent ``source_id`` (``agentdojo:<parent>:tool_result``
/ ``...:tool_call``) and the lineage is recorded in metadata (guide §20).

The real projection imports ``agentdojo`` from the pinned clone (``pip install -e
cache/datasets_v3/raw/agentdojo``, guide §19); the import is lazy so the module
loads and unit tests run without it — tests inject synthetic task fixtures
shaped like the real objects (same attribute names: PROMPT, GOAL,
ground_truth(env) -> [FunctionCall(function, args)], injection vector text).
"""
from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator, Protocol

from ...config import DatasetSourceConfig, get_dataset, load_dataset_projection
from ...core.enums import ExpectedAction
from ...core.exceptions import DatasetSourceError
from ...core.models import SecurityCase
from ..base import DatasetAdapter, ValidationReport
from ..dedup import normalize_text
from ..quality import SourceProvenance, attach_provenance
from ..registry import register_adapter
from ..source_lock import load_source_lock


# --------------------------------------------------------------------------
# Lightweight task object protocols (duck-typed; match the real agentdojo API)
# --------------------------------------------------------------------------
class _FunctionCall(Protocol):
    function: str
    args: dict[str, Any]


@dataclass
class SyntheticFunctionCall:
    function: str
    args: dict[str, Any]


class _InjectionTask(Protocol):
    ID: str
    GOAL: str

    def ground_truth(self, pre_environment: Any) -> list[_FunctionCall]: ...


class _UserTask(Protocol):
    ID: str
    PROMPT: str


@dataclass
class InjectedTaskPair:
    """A UserTask + the InjectionTask paired with it, plus the injection text.

    This is the unit one original security case becomes. The real loader
    produces these from the official suite; tests construct them directly.
    """

    suite: str
    user_task_id: str
    user_prompt: str
    injection_task_id: str
    injection_goal: str
    injection_text: str          # the injected tool-result content the agent sees
    ground_truth_calls: list[_FunctionCall]  # dangerous tool calls (P2)


def _sha(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", errors="replace")).hexdigest()


@register_adapter
class AgentDojoAdapter(DatasetAdapter):
    """Project pinned AgentDojo security cases into TOOL_RESULT + TOOL_CALL cases."""

    dataset_id = "agentdojo"
    adapter_version = "1.1.0"

    def __init__(
        self,
        *,
        raw_dir: Path | str | None = None,
        source_config: DatasetSourceConfig | None = None,
        benchmark_version: str | None = None,
        suites: list[str] | None = None,
        task_provider: "Iterable[InjectedTaskPair] | None" = None,
        max_per_suite: int | None = None,
    ) -> None:
        if source_config is None:
            source_config = get_dataset(self.dataset_id)
        self.source_config = source_config
        self.raw_dir = Path(raw_dir) if raw_dir else source_config.raw_path
        self.projection = load_dataset_projection(self.dataset_id)
        self.benchmark_version = benchmark_version or self.projection.benchmark_version or "v1"
        self.suites = suites or self.projection.suites or ["workspace", "travel", "banking", "slack"]
        # When provided (tests / pre-built inventory), skip the heavy import.
        self._task_provider = task_provider
        self.max_per_suite = max_per_suite

    # ------------------------------------------------------------------ revision
    def _lock_revision(self) -> str:
        if self.source_config.revision:
            return self.source_config.revision
        try:
            return load_source_lock(self.dataset_id).revision
        except DatasetSourceError:
            return self.source_config.revision

    # ------------------------------------------------------------------ tasks
    def _load_pairs(self) -> Iterator[InjectedTaskPair]:
        if self._task_provider is not None:
            yield from self._task_provider
            return
        yield from self._load_real_pairs()

    def _load_real_pairs(self) -> Iterator[InjectedTaskPair]:
        """Import the official pinned suite and enumerate security cases.

        Each InjectionTask is one official security case (guide §25). We pair
        every injection task with every user task in its suite — this is how
        agentdojo's own benchmark enumerates the security test matrix
        (utility x security). For ground_truth we build the POPULATED default
        environment via ``load_and_inject_default_environment({})`` (not the
        bare ``environment_type()`` class), so tool args resolve correctly.

        The injected content the agent observes (guide §24) is the injection
        vector default text from ``get_injection_vector_defaults()`` — the
        actual attacker payload embedded in the environment — concatenated so
        the tool_result case carries real injected data, not just the GOAL.
        """
        src = str(self.raw_dir / "src")
        if src not in sys.path:
            sys.path.insert(0, src)
        try:
            from agentdojo.task_suite.load_suites import get_suites  # type: ignore
        except ImportError as e:  # pragma: no cover — needs the pinned clone installed
            raise DatasetSourceError(
                f"agentdojo import failed from {src}: {e}. "
                "Run: pip install -e cache/datasets_v3/raw/agentdojo (guide §19)"
            ) from e

        suites = get_suites(self.benchmark_version)
        for suite_name in self.suites:
            if suite_name not in suites:
                continue
            suite = suites[suite_name]
            count = 0
            # build the populated default environment ONCE per suite (expensive)
            try:
                env = suite.load_and_inject_default_environment({})  # type: ignore[attr-defined]
            except Exception:
                env = None
            # injection vector defaults are the real attacker payloads (guide §24)
            try:
                ivd = suite.get_injection_vector_defaults()  # type: ignore[attr-defined]
            except Exception:
                ivd = {}
            injection_text = "\n---\n".join(str(v) for v in ivd.values() if v)
            for it_id, it in getattr(suite, "injection_tasks", {}).items():
                # ground_truth needs the populated env
                try:
                    calls = it.ground_truth(env) if env is not None else []  # type: ignore[arg-type]
                except Exception:
                    calls = []
                # pair with each user task (utility x security matrix)
                for ut_id, ut in getattr(suite, "user_tasks", {}).items():
                    yield InjectedTaskPair(
                        suite=suite_name,
                        user_task_id=str(ut_id),
                        user_prompt=getattr(ut, "PROMPT", "") or "",
                        injection_task_id=str(it_id),
                        injection_goal=getattr(it, "GOAL", "") or "",
                        injection_text=injection_text,
                        ground_truth_calls=list(calls or []),
                    )
                    count += 1
                    if self.max_per_suite and count >= self.max_per_suite:
                        break
                if self.max_per_suite and count >= self.max_per_suite:
                    break

    def _injection_text_for(self, suite: Any, suite_name: str) -> str:
        """Kept for backward compat / tests; real path uses injection_vector_defaults."""
        try:
            text = suite.read_injection_vectors()  # type: ignore[attr-defined]
            if isinstance(text, str) and text.strip():
                return text
        except Exception:
            pass
        try:
            from agentdojo.task_suite.task_suite import read_suite_file  # type: ignore
            return read_suite_file(suite_name, "injection_vectors.yaml", suite.data_path)
        except Exception:
            return ""

    # ------------------------------------------------------------------ iter
    def iter_cases(self) -> Iterator[SecurityCase]:
        for pair in self._load_pairs():
            parent = f"agentdojo:{pair.suite}:{pair.user_task_id}:{pair.injection_task_id}"
            # P2 only in core (P1 tool_result from default vectors removed — guide P0-2)
            for step, call in enumerate(pair.ground_truth_calls or [], start=1):
                yield self._build_tool_call_case(pair=pair, parent=parent, call=call, step=step)

    def _make_prov(self, *, source_id: str, content: str, parent: str) -> SourceProvenance:
        raw = _sha(content)
        nsha = _sha(normalize_text(content))
        return SourceProvenance(
            source_dataset=self.dataset_id,
            source_revision=self._lock_revision(),
            source_id=source_id,
            group_id=parent,
            raw_sha256=raw,
            normalized_sha256=nsha,
            adapter_name="agentdojo",
            adapter_version=self.adapter_version,
            quality_tier="B",
            derivation="deterministic_projection",
            parent_source_id=parent,
        )

    def _common_meta(self, pair: InjectedTaskPair, derived_channel: str, step: int) -> dict[str, Any]:
        return {
            "source_dataset": "agentdojo",
            "source_task_id": pair.user_task_id,
            "source_security_case_id": pair.injection_task_id,
            "environment": pair.suite,
            "user_task": pair.user_prompt,
            "attack": pair.injection_goal,
            "trajectory_step": step,
            "derived_channel": derived_channel,
            "parent_source_id": f"agentdojo:{pair.suite}:{pair.user_task_id}:{pair.injection_task_id}",
            "quality_tier": "B",
            "derivation": "deterministic_projection",
            "benchmark_version": self.benchmark_version,
        }

    def _build_tool_result_case(
        self, *, pair: InjectedTaskPair, parent: str, content: str, raw_inj: str
    ) -> SecurityCase:
        source_id = f"{parent}:tool_result"
        case = SecurityCase.build(
            dataset_id=self.dataset_id,
            source_id=source_id,
            channel="tool_result",
            operation="read",
            direction="inbound",
            content=content,
            tool_result=raw_inj,        # the injected observation verbatim (RAW fallback)
            user_intent=pair.user_prompt,
            expected_action=ExpectedAction.BLOCK,
            project_id="P1_external_instruction",
            threat_id="tool_result_injection",
            presentation_style="structured",
        )
        d = case.to_dict()
        d["metadata"] = {**(d.get("metadata") or {}), **self._common_meta(pair, "tool_result", 1)}
        case = SecurityCase.from_dict(d)
        return attach_provenance(case, self._make_prov(source_id=source_id, content=content, parent=parent))

    def _build_tool_call_case(
        self, *, pair: InjectedTaskPair, parent: str, call: _FunctionCall, step: int
    ) -> SecurityCase:
        source_id = f"{parent}:tool_call:{step}"
        tool_name = getattr(call, "function", "") or ""
        args = dict(getattr(call, "args", {}) or {})
        # realistic tool-call envelope carrying user_intent so each (user_task x
        # injection) pair is distinct; the gateway would see this exact dispatch.
        envelope = {
            "tool": tool_name,
            "arguments": args,
            "user_intent": pair.user_prompt,
        }
        content = json.dumps(envelope, sort_keys=True, ensure_ascii=False)
        case = SecurityCase.build(
            dataset_id=self.dataset_id,
            source_id=source_id,
            channel="tool_call",
            operation="execute_tool",
            direction="outbound",
            content=content,
            tool_name=tool_name,
            tool_arguments=args,
            user_intent=pair.user_prompt,
            expected_action=ExpectedAction.BLOCK,
            project_id="P2_tool_action",
            threat_id="dangerous_tool_call",
            presentation_style="structured",
        )
        d = case.to_dict()
        d["metadata"] = {**(d.get("metadata") or {}), **self._common_meta(pair, "tool_call", step)}
        case = SecurityCase.from_dict(d)
        return attach_provenance(case, self._make_prov(source_id=source_id, content=content, parent=parent))

    # ------------------------------------------------------------------ validate
    def validate_raw(self) -> ValidationReport:
        rep = ValidationReport(ok=True)
        rep.add("clone_present", self.raw_dir.exists(), str(self.raw_dir))
        head = self.raw_dir / "src" / "agentdojo"
        rep.add("src_present", head.exists(), str(head))
        return rep

    def source_metadata(self) -> dict[str, Any]:
        return {
            "dataset_id": self.dataset_id,
            "adapter_version": self.adapter_version,
            "source_type": self.source_config.source_type,
            "source_uri": self.source_config.source_uri,
            "revision": self._lock_revision(),
            "benchmark_version": self.benchmark_version,
            "quality_tier": "B",
            "derivation": "deterministic_projection",
        }


def build_inventory(task_pairs: Iterable[InjectedTaskPair]) -> dict[str, Any]:
    """Summarize loaded pairs into the agentdojo_inventory.json (guide §23).

    This is produced before the adapter proper so we can confirm how many
    official tasks the adapter saw, without running the full projection.
    """
    suites: dict[str, dict[str, list[str]]] = {}
    for p in task_pairs:
        s = suites.setdefault(p.suite, {"user_tasks": [], "injection_tasks": []})
        if p.user_task_id not in s["user_tasks"]:
            s["user_tasks"].append(p.user_task_id)
        if p.injection_task_id not in s["injection_tasks"]:
            s["injection_tasks"].append(p.injection_task_id)
    for s in suites.values():
        s["user_tasks"].sort()
        s["injection_tasks"].sort()
    return {"benchmark_version": "v1", "suites": suites}
