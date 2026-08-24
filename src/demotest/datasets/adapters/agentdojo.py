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

v1.2.0 (Phase 1.5) adds the official benign control on the SAME benchmark:

  * UserTask.ground_truth(clean env) — the user-AUTHORIZED tool calls AgentDojo
    itself defines — projected as expected_action=ALLOW, metadata
    ground_truth_kind=user_authorized, grouped per UserTask so multi-step
    trajectories never span splits. Nothing is synthesized/rewritten.
  * Injection ground-truth calls are filtered through the committed human
    review config/v3/datasets/agentdojo_injection_gt_calls.json (fail-closed):
    only attack-implementing calls stay BLOCK; preparatory read-only calls
    reviewed "exclude" are dropped.

P1 tool_result from default injection vectors was removed from core (guide P0-2):
get_injection_vector_defaults() is environment content, not an attacker payload;
the constructed content also leaked the attacker goal. AgentDojo P1 may return
only as an Extended/Regression track.
Each case carries a deterministic ``source_id`` and ``parent_source_id`` lineage (guide §20).

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
    """A UserTask + the InjectionTask paired with it."""

    suite: str
    user_task_id: str
    user_prompt: str
    injection_task_id: str
    injection_goal: str
    ground_truth_calls: list[_FunctionCall]  # dangerous tool calls (P2)


@dataclass
class AuthorizedUserTask:
    """A UserTask's OWN ground truth — the official benign control (Phase 1.5).

    ``ground_truth_calls`` are the tool calls AgentDojo itself defines as the
    correct, user-authorized way to fulfil the task prompt. They are projected
    as expected_action=ALLOW so P2 can measure Authorized Tool Call FPR against
    the same benchmark, environment and tool set as the BLOCK side.
    """

    suite: str
    user_task_id: str
    user_prompt: str
    ground_truth_calls: list[_FunctionCall]


def _sha(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", errors="replace")).hexdigest()


@register_adapter
class AgentDojoAdapter(DatasetAdapter):
    """Project pinned AgentDojo security cases into tool_call (P2) cases."""

    dataset_id = "agentdojo"
    adapter_version = "1.2.0"

    def __init__(
        self,
        *,
        raw_dir: Path | str | None = None,
        source_config: DatasetSourceConfig | None = None,
        benchmark_version: str | None = None,
        suites: list[str] | None = None,
        task_provider: "Iterable[InjectedTaskPair] | None" = None,
        authorized_provider: "Iterable[AuthorizedUserTask] | None" = None,
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
        self._authorized_provider = authorized_provider
        self.max_per_suite = max_per_suite

    # ------------------------------------------------------------------ revision
    def _lock_revision(self) -> str:
        if self.source_config.revision:
            return self.source_config.revision
        try:
            return load_source_lock(self.dataset_id).revision
        except DatasetSourceError:
            return self.source_config.revision

    # ------------------------------------------------------------------ GT review
    def _gt_verdicts(self) -> dict[tuple[str, str, int], dict[str, Any]]:
        """Load the committed per-call review verdicts (Phase 1.5 step 4).

        Fail-closed: the file must exist, must have been reviewed at exactly
        the pinned revision, and every ground-truth call the suites produce is
        looked up in it (enforced in ``_load_real_pairs``).
        """
        from ...config import DATASETS_CONFIG_DIR

        p = DATASETS_CONFIG_DIR / "agentdojo_injection_gt_calls.json"
        if not p.exists():
            raise DatasetSourceError(
                f"missing injection ground-truth review file: {p}. "
                "Run scripts/_agentdojo_gt_audit.py and complete the human review first."
            )
        doc = json.loads(p.read_text(encoding="utf-8"))
        reviewed = str(doc.get("reviewed_revision") or "")
        if reviewed != self._lock_revision():
            raise DatasetSourceError(
                f"ground-truth review was done at revision {reviewed or '<none>'} "
                f"but the source pin is {self._lock_revision()} — re-run the audit + review"
            )
        out: dict[tuple[str, str, int], dict[str, Any]] = {}
        for v in doc.get("calls", []):
            out[(str(v["suite"]), str(v["injection_task_id"]), int(v["step"]))] = {
                "function": str(v["function"]),
                "verdict": str(v["verdict"]),
            }
        return out

    # ------------------------------------------------------------------ tasks
    def _load_pairs(self) -> Iterator[InjectedTaskPair]:
        if self._task_provider is not None:
            yield from self._task_provider
            return
        yield from self._load_real_pairs()

    def _load_authorized(self) -> Iterator[AuthorizedUserTask]:
        if self._authorized_provider is not None:
            yield from self._authorized_provider
            return
        if self._task_provider is not None:
            # synthetic/test mode: no real authorized tasks unless injected
            return
        yield from self._load_real_authorized_tasks()

    def _import_suites(self) -> dict[str, Any]:
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
        return get_suites(self.benchmark_version)

    @staticmethod
    def _default_env(suite: Any) -> Any:
        """The POPULATED clean default environment (no injected text)."""
        try:
            return suite.load_and_inject_default_environment({})  # type: ignore[attr-defined]
        except Exception:
            return None

    @staticmethod
    def _review_filter(
        *,
        suite_name: str,
        it_id: str,
        calls: list[_FunctionCall],
        verdicts: dict[tuple[str, str, int], dict[str, Any]],
    ) -> list[_FunctionCall]:
        """Apply the committed per-call review; fail closed on any gap/drift."""
        kept: list[_FunctionCall] = []
        for step, call in enumerate(calls or [], start=1):
            key = (suite_name, str(it_id), step)
            v = verdicts.get(key)
            fn = getattr(call, "function", "") or ""
            if v is None:
                raise DatasetSourceError(
                    f"no human-review verdict for ground-truth call "
                    f"{suite_name}:{it_id} step {step} (function '{fn}') — "
                    "pinned output drifted; re-run scripts/_agentdojo_gt_audit.py + review"
                )
            if v["function"] != fn:
                raise DatasetSourceError(
                    f"ground-truth drift at {suite_name}:{it_id} step {step}: "
                    f"reviewed '{v['function']}' but suite produced '{fn}'"
                )
            if v["verdict"] == "block":
                kept.append(call)
            elif v["verdict"] != "exclude":
                raise DatasetSourceError(
                    f"invalid verdict '{v['verdict']}' at {suite_name}:{it_id} "
                    f"step {step} (expected block|exclude)"
                )
        return kept

    def _load_real_pairs(self) -> Iterator[InjectedTaskPair]:
        """Import the official pinned suite and enumerate security cases.

        Each InjectionTask is one official security case (guide §25). We pair
        every injection task with every user task in its suite — this matches
        agentdojo's own benchmark enumeration (verified Phase 1.5 step 3:
        benchmark_suite_with_injections runs all user_tasks x all
        injection_tasks; gate missing=0 extra=0 at the pinned revision).

        Ground truth calls come from ``InjectionTask.ground_truth(env)`` and are
        filtered through the committed per-call human review
        (``config/v3/datasets/agentdojo_injection_gt_calls.json``, fail-closed):
        only calls reviewed ``block`` — i.e. calls that genuinely implement the
        attack goal — are projected BLOCK; preparatory read-only calls reviewed
        ``exclude`` are dropped entirely.
        """
        suites = self._import_suites()
        verdicts = self._gt_verdicts()
        for suite_name in self.suites:
            if suite_name not in suites:
                continue
            suite = suites[suite_name]
            count = 0
            env = self._default_env(suite)
            for it_id, it in getattr(suite, "injection_tasks", {}).items():
                try:
                    calls = it.ground_truth(env) if env is not None else []  # type: ignore[arg-type]
                except Exception:
                    calls = []
                kept = self._review_filter(
                    suite_name=suite_name, it_id=str(it_id),
                    calls=list(calls or []), verdicts=verdicts,
                )
                for ut_id, ut in getattr(suite, "user_tasks", {}).items():
                    yield InjectedTaskPair(
                        suite=suite_name,
                        user_task_id=str(ut_id),
                        user_prompt=getattr(ut, "PROMPT", "") or "",
                        injection_task_id=str(it_id),
                        injection_goal=getattr(it, "GOAL", "") or "",
                        ground_truth_calls=list(kept),
                    )
                    count += 1
                    if self.max_per_suite and count >= self.max_per_suite:
                        break
                if self.max_per_suite and count >= self.max_per_suite:
                    break

    def _load_real_authorized_tasks(self) -> Iterator[AuthorizedUserTask]:
        """Official benign controls: UserTask.ground_truth(clean env) -> ALLOW.

        Same pinned clone, same environments, same tool set as the attack side;
        nothing here is synthesized, rewritten, or template-expanded.
        """
        suites = self._import_suites()
        for suite_name in self.suites:
            if suite_name not in suites:
                continue
            suite = suites[suite_name]
            env = self._default_env(suite)
            for ut_id, ut in getattr(suite, "user_tasks", {}).items():
                try:
                    calls = ut.ground_truth(env) if env is not None else []  # type: ignore[arg-type]
                except Exception:
                    continue
                yield AuthorizedUserTask(
                    suite=suite_name,
                    user_task_id=str(ut_id),
                    user_prompt=getattr(ut, "PROMPT", "") or "",
                    ground_truth_calls=list(calls or []),
                )

    # ------------------------------------------------------------------ iter
    def iter_cases(self) -> Iterator[SecurityCase]:
        # BLOCK side — injection ground-truth calls that survived the human
        # review (P2 only; P1 tool_result from default vectors removed, P0-2).
        for pair in self._load_pairs():
            parent = f"agentdojo:{pair.suite}:{pair.user_task_id}:{pair.injection_task_id}"
            for step, call in enumerate(pair.ground_truth_calls or [], start=1):
                yield self._build_tool_call_case(pair=pair, parent=parent, call=call, step=step)
        # ALLOW side — official user-authorized ground truth (Phase 1.5).
        for task in self._load_authorized():
            parent = f"agentdojo:{task.suite}:user:{task.user_task_id}"
            for step, call in enumerate(task.ground_truth_calls or [], start=1):
                yield self._build_authorized_call_case(
                    task=task, parent=parent, call=call, step=step
                )

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
            "ground_truth_kind": "injection_attack",
            "parent_source_id": f"agentdojo:{pair.suite}:{pair.user_task_id}:{pair.injection_task_id}",
            "quality_tier": "B",
            "derivation": "deterministic_projection",
            "benchmark_version": self.benchmark_version,
        }

    def _authorized_meta(self, task: AuthorizedUserTask, step: int) -> dict[str, Any]:
        return {
            "source_dataset": "agentdojo",
            "source_task_id": task.user_task_id,
            "environment": task.suite,
            "user_task": task.user_prompt,
            "trajectory_step": step,
            "derived_channel": "tool_call",
            "ground_truth_kind": "user_authorized",
            "parent_source_id": f"agentdojo:{task.suite}:user:{task.user_task_id}",
            "quality_tier": "B",
            "derivation": "deterministic_projection",
            "benchmark_version": self.benchmark_version,
        }

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

    def _build_authorized_call_case(
        self, *, task: AuthorizedUserTask, parent: str, call: _FunctionCall, step: int
    ) -> SecurityCase:
        """Official user-authorized ground truth -> ALLOW (Phase 1.5 step 5).

        The tool-call envelope is byte-identical in structure to the BLOCK one
        ({"tool", "arguments", "user_intent"}), so the renderer cannot reveal
        expected_action; only the official PROMPT/function/args are used.
        """
        source_id = f"{parent}:tool_call:{step}"
        tool_name = getattr(call, "function", "") or ""
        args = dict(getattr(call, "args", {}) or {})
        envelope = {
            "tool": tool_name,
            "arguments": args,
            "user_intent": task.user_prompt,
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
            user_intent=task.user_prompt,
            expected_action=ExpectedAction.ALLOW,
            project_id="P2_tool_action",
            threat_id="",
            presentation_style="structured",
        )
        d = case.to_dict()
        d["metadata"] = {**(d.get("metadata") or {}), **self._authorized_meta(task, step)}
        case = SecurityCase.from_dict(d)
        return attach_provenance(
            case,
            self._make_prov(
                source_id=source_id,
                content=content,
                parent=f"agentdojo:{task.suite}:user:{task.user_task_id}",
            ),
        )

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
