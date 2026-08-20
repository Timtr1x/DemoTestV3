"""SandboxSession — constrained actions between Host Agent and Docker skill."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from .sandbox import SkillLeakBenchSandboxRunner


@dataclass(frozen=True)
class SkillContext:
    skill_id: str
    instruction: str
    files: tuple[str, ...] = ()


@dataclass(frozen=True)
class SandboxAction:
    kind: str  # read_skill_instruction | execute_skill_entrypoint | read_declared_output
    arguments: dict[str, Any] | None = None


@dataclass(frozen=True)
class SandboxObservation:
    stdout: str = ""
    network_events: tuple[dict[str, Any], ...] = ()
    exit_code: int | None = None
    artifact_dir: str = ""


class SandboxSession:
    """Whitelisted session: Agent requests actions, Host executes them in Docker.

    ``condition`` is the experimental condition (benign/adversarial) and is
    orthogonal to ``action.kind``.
    """

    ALLOWED_ACTIONS = frozenset({
        "read_skill_instruction",
        "execute_skill_entrypoint",
        "read_declared_output",
    })

    def __init__(
        self,
        *,
        runner: SkillLeakBenchSandboxRunner,
        skill_id: str,
        skill_dir: Path | str,
        skill_snapshot_sha256: str,
        credentials: dict[str, str],
        work_root: Path | str,
        condition: Literal["benign", "adversarial", "deterministic"] = "benign",
    ) -> None:
        self.runner = runner
        self.skill_id = skill_id
        self.skill_dir = Path(skill_dir)
        self.skill_snapshot_sha256 = skill_snapshot_sha256
        self.credentials = credentials
        self.work_root = Path(work_root)
        self.condition = condition  # type: ignore[assignment]
        self.work_root.mkdir(parents=True, exist_ok=True)
        self._last_observation: SandboxObservation | None = None

    def describe_skill(self) -> SkillContext:
        md = (self.skill_dir / "SKILL.md").read_text(encoding="utf-8", errors="replace") if (self.skill_dir / "SKILL.md").exists() else ""
        files = tuple(p.name for p in self.skill_dir.iterdir() if p.is_file())
        return SkillContext(skill_id=self.skill_id, instruction=md[:4000], files=files)

    def execute(
        self,
        action: SandboxAction,
        *,
        condition: Literal["benign", "adversarial", "deterministic"] | None = None,
    ) -> SandboxObservation:
        if action.kind not in self.ALLOWED_ACTIONS:
            raise ValueError(f"action {action.kind!r} not in allowlist {sorted(self.ALLOWED_ACTIONS)}")
        if action.kind == "read_skill_instruction":
            ctx = self.describe_skill()
            return SandboxObservation(stdout=ctx.instruction, artifact_dir=str(self.skill_dir))
        if action.kind == "read_declared_output":
            if self._last_observation is None:
                return SandboxObservation(stdout="", artifact_dir=str(self.work_root))
            return self._last_observation
        # execute_skill_entrypoint — condition is orthogonal to action
        eff_condition = condition or self.condition  # type: ignore[assignment]
        rec = self.runner.run_skill(
            skill_id=self.skill_id,
            skill_dir=self.skill_dir,
            skill_snapshot_sha256=self.skill_snapshot_sha256,
            credentials=self.credentials,
            condition=eff_condition,  # type: ignore[arg-type]
            work_root=self.work_root,
        )
        obs = SandboxObservation(
            stdout=rec.stdout_text,
            network_events=rec.network_events,
            exit_code=rec.exit_code,
            artifact_dir=rec.stdout_artifact,
        )
        self._last_observation = obs
        return obs
