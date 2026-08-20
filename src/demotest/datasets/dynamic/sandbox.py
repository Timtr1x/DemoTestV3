"""SkillLeakBench sandbox runner — subprocess boundary, never a fork (guide §4).

DemoTest does NOT copy entrypoint.sh / run_dual.py / the network sinkhole into
this repo. This runner invokes the PINNED SkillLeakBench pipeline
(cache/datasets_v3/raw/skillleakbench_pipeline @ source-lock revision) via
subprocess + Docker, following the official container contract:

    docker run --rm --network <mode> --memory <mem>
        -v <skill_copy>:/skills -v <monitoring>:/monitoring
        -e SKILL_ID=<id> -e CONDITION=<condition>
        -e <REAL_ENV_NAME>=<TEST_SECRET_canary> ...   # fake values only
        <image> <command>

Hard security boundaries (guide §6/§13):
  * only TEST_SECRET_<HEX16> canary values are ever passed with `-e`;
  * the child process env is scrubbed to an allowlist — host credentials
    (keys/tokens/secrets) are never forwarded to docker or the container;
  * real skills are untrusted code: run them only in the disposable sandbox,
    never on the host.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..traces.canary import canonical_canary
from .schemas import (
    DynamicExecutionRecord,
    DynamicSpecError,
    assert_fake_canary,
)

#: Real env-var names kept for semantics; values are always TEST_SECRET canaries.
DEFAULT_CREDENTIAL_NAMES: tuple[str, ...] = (
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "GITHUB_TOKEN",
)

#: Names that must NEVER reach the child process (host credential hygiene).
_CREDENTIAL_NAME_RE = re.compile(
    r"(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|PRIVATE|AUTH)", re.IGNORECASE
)

#: Minimal env allowlist for the docker CLI subprocess itself.
_CHILD_ENV_ALLOWLIST = (
    "PATH",
    "SYSTEMROOT",
    "SystemRoot",
    "WINDIR",
    "TEMP",
    "TMP",
    "DOCKER_HOST",
    "DOCKER_TLS_VERIFY",
    "DOCKER_CERT_PATH",
)


def injected_credentials(
    *,
    pipeline_revision: str,
    skill_id: str,
    names: Sequence[str] = DEFAULT_CREDENTIAL_NAMES,
) -> dict[str, str]:
    """Deterministic TEST_SECRET canaries under REAL env-var names (guide §13).

    Anchored on (pipeline_revision | skill_id | credential_name | "dynamic") via
    canonical_canary — same inputs always yield the same values; any revision
    change rotates every canary.
    """
    return {
        name: canonical_canary(
            source_revision=pipeline_revision,
            skill_id=skill_id,
            issue_id=name,
            trace_channel="dynamic",
        )
        for name in names
    }


def scrub_child_env(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """Minimal env for the docker CLI child: allowlist only, never credentials.

    This is the hard boundary behind "no real credential env vars copied into
    the child container" (guide §5): even if the host shell exports AWS keys,
    they do not reach the sandbox.
    """
    environ = environ if environ is not None else os.environ
    return {k: v for k, v in environ.items() if k in _CHILD_ENV_ALLOWLIST}


def host_credential_names(environ: Mapping[str, str] | None = None) -> list[str]:
    """Credential-looking host env names — for doctor reporting (never forwarded)."""
    environ = environ if environ is not None else os.environ
    return sorted(k for k in environ if _CREDENTIAL_NAME_RE.search(k))


@dataclass(frozen=True)
class DoctorCheck:
    name: str
    ok: bool
    detail: str = ""
    required: bool = True


@dataclass(frozen=True)
class DoctorReport:
    checks: tuple[DoctorCheck, ...] = field(default_factory=tuple)

    @property
    def ok(self) -> bool:
        return all(c.ok for c in self.checks if c.required)


class SandboxUnavailable(RuntimeError):
    """Docker / pinned pipeline not usable on this machine."""


class SkillLeakBenchSandboxRunner:
    """Subprocess wrapper around the pinned SkillLeakBench pipeline + Docker."""

    def __init__(
        self,
        *,
        pipeline_root: Path | str,
        pipeline_revision: str,
        image: str = "skill-leakbench",
        docker: Sequence[str] | None = None,
        network: str = "none",
        memory: str = "512m",
        timeout_s: int = 240,
    ) -> None:
        self.pipeline_root = Path(pipeline_root)
        self.pipeline_revision = pipeline_revision
        self.image = image
        if docker is None:
            docker = os.environ.get("SLB_DOCKER", "docker").split()
        self.docker = tuple(docker)
        self.network = network
        self.memory = memory
        self.timeout_s = timeout_s

    # -- doctor (guide §5) ---------------------------------------------------

    def docker_available(self) -> bool:
        return shutil.which(self.docker[0]) is not None

    def image_digest(self) -> str:
        """Repo digest / Id of the pinned image, or "" when unknown."""
        if not self.docker_available():
            return ""
        try:
            proc = subprocess.run(
                [*self.docker, "image", "inspect", self.image,
                 "--format", "{{json .RepoDigests}}|{{.Id}}"],
                capture_output=True, text=True, timeout=30,
                env=scrub_child_env(),
            )
            if proc.returncode != 0:
                return ""
            digests_raw, _, image_id = proc.stdout.strip().partition("|")
            digests = json.loads(digests_raw or "[]")
            return digests[0] if digests else image_id
        except Exception:
            return ""

    def doctor_checks(self, *, with_self_test: bool = False) -> DoctorReport:
        checks: list[DoctorCheck] = []
        checks.append(DoctorCheck(
            "docker_available", self.docker_available(),
            f"docker binary: {' '.join(self.docker)}"))
        checks.append(DoctorCheck(
            "pipeline_checkout_exists",
            (self.pipeline_root / "code" / "phase3_dynamic").is_dir(),
            f"{self.pipeline_root} @ {self.pipeline_revision}"))
        digest = self.image_digest()
        checks.append(DoctorCheck(
            "image_digest_known", bool(digest), digest or "image not built/inspectable"))
        scrubbed = scrub_child_env()
        leaked = [k for k in scrubbed if _CREDENTIAL_NAME_RE.search(k)]
        checks.append(DoctorCheck(
            "no_real_credentials_forwarded", not leaked,
            f"credential-looking host vars present but NOT forwarded: {host_credential_names()}",
        ))
        if with_self_test:
            st = self.run_self_test()
            checks.append(DoctorCheck("t3_stdout_fixture_pass", st.get("stdout", False),
                                      st.get("detail", "")))
            checks.append(DoctorCheck("t3_network_fixture_pass", st.get("network", False),
                                      st.get("detail", "")))
        return DoctorReport(tuple(checks))

    def run_self_test(self) -> dict[str, Any]:
        """Official T3 self-test via the pinned pipeline (guide §5).

        `bash code/scripts/03_dynamic_validate.sh --self-test` — expects the two
        official fixtures (stdout leak detected, network payload detected).
        """
        script = self.pipeline_root / "code" / "scripts" / "03_dynamic_validate.sh"
        if not script.exists():
            return {"stdout": False, "network": False, "detail": f"missing {script}"}
        bash = shutil.which("bash")
        if bash is None:
            return {"stdout": False, "network": False, "detail": "bash not available"}
        if not self.docker_available():
            return {"stdout": False, "network": False, "detail": "docker not available"}
        proc = subprocess.run(
            [bash, str(script), "--self-test"],
            cwd=str(self.pipeline_root),
            capture_output=True, text=True, timeout=max(self.timeout_s, 600),
            env=scrub_child_env(),
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        ok = proc.returncode == 0
        return {
            "stdout": ok and ("stdout" in out.lower() and ("detect" in out.lower() or "pass" in out.lower())),
            "network": ok and ("network" in out.lower() and ("detect" in out.lower() or "pass" in out.lower())),
            "detail": out[-400:],
        }

    # -- execution (guide §6) ------------------------------------------------

    def build_docker_argv(
        self,
        *,
        skill_id: str,
        skill_dir: Path,
        monitoring_dir: Path,
        credentials: Mapping[str, str],
        condition: str,
        command: Sequence[str] | None = None,
    ) -> list[str]:
        """Official container contract; `-e` carries TEST_SECRET values only."""
        for name, value in credentials.items():
            assert_fake_canary(name, value)
        argv = [
            *self.docker, "run", "--rm",
            "--network", self.network,
            "--memory", self.memory,
            "-v", f"{skill_dir.resolve()}:/skills",
            "-v", f"{monitoring_dir.resolve()}:/monitoring",
            "-e", f"SKILL_ID={skill_id}",
            "-e", f"CONDITION={condition}",
        ]
        for name in sorted(credentials):
            argv += ["-e", f"{name}={credentials[name]}"]
        argv.append(self.image)
        if command:
            argv += list(command)
        return argv

    def run_skill(
        self,
        *,
        skill_id: str,
        skill_dir: Path | str,
        skill_snapshot_sha256: str,
        credentials: Mapping[str, str],
        condition: str = "deterministic",
        declared_providers: Sequence[str] = (),
        command: Sequence[str] | None = None,
        work_root: Path | str | None = None,
        timeout_s: int | None = None,
    ) -> DynamicExecutionRecord:
        """Execute one skill in the disposable sandbox; collect artifacts.

        The skill is untrusted code — it runs ONLY inside the container. The
        monitoring dir (stdout.log / network_payload.log / exit_status) is the
        raw evidence; this function never interprets it.
        """
        skill_dir = Path(skill_dir)
        timeout_s = timeout_s or self.timeout_s
        if not self.docker_available():
            raise SandboxUnavailable("docker not available — run `demotest dynamic doctor`")
        if not (self.pipeline_root / "code" / "phase3_dynamic").is_dir():
            raise SandboxUnavailable(f"pinned pipeline checkout missing at {self.pipeline_root}")

        work = Path(work_root) if work_root else Path(
            __import__("tempfile").mkdtemp(prefix="dynexec-"))
        monitoring = work / "monitoring"
        monitoring.mkdir(parents=True, exist_ok=True)
        execution_id = "exec-" + hashlib.sha256(
            f"{self.pipeline_revision}|{skill_id}|{condition}|{skill_snapshot_sha256}".encode()
        ).hexdigest()[:16]

        argv = self.build_docker_argv(
            skill_id=skill_id, skill_dir=skill_dir, monitoring_dir=monitoring,
            credentials=credentials, condition=condition, command=command,
        )
        started = time.monotonic()
        timed_out = False
        try:
            proc = subprocess.run(
                argv, timeout=timeout_s, check=False,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                env=scrub_child_env(),
            )
            exit_code: int | None = proc.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            exit_code = 124
        wall_ms = int((time.monotonic() - started) * 1000)

        artifacts = read_monitoring_dir(monitoring)
        return DynamicExecutionRecord(
            execution_id=execution_id,
            skill_id=skill_id,
            skill_snapshot_sha256=skill_snapshot_sha256,
            condition=condition,  # type: ignore[arg-type]
            execution_mode="deterministic" if condition == "deterministic" else "agent_driven",
            sandbox_provider="SkillLeakBench",
            pipeline_revision=self.pipeline_revision,
            sandbox_image_digest=self.image_digest(),
            outcome="TIMEOUT" if timed_out else "SANDBOX_ERROR" if exit_code not in (0, None) else "SUCCESS_NO_SECRET_FLOW",
            exit_code=exit_code,
            timeout=timed_out,
            wall_clock_ms=wall_ms,
            stdout_artifact=str(monitoring / "stdout.log"),
            network_artifact=str(monitoring / "network_payload.log"),
            network_events=tuple(artifacts["network_events"]),
            stdout_text=artifacts["stdout"],
            credential_names=tuple(sorted(credentials)),
            declared_providers=tuple(declared_providers),
            metadata={"exit_status_file": artifacts["exit_status"]},
        )


def read_monitoring_dir(monitoring_dir: Path | str) -> dict[str, Any]:
    """Read the sandbox's captured channels (official artifact names)."""
    d = Path(monitoring_dir)

    def _read(name: str) -> str:
        f = d / name
        return f.read_text(encoding="utf-8", errors="replace") if f.exists() else ""

    network_payload = _read("network_payload.log")
    return {
        "stdout": _read("stdout.log"),
        "network": _read("network.log") + ("\n" + network_payload if network_payload else ""),
        "files": _read("files.log"),
        "exit_status": (_read("exit_status").strip() or None),
        "network_events": tuple(normalize_network_events(network_payload)),
    }


def normalize_network_events(network_payload_text: str) -> list[dict[str, Any]]:
    """Normalize captured network payload lines into event dicts.

    JSON lines are used verbatim ({method, destination, headers, body}); plain
    text lines become {body: line} events. Destinations are kept EXACTLY as
    captured — never rewritten (guide §12).
    """
    events: list[dict[str, Any]] = []
    for raw in (network_payload_text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
            if isinstance(ev, dict):
                events.append({
                    "method": str(ev.get("method") or ""),
                    "destination": str(ev.get("destination") or ev.get("url") or ""),
                    "headers": dict(ev.get("headers") or {}),
                    "body": str(ev.get("body") or ""),
                })
                continue
        except Exception:
            pass
        events.append({"method": "", "destination": "", "headers": {}, "body": line})
    return events


def shell_join(argv: Sequence[str]) -> str:
    return " ".join(shlex.quote(a) for a in argv)
