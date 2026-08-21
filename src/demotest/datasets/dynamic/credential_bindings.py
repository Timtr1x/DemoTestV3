"""Source-bound credential bindings — ``source-bound-v1`` profile (P4 扩展 Core).

The official SkillLeakBench baseline injects forged canaries only under the 9
env names its own ``mock_creds.py`` knows about. Real skills frequently read
*custom* credential names (``CRUN_API_KEY``, ``TWILIO_AUTH_TOKEN``, …) that the
official profile never covers, so an otherwise leaky skill shows up as
CREDENTIAL_MISSING instead of exercising its real credential path.

This module implements the reviewer-approved remedy: a human-audited sidecar
``credential_bindings/credential_bindings.jsonl`` that binds

    candidate_id + source_sha256 + credential_name + evidence

and yields a deterministic fake canary
``leakbench-sourcebound-<sha12(candidate_id|source_sha256)>-<sha12(credential_name)>``
which the collector merges into the injected credential set.

Hard rules (fail-closed):
  * binding rows are only accepted with ``review_status == "CONFIRMED"`` and
    ``profile == "source-bound-v1"`` — anything else is a schema error, never
    silently skipped;
  * credential names must match ``^[A-Z_][A-Z0-9_]*$`` and must NOT collide
    with the official forged namespace (a binding may never redefine an
    official baseline canary);
  * names come only from human-confirmed source evidence — never guessed from
    the skill name, never model-generated;
  * the binding is anchored to the candidate's *current* source_sha256; a
    re-crawl under different bytes invalidates it (drift is reported, the
    stale row is never projected into a materialization);
  * canary values always contain ``leakbench`` so they pass the sandbox's
    fake-only injection gate (``_assert_fake_credentials``).

This layer is additive: it never modifies skills, ``mock_creds.py``, the
official marker pipeline, or any existing judgment semantics. Results
collected with bindings must be reported as the *source-bound* profile,
layered separately from the official baseline — never claimed as
"official SkillLeakBench T3 as-is".
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

CREDENTIAL_BINDINGS_DIRNAME = "credential_bindings"
CREDENTIAL_BINDINGS_FILE = "credential_bindings.jsonl"
SOURCE_BOUND_PROFILE = "source-bound-v1"
OFFICIAL_BASELINE_PROFILE = "official-baseline"

#: Credential namespace owned by the official SkillLeakBench baseline
#: (``mock_creds.py`` env_vars + honeypots). A source-bound binding may never
#: occupy one of these names — that would silently redefine an official canary.
OFFICIAL_FORGED_ENV_NAMES: frozenset[str] = frozenset({
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "DATABASE_URL",
    "GOOGLE_API_KEY",
    "SLACK_TOKEN",
    "GITHUB_TOKEN",
    "STRIPE_SECRET_KEY",
    "JWT_SECRET",
})

_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")

_REQUIRED_FIELDS = (
    "candidate_id",
    "source_sha256",
    "credential_name",
    "credential_kind",
    "evidence_file",
    "evidence",
    "review_status",
    "profile",
)


class CredentialBindingError(ValueError):
    """Any schema/authority violation in the credential-bindings sidecar."""


@dataclass(frozen=True)
class CredentialBinding:
    """One human-confirmed custom credential name for one candidate revision."""

    candidate_id: str
    source_sha256: str
    credential_name: str
    credential_kind: str  # e.g. env_var | dotenv | config_file
    evidence_file: str  # path inside the skill tree where the read was confirmed
    evidence: str  # short human note / code excerpt proving the read
    review_status: str = "CONFIRMED"
    profile: str = SOURCE_BOUND_PROFILE

    @property
    def canary(self) -> str:
        return source_bound_canary(self.candidate_id, self.source_sha256, self.credential_name)

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "source_sha256": self.source_sha256,
            "credential_name": self.credential_name,
            "credential_kind": self.credential_kind,
            "evidence_file": self.evidence_file,
            "evidence": self.evidence,
            "review_status": self.review_status,
            "profile": self.profile,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any], *, lineno: int = 0) -> "CredentialBinding":
        where = f"line {lineno}" if lineno else "row"
        if not isinstance(d, dict):
            raise CredentialBindingError(f"{where}: binding must be a JSON object")
        missing = [k for k in _REQUIRED_FIELDS if not str(d.get(k) or "").strip()]
        if missing:
            raise CredentialBindingError(f"{where}: missing/empty fields: {', '.join(missing)}")
        b = cls(
            candidate_id=str(d["candidate_id"]),
            source_sha256=str(d["source_sha256"]),
            credential_name=str(d["credential_name"]),
            credential_kind=str(d["credential_kind"]),
            evidence_file=str(d["evidence_file"]),
            evidence=str(d["evidence"]),
            review_status=str(d["review_status"]),
            profile=str(d["profile"]),
        )
        _validate_binding(b, where=where)
        return b


def _validate_binding(b: CredentialBinding, *, where: str = "row") -> None:
    if not _NAME_RE.match(b.credential_name):
        raise CredentialBindingError(
            f"{where}: credential_name {b.credential_name!r} must match ^[A-Z_][A-Z0-9_]*$")
    if b.credential_name in OFFICIAL_FORGED_ENV_NAMES:
        raise CredentialBindingError(
            f"{where}: credential_name {b.credential_name!r} collides with the official "
            "SkillLeakBench forged namespace — a source-bound binding may never "
            "redefine an official baseline canary")
    if b.review_status != "CONFIRMED":
        raise CredentialBindingError(
            f"{where}: review_status must be CONFIRMED (got {b.review_status!r}) — "
            "unreviewed bindings are never injected")
    if b.profile != SOURCE_BOUND_PROFILE:
        raise CredentialBindingError(
            f"{where}: profile must be {SOURCE_BOUND_PROFILE!r} (got {b.profile!r})")
    if not re.fullmatch(r"[0-9a-f]{64}", b.source_sha256):
        raise CredentialBindingError(
            f"{where}: source_sha256 must be a 64-char lowercase hex digest")


def source_bound_canary(candidate_id: str, source_sha256: str, credential_name: str) -> str:
    """Deterministic fake canary for one binding.

    ``leakbench-sourcebound-<sha12(candidate_id|source_sha256)>-<sha12(credential_name)>``
    — stable across runs, rotates if the skill bytes change, and always passes
    the sandbox's fake-only injection gate (contains ``leakbench``).
    """
    skill_hash = hashlib.sha256(f"{candidate_id}|{source_sha256}".encode()).hexdigest()[:12]
    binding_hash = hashlib.sha256(credential_name.encode()).hexdigest()[:12]
    return f"leakbench-sourcebound-{skill_hash}-{binding_hash}"


def _bindings_path(pool_root: Path) -> Path:
    return pool_root / CREDENTIAL_BINDINGS_DIRNAME / CREDENTIAL_BINDINGS_FILE


def load_credential_bindings(pool_root: Path | str) -> list[CredentialBinding]:
    """Fail-closed loader: any schema violation raises CredentialBindingError.

    A malformed sidecar must never degrade to "no bindings" — that would let a
    typo silently revert an execution to the official-baseline profile.
    """
    p = _bindings_path(Path(pool_root))
    if not p.exists():
        return []
    if p.is_symlink():
        raise CredentialBindingError(f"credential bindings file is a symlink: {p}")
    out: list[CredentialBinding] = []
    seen: set[tuple[str, str]] = set()
    for lineno, raw in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        try:
            d = json.loads(raw)
        except Exception as e:
            raise CredentialBindingError(f"line {lineno}: invalid JSON ({e})") from e
        b = CredentialBinding.from_dict(d, lineno=lineno)
        key = (b.candidate_id, b.credential_name)
        if key in seen:
            raise CredentialBindingError(
                f"line {lineno}: duplicate binding for ({b.candidate_id}, {b.credential_name})")
        seen.add(key)
        out.append(b)
    return sorted(out, key=lambda b: (b.candidate_id, b.credential_name))


def bindings_for_candidate(
    bindings: list[CredentialBinding], candidate_id: str, source_sha256: str = "",
) -> list[CredentialBinding]:
    """Bindings for one candidate; when *source_sha256* is given, only rows
    anchored to exactly that revision are returned (stale rows excluded)."""
    return [
        b for b in bindings
        if b.candidate_id == candidate_id and (not source_sha256 or b.source_sha256 == source_sha256)
    ]


def upsert_credential_binding(
    *,
    pool_root: Path | str,
    candidate_id: str,
    credential_name: str,
    credential_kind: str,
    evidence_file: str,
    evidence: str,
) -> CredentialBinding:
    """Create or replace one CONFIRMED binding, anchored to the candidate's
    *current* source_sha256 in candidates.jsonl.

    Refuses unknown candidates and SOURCE_REJECTED ones — a binding on bytes
    that were never accepted would inject a canary into an unreviewed tree.
    """
    from .candidates import load_candidates  # local import: candidates imports nothing here

    pool = Path(pool_root)
    cands = {c.candidate_id: c for c in load_candidates(pool)}
    cand = cands.get(candidate_id)
    if cand is None:
        raise CredentialBindingError(f"candidate not found: {candidate_id}")
    if cand.reject_reason != "ACCEPT":
        raise CredentialBindingError(
            f"candidate {candidate_id} is {cand.reject_reason} — bindings require ACCEPT source")
    binding = CredentialBinding(
        candidate_id=candidate_id,
        source_sha256=cand.source_sha256,
        credential_name=credential_name.strip(),
        credential_kind=credential_kind.strip(),
        evidence_file=evidence_file.strip(),
        evidence=evidence.strip(),
    )
    _validate_binding(binding, where=f"binding {candidate_id}/{credential_name}")
    bindings = [
        b for b in load_credential_bindings(pool)
        if not (b.candidate_id == candidate_id and b.credential_name == binding.credential_name)
    ]
    bindings.append(binding)
    _write_bindings(pool, bindings)
    return binding


def _write_bindings(pool: Path, bindings: list[CredentialBinding]) -> Path:
    d = pool / CREDENTIAL_BINDINGS_DIRNAME
    d.mkdir(parents=True, exist_ok=True)
    p = d / CREDENTIAL_BINDINGS_FILE
    lines = [
        json.dumps(b.to_dict(), ensure_ascii=False, sort_keys=True)
        for b in sorted(bindings, key=lambda x: (x.candidate_id, x.credential_name))
    ]
    p.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return p


def credential_bindings_sha256(pool_root: Path | str) -> str:
    """Whole-file identity hash; empty-sidecar convention matches runtime_specs."""
    p = _bindings_path(Path(pool_root))
    if not p.exists():
        return hashlib.sha256(b"").hexdigest()
    return hashlib.sha256(p.read_bytes()).hexdigest()


def materialization_bindings(
    bindings: list[CredentialBinding], candidate_id: str, source_sha256: str,
) -> list[dict[str, str]]:
    """Projection written into _p4_materialization.json / snapshot.json per skill.

    Only rows anchored to the exact materialized revision are projected; each
    row carries the precomputed deterministic canary so downstream layers never
    re-derive naming rules.
    """
    return [
        {
            "credential_name": b.credential_name,
            "credential_kind": b.credential_kind,
            "canary": b.canary,
        }
        for b in bindings_for_candidate(bindings, candidate_id, source_sha256)
    ]


def validate_bindings_against_pool(pool_root: Path | str) -> list[str]:
    """Cross-checks for ``candidates verify`` — returns problem strings.

    Schema violations surface as problems here (verify never raises); drift
    between a binding's anchored source_sha256 and the candidate's current
    bytes is reported so a human can re-confirm via another upsert.
    """
    from .candidates import load_candidates

    pool = Path(pool_root)
    try:
        bindings = load_credential_bindings(pool)
    except CredentialBindingError as e:
        return [f"credential_bindings sidecar invalid: {e}"]
    problems: list[str] = []
    cands = {c.candidate_id: c for c in load_candidates(pool)}
    for b in bindings:
        cand = cands.get(b.candidate_id)
        if cand is None:
            problems.append(f"binding for unknown candidate: {b.candidate_id} ({b.credential_name})")
            continue
        if cand.reject_reason != "ACCEPT":
            problems.append(
                f"binding on non-ACCEPT candidate: {b.candidate_id} ({cand.reject_reason})")
        if b.source_sha256 != cand.source_sha256:
            problems.append(
                f"binding source drift: {b.candidate_id}/{b.credential_name} "
                f"bound={b.source_sha256[:12]} current={cand.source_sha256[:12]} — "
                "re-confirm via credential-binding set")
    return problems
