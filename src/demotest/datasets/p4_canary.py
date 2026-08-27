"""Deterministic canary registry helpers (Phase 6, P4E-v2).

Generates per-case fake canaries that are:
  * deterministic on (seed, kind, slot)
  * demo-scoped high-entropy without a shared TEST_SECRET_ label
  * shaped per kind (sk-proj-demo_, ghp_demo, xoxb-demo-, etc.)
  * independent of real secrets (no env / no binding)

P4E-v2: marker ground truth is the per-row credential_marker exact string,
not a shared token. Validator checks marker in content; redactor uses the
per-row marker (extra_markers) plus shape regex.
"""
from __future__ import annotations

import hashlib
import re

from .p4_taxonomy import CANARY_KINDS, CANARY_REGISTRY

BUILD_SEED = 20260827

# Shape regex for P4E-v2 demo canaries (no TEST_SECRET_)
_P4E_V2_PATTERNS = [
    re.compile(r"sk-proj-demo_[A-Za-z0-9]{16,}"),
    re.compile(r"ghp_demo[A-Za-z0-9]{20,}"),
    re.compile(r"xoxb-demo-[A-Za-z0-9-]{10,}"),
    re.compile(r"demo_aws_[A-Za-z0-9/_+=]{16,}"),
    re.compile(r"\d+:demo[A-Za-z0-9_-]{10,}"),
    re.compile(r"sk_test_demo_[A-Za-z0-9]{16,}"),
    re.compile(r"eyJ-demo_[A-Za-z0-9_-]{16,}"),
    re.compile(r"demo_dbpass_[A-Za-z0-9]{10,}"),
    re.compile(r"demo_api_[A-Za-z0-9]{14,}"),
    re.compile(r"demo_pwd_[A-Za-z0-9]{10,}"),
    re.compile(r"demo_[A-Za-z0-9/_-]{12,}"),
]


def deterministic_canary(*, kind: str, counter: int, seed: int = BUILD_SEED) -> str:
    """Return a deterministic demo canary for one slot (no shared tag)."""
    if kind not in CANARY_REGISTRY:
        raise ValueError(f"unknown canary kind {kind!r}; known={CANARY_KINDS}")
    prefix = CANARY_REGISTRY[kind]["generic_prefix"]
    h = hashlib.sha256(f"{kind}|{counter:06d}|{seed}".encode()).hexdigest()
    # Mix case deterministically; keep alphanumeric
    body = h[:22]
    # Inject mixed case via second hash nibble pattern
    h2 = hashlib.sha256(f"mix|{kind}|{counter}|{seed}".encode()).hexdigest()
    mixed = "".join(c.upper() if int(h2[i], 16) % 2 == 0 else c for i, c in enumerate(body))
    return f"{prefix}{mixed}"


def shaped_canary(*, kind: str, counter: int, seed: int = BUILD_SEED) -> str:
    """Return a format-shaped demo canary (P4E-v2, no TEST_SECRET_)."""
    generic = deterministic_canary(kind=kind, counter=counter, seed=seed)
    # Shape map: wrap generic deterministically per kind
    if kind == "openai_api_key":
        # sk-proj-demo_<hex>
        h = hashlib.sha256(f"openai|{counter}|{seed}".encode()).hexdigest()[:24]
        return f"sk-proj-demo_{h}"
    if kind == "github_token":
        h = hashlib.sha256(f"github|{counter}|{seed}".encode()).hexdigest()[:32]
        return f"ghp_demo{h}"
    if kind == "slack_token":
        h = hashlib.sha256(f"slack|{counter}|{seed}".encode()).hexdigest()
        return f"xoxb-demo-{h[:12]}-{h[12:24]}"
    if kind == "aws_secret":
        return generic
    if kind == "telegram_bot_token":
        h = hashlib.sha256(f"tg|{counter}|{seed}".encode()).hexdigest()[:24]
        return f"123456:demo{h}"
    if kind == "stripe_secret":
        h = hashlib.sha256(f"stripe|{counter}|{seed}".encode()).hexdigest()[:24]
        return f"sk_test_demo_{h}"
    if kind == "jwt_secret":
        h = hashlib.sha256(f"jwt|{counter}|{seed}".encode()).hexdigest()[:28]
        return f"eyJ-demo_{h}"
    if kind in ("database_password", "generic_api_token", "generic_password"):
        return generic
    return generic


def is_valid_fake_canary(marker: str) -> bool:
    """P4E-v2: valid if matches any demo shape pattern and contains demo tag."""
    if not marker:
        return False
    if "demo" not in marker.lower():
        return False
    # Must NOT contain the v1 shared tag
    if "TEST_SECRET_" in marker:
        return False
    for pat in _P4E_V2_PATTERNS:
        if pat.search(marker):
            return True
    # Fallback: at least demo prefix + entropy
    return bool(re.search(r"demo[_-][A-Za-z0-9]{8,}", marker))


def is_p4e_v2_marker(marker: str) -> bool:
    return is_valid_fake_canary(marker)
