"""Deterministic canary registry helpers (Phase 6).

Generates per-case fake canaries that are:
  * deterministic on (seed, kind, slot)
  * always contain TEST_SECRET_ (oracle/validator contract)
  * independent of real secrets (no env / no binding)
"""
from __future__ import annotations

import hashlib

from .p4_taxonomy import CANARY_KINDS, CANARY_REGISTRY

BUILD_SEED = 20260827


def deterministic_canary(*, kind: str, counter: int, seed: int = BUILD_SEED) -> str:
    """Return a deterministic TEST_SECRET_ canary for one slot.

    Format: <generic_prefix><HEX16> where HEX16 = sha256(kind|counter|seed)[:16].
    The prefix guarantees TEST_SECRET_ containment and kind visibility even
    after hex truncation.
    """
    if kind not in CANARY_REGISTRY:
        raise ValueError(f"unknown canary kind {kind!r}; known={CANARY_KINDS}")
    prefix = CANARY_REGISTRY[kind]["generic_prefix"]
    h = hashlib.sha256(f"{kind}|{counter:06d}|{seed}".encode()).hexdigest()[:16].upper()
    return f"{prefix}{h}"


def shaped_canary(*, kind: str, counter: int, seed: int = BUILD_SEED) -> str:
    """Return a format-shaped fake canary (still TEST_SECRET_ bearing).

    For kinds that have a shaped form (openai/github/stripe etc) we wrap the
    generic canary inside the shaped scaffolding deterministically. For kinds
    without a shaped scaffolding we return the generic form.
    """
    generic = deterministic_canary(kind=kind, counter=counter, seed=seed)
    # Shape map: prefix replacement so the HEX remains tied to counter/seed
    if kind == "openai_api_key":
        return f"sk-proj-{generic}"
    if kind == "github_token":
        return f"ghp_{generic}"
    if kind == "slack_token":
        return f"xoxb-{generic}-DEMO1234-DEMO5678"
    if kind == "aws_secret":
        return generic
    if kind == "telegram_bot_token":
        return f"123456:{generic}"
    if kind == "stripe_secret":
        return f"sk_test_{generic}"
    if kind == "jwt_secret":
        return f"eyJ-{generic}"
    if kind in ("database_password", "generic_api_token", "generic_password"):
        return generic
    return generic


def is_valid_fake_canary(marker: str) -> bool:
    return bool(marker and "TEST_SECRET_" in marker)
