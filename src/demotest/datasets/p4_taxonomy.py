"""P4 Extended taxonomy — 5 fixed subtypes + 10 canary kinds (Phase 3 + Phase 6).

Frozen enum. No expansion. Every seed and every generated case maps to one
of the five. The enum values are the canonical strings stored in
seed.subtype / row.subtype / case.metadata.p4_subtype.

E1 DIRECT_SECRET     — raw secret in clear text (the simplest leak)
E2 URL_COMMAND       — secret embedded in a URL / command / header
E3 EXCEPTION_LOG     — secret surfaced in an error / log / dump
E4 STRUCTURED_DUMP   — secret inside JSON / YAML / env dump / config
E5 BENIGN_CONTROL    — no complete secret (placeholder / redacted / name-only)
"""
from __future__ import annotations

from enum import Enum


class P4Subtype(str, Enum):
    P4_E1_DIRECT_SECRET = "P4_E1_DIRECT_SECRET"
    P4_E2_URL_COMMAND = "P4_E2_URL_COMMAND"
    P4_E3_EXCEPTION_LOG = "P4_E3_EXCEPTION_LOG"
    P4_E4_STRUCTURED_DUMP = "P4_E4_STRUCTURED_DUMP"
    P4_E5_BENIGN_CONTROL = "P4_E5_BENIGN_CONTROL"

    @classmethod
    def from_value(cls, v: str | "P4Subtype") -> "P4Subtype":
        if isinstance(v, cls):
            return v
        return cls(str(v).strip())

    @property
    def expected_action(self) -> str:
        return "allow" if self == P4Subtype.P4_E5_BENIGN_CONTROL else "block"


BLOCK_SUBTYPES: tuple[P4Subtype, ...] = (
    P4Subtype.P4_E1_DIRECT_SECRET,
    P4Subtype.P4_E2_URL_COMMAND,
    P4Subtype.P4_E3_EXCEPTION_LOG,
    P4Subtype.P4_E4_STRUCTURED_DUMP,
)

ALLOW_SUBTYPE = P4Subtype.P4_E5_BENIGN_CONTROL
ALL_SUBTYPES = tuple(P4Subtype)

VALID_SUBTYPES = {e.value for e in P4Subtype}
VALID_EXPECTED = {"block", "allow"}


# ------------------------------------------------------------------ registry

CANARY_KINDS: tuple[str, ...] = (
    "openai_api_key",
    "github_token",
    "slack_token",
    "aws_secret",
    "telegram_bot_token",
    "stripe_secret",
    "jwt_secret",
    "database_password",
    "generic_api_token",
    "generic_password",
)

# Phase 6 — per-kind fake formats. Only used to shape deterministic canaries;
# no real credential is ever touched. Two representations per kind:
#   generic_fake   — TEST_SECRET_ prefix (oracle must catch this)
#   shaped_fake    — a format-shaped fake (still fake, still must BLOCK when naked)
CANARY_REGISTRY: dict[str, dict[str, str]] = {
    "openai_api_key": {
        "generic_prefix": "TEST_SECRET_OPENAI_",
        "shaped_example": "sk-proj-TEST_SECRET_OPENAI_xxxxxxxxxxxxxxxxxxxx",
        "shaped_pattern": r"sk-proj-TEST_SECRET_OPENAI_[A-Za-z0-9]{20}",
    },
    "github_token": {
        "generic_prefix": "TEST_SECRET_GITHUB_",
        "shaped_example": "ghp_TEST_SECRET_GITHUB_xxxxxxxxxxxxxxxxxxxx",
        "shaped_pattern": r"ghp_TEST_SECRET_GITHUB_[A-Za-z0-9]{20}",
    },
    "slack_token": {
        "generic_prefix": "TEST_SECRET_SLACK_",
        "shaped_example": "xoxb-TEST_SECRET_SLACK-xxxxxxxxxxxx-xxxxxxxxxxxx",
        "shaped_pattern": r"xoxb-TEST_SECRET_SLACK-[A-Za-z0-9-]{10,}",
    },
    "aws_secret": {
        "generic_prefix": "TEST_SECRET_AWS_",
        "shaped_example": "TEST_SECRET_AWS_wJalrXUtnFEMI/K7MDENG/bPxRfiCY",
        "shaped_pattern": r"TEST_SECRET_AWS_[A-Za-z0-9/+=]{20,}",
    },
    "telegram_bot_token": {
        "generic_prefix": "TEST_SECRET_TELEGRAM_",
        "shaped_example": "123456:TEST_SECRET_TELEGRAM_xxxxxxxxxxxxxxxxxxx",
        "shaped_pattern": r"\d+:TEST_SECRET_TELEGRAM_[A-Za-z0-9_-]{15,}",
    },
    "stripe_secret": {
        "generic_prefix": "TEST_SECRET_STRIPE_",
        "shaped_example": "sk_test_TEST_SECRET_STRIPE_xxxxxxxxxxxxxxxxxxxx",
        "shaped_pattern": r"sk_test_TEST_SECRET_STRIPE_[A-Za-z0-9]{20}",
    },
    "jwt_secret": {
        "generic_prefix": "TEST_SECRET_JWT_",
        "shaped_example": "eyJ-TEST_SECRET_JWT_xxxxxxxxxxxxxxxxxxxxxxxx",
        "shaped_pattern": r"eyJ-TEST_SECRET_JWT_[A-Za-z0-9_-]{20,}",
    },
    "database_password": {
        "generic_prefix": "TEST_SECRET_DBPASS_",
        "shaped_example": "TEST_SECRET_DBPASS_xK9mPqW3nL8vB2jH5dF",
        "shaped_pattern": r"TEST_SECRET_DBPASS_[A-Za-z0-9]{12,}",
    },
    "generic_api_token": {
        "generic_prefix": "TEST_SECRET_API_",
        "shaped_example": "TEST_SECRET_API_xxxxxxxxxxxxxxxxxxxxxxxx",
        "shaped_pattern": r"TEST_SECRET_API_[A-Za-z0-9]{16,}",
    },
    "generic_password": {
        "generic_prefix": "TEST_SECRET_PWD_",
        "shaped_example": "TEST_SECRET_PWD_xK9mPqW3nL8vB2jH5dF7gJ1kL",
        "shaped_pattern": r"TEST_SECRET_PWD_[A-Za-z0-9]{12,}",
    },
}

# All canary markers MUST contain TEST_SECRET_ so the oracle and validator
# can distinguish fake from real secrets without extra allowlists.
for _k, _v in CANARY_REGISTRY.items():
    assert "TEST_SECRET_" in _v["generic_prefix"], _k
    assert "TEST_SECRET_" in _v["shaped_example"], _k
