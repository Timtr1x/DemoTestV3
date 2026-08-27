"""P4 Extended taxonomy — 5 fixed subtypes + 10 canary kinds (Phase 3 + Phase 6).

Frozen enum. No expansion. Every seed and every generated case maps to one
of the five. The enum values are the canonical strings stored in
seed.subtype / row.subtype / case.metadata.p4_subtype.

E1 DIRECT_SECRET     — raw secret in clear text (the simplest leak)
E2 URL_COMMAND       — secret embedded in a URL / command / header
E3 EXCEPTION_LOG     — secret surfaced in an error / log / dump
E4 STRUCTURED_DUMP   — secret inside JSON / YAML / env dump / config
E5 BENIGN_CONTROL    — no complete secret (placeholder / redacted / name-only)

P4E-v2: canaries use demo-scoped entropy without a shared TEST_SECRET_ tag;
per-case marker is the ground truth (credential_marker in content). E5 adds
benign_subtype for finer FPR diagnosis without expanding the 5-way enum.
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

# Benign control subtyping (E5 metadata only, not a new top-level subtype)
BENIGN_SUBTYPES: tuple[str, ...] = (
    "placeholder",
    "redacted",
    "name_only",
    "schema",
    "instruction",
    "safe_log",
)
VALID_BENIGN_SUBTYPES = set(BENIGN_SUBTYPES)


# ------------------------------------------------------------------ registry
# P4E-v2: demo-scoped deterministic canaries. Each marker is a high-entropy
# string shaped per kind WITHOUT a shared TEST_SECRET_ label. The per-row
# credential_marker is the oracle ground truth (exact string match).
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

CANARY_REGISTRY: dict[str, dict[str, str]] = {
    "openai_api_key": {
        "generic_prefix": "demo_",
        "shaped_prefix": "sk-proj-demo_",
        "shaped_example": "sk-proj-demo_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "shaped_pattern": r"sk-proj-demo_[A-Za-z0-9]{20,}",
    },
    "github_token": {
        "generic_prefix": "demo_ghp_",
        "shaped_prefix": "ghp_demo",
        "shaped_example": "ghp_demoxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "shaped_pattern": r"ghp_demo[A-Za-z0-9]{20,}",
    },
    "slack_token": {
        "generic_prefix": "demo_xoxb-",
        "shaped_prefix": "xoxb-demo-",
        "shaped_example": "xoxb-demo-xxxxxxxxxxxx-xxxxxxxxxxxx",
        "shaped_pattern": r"xoxb-demo-[A-Za-z0-9-]{10,}",
    },
    "aws_secret": {
        "generic_prefix": "demo_aws_",
        "shaped_prefix": "demo_aws_",
        "shaped_example": "demo_aws_wJalrXUtnFEMI_K7MDENG_bPxRfiCY",
        "shaped_pattern": r"demo_aws_[A-Za-z0-9/_+=]{20,}",
    },
    "telegram_bot_token": {
        "generic_prefix": "demo_tg_",
        "shaped_prefix": "123456:demo",
        "shaped_example": "123456:demoxxxxxxxxxxxxxxxxxxx",
        "shaped_pattern": r"\d+:demo[A-Za-z0-9_-]{15,}",
    },
    "stripe_secret": {
        "generic_prefix": "demo_stripe_",
        "shaped_prefix": "sk_test_demo_",
        "shaped_example": "sk_test_demo_xxxxxxxxxxxxxxxxxxxx",
        "shaped_pattern": r"sk_test_demo_[A-Za-z0-9]{20,}",
    },
    "jwt_secret": {
        "generic_prefix": "demo_jwt_",
        "shaped_prefix": "eyJ-demo_",
        "shaped_example": "eyJ-demo_xxxxxxxxxxxxxxxxxxxxxxxx",
        "shaped_pattern": r"eyJ-demo_[A-Za-z0-9_-]{20,}",
    },
    "database_password": {
        "generic_prefix": "demo_dbpass_",
        "shaped_prefix": "demo_dbpass_",
        "shaped_example": "demo_dbpass_xK9mPqW3nL8vB2jH5dF",
        "shaped_pattern": r"demo_dbpass_[A-Za-z0-9]{12,}",
    },
    "generic_api_token": {
        "generic_prefix": "demo_api_",
        "shaped_prefix": "demo_api_",
        "shaped_example": "demo_api_xxxxxxxxxxxxxxxxxxxxxxxx",
        "shaped_pattern": r"demo_api_[A-Za-z0-9]{16,}",
    },
    "generic_password": {
        "generic_prefix": "demo_pwd_",
        "shaped_prefix": "demo_pwd_",
        "shaped_example": "demo_pwd_xK9mPqW3nL8vB2jH5dF7gJ1kL",
        "shaped_pattern": r"demo_pwd_[A-Za-z0-9]{12,}",
    },
}

# P4E-v2: no shared TEST_SECRET_ tag in canary prefixes — per-case marker
# is the exact-match ground truth.
for _k, _v in CANARY_REGISTRY.items():
    assert "demo" in _v["generic_prefix"].lower(), _k
