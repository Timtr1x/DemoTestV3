"""Enumerations for the gateway security event model.

``Channel`` answers *where this content came from*.
``Operation`` answers *what the system is about to do with it*.
``ExpectedAction`` / ``Outcome`` answer *what should happen* vs *what did happen*.
"""
from __future__ import annotations

from enum import Enum


class Channel(str, Enum):
    """The trust channel a piece of content travels on."""

    USER_PROMPT = "user_prompt"
    EMAIL = "email"
    WEB_PAGE = "web_page"
    RAG_DOCUMENT = "rag_document"
    TOOL_RESULT = "tool_result"
    TOOL_CALL = "tool_call"
    MCP_DEFINITION = "mcp_definition"
    MEMORY_WRITE = "memory_write"
    OUTBOUND_RESPONSE = "outbound_response"
    SYSTEM_CONTEXT = "system_context"

    @classmethod
    def from_value(cls, v: str | "Channel") -> "Channel":
        if isinstance(v, cls):
            return v
        s = str(v).strip().lower()
        # accept a few common aliases
        aliases = {
            "webpage": cls.WEB_PAGE,
            "web": cls.WEB_PAGE,
            "rag": cls.RAG_DOCUMENT,
            "rag_doc": cls.RAG_DOCUMENT,
            "mcp": cls.MCP_DEFINITION,
            "mcp_tool": cls.MCP_DEFINITION,
            "memory": cls.MEMORY_WRITE,
            "outbound": cls.OUTBOUND_RESPONSE,
            "user": cls.USER_PROMPT,
            "prompt": cls.USER_PROMPT,
        }
        if s in aliases:
            return aliases[s]
        return cls(s)


class Operation(str, Enum):
    """What the system is about to do with the content."""

    CHAT = "chat"
    READ = "read"
    WRITE = "write"
    EXECUTE_TOOL = "execute_tool"
    REGISTER_TOOL = "register_tool"
    WRITE_MEMORY = "write_memory"
    SEND_DATA = "send_data"
    RETURN_RESPONSE = "return_response"

    @classmethod
    def from_value(cls, v: str | "Operation") -> "Operation":
        if isinstance(v, cls):
            return v
        s = str(v).strip().lower()
        aliases = {
            "execute": cls.EXECUTE_TOOL,
            "register": cls.REGISTER_TOOL,
            "send": cls.SEND_DATA,
            "return": cls.RETURN_RESPONSE,
        }
        if s in aliases:
            return aliases[s]
        return cls(s)


class Direction(str, Enum):
    """Traffic direction relative to the gateway."""

    INBOUND = "inbound"
    OUTBOUND = "outbound"

    @classmethod
    def from_value(cls, v: str | "Direction") -> "Direction":
        if isinstance(v, cls):
            return v
        s = str(v).strip().lower()
        aliases = {"in": cls.INBOUND, "out": cls.OUTBOUND}
        if s in aliases:
            return aliases[s]
        return cls(s)


class ExpectedAction(str, Enum):
    """What the gateway *should do* with this case (the security decision)."""

    BLOCK = "block"
    ALLOW = "allow"

    @classmethod
    def from_value(cls, v: str | "ExpectedAction") -> "ExpectedAction":
        if isinstance(v, cls):
            return v
        s = str(v).strip().lower()
        aliases = {"blocked": cls.BLOCK, "pass": cls.ALLOW, "passed": cls.ALLOW}
        if s in aliases:
            return aliases[s]
        return cls(s)


class LeakageExpectation(str, Enum):
    """For credential cases (external review F13): the *second* oracle axis.

    A credential case has two independent expectations:
      * ``expected_action`` — should the gateway block the request? (BLOCK/ALLOW)
      * ``leakage_expected`` — may the secret appear in the response?

    Splitting them prevents equating "gateway did not block" with "credential
    leaked": a benign vault-read may be ALLOW + NO_LEAK, while exfiltration to
    attacker.com is BLOCK + NO_LEAK (blocked before any leak).
    """

    NO_LEAK = "no_leak"        # secret must never appear in the response
    LEAK_ALLOWED = "leak_allowed"  # benign flow where echoing the secret is fine
    UNSET = ""                 # not a credential case; oracle ignores this axis

    @classmethod
    def from_value(cls, v: str | "LeakageExpectation") -> "LeakageExpectation":
        if isinstance(v, cls):
            return v
        s = str(v or "").strip().lower()
        aliases = {"none": cls.NO_LEAK, "allow": cls.LEAK_ALLOWED}
        if s in aliases:
            return aliases[s]
        if not s:
            return cls.UNSET
        return cls(s)


class Outcome(str, Enum):
    """What the gateway actually did (transport + observation parsed)."""

    BLOCKED = "blocked"
    PASSED = "passed"
    UPSTREAM_COOLDOWN = "upstream_cooldown"
    RATE_LIMITED = "rate_limited"
    PAYLOAD_TOO_LARGE = "payload_too_large"
    ERROR = "error"

    @classmethod
    def from_value(cls, v: str | "Outcome") -> "Outcome":
        if isinstance(v, cls):
            return v
        s = str(v).strip().lower()
        # V2 used "passed_upstream_cooldown"; V3 drops the redundant prefix
        aliases = {
            "passed_upstream_cooldown": cls.UPSTREAM_COOLDOWN,
            "cooldown": cls.UPSTREAM_COOLDOWN,
            "ok": cls.PASSED,
            "allow": cls.PASSED,
            "allowed": cls.PASSED,
        }
        if s in aliases:
            return aliases[s]
        return cls(s)


# Outcomes that are "final enough" to count in metrics (judged).
# Mirrors V2 CLEAR_OUTCOMES so the regression oracle agrees with V2.
CLEAR_OUTCOMES = frozenset(
    {Outcome.BLOCKED, Outcome.PASSED, Outcome.UPSTREAM_COOLDOWN, Outcome.PAYLOAD_TOO_LARGE}
)

# Outcomes that warrant a benchmark-level retest (transport errors / cooldown).
RETRYABLE_OUTCOMES = frozenset(
    {Outcome.RATE_LIMITED, Outcome.ERROR, Outcome.UPSTREAM_COOLDOWN}
)
