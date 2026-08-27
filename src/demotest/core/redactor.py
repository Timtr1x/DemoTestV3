"""SecretRedactor — unified masking across all logs / dumps / reports (plan §24).

V3 expands V2's API-key-only masking into a single redactor covering every
output surface: logs, exceptions, request dumps, result dumps, debug, reports.

Credential benchmarks use fake canaries (e.g. ``TEST_SECRET_7B021C``) never real
secrets. The redactor's own self-test (plan §43) verifies that a canary never
appears in any redacted output.
"""
from __future__ import annotations

import re
from typing import Any, Iterable


# Patterns that look like secrets. Keep broad + conservative; the benchmark's
# own canaries (TEST_SECRET_*, TEST_CANARY_*, CNY-*, P4E-v2 demo_* shapes) are always matched.
_SECRET_PATTERNS = [
    # Benchmark canaries — v1 + v2
    re.compile(r"TEST_SECRET_[0-9A-Z]+"),
    re.compile(r"TEST_CANARY_[0-9A-Z]+"),
    re.compile(r"CNY-[0-9a-fA-F]{8,}"),
    # P4E-v2 demo-scoped canaries (no shared TEST_SECRET_ tag) — shape regex
    re.compile(r"sk-proj-demo_[A-Za-z0-9]{16,}"),
    re.compile(r"ghp_demo[A-Za-z0-9]{20,}"),
    re.compile(r"xoxb-demo-[A-Za-z0-9\-]{8,}"),
    re.compile(r"demo_aws_[A-Za-z0-9/_+=]{16,}"),
    re.compile(r"sk_test_demo_[A-Za-z0-9]{16,}"),
    re.compile(r"eyJ-demo_[A-Za-z0-9_\-]{16,}"),
    re.compile(r"demo_(?:dbpass|api|pwd)[_A-Za-z0-9]{8,}"),
    re.compile(r"\d+:demo[A-Za-z0-9_\-]{10,}"),
    # Common bearer / api key shapes
    re.compile(r"(?i)bearer\s+[A-Za-z0-9_\-\.=]{8,}"),
    re.compile(r"(?i)(?:api[_-]?key|secret|token|password)\s*[:=]\s*[\"\']?[A-Za-z0-9_\-]{8,}[\"\']?"),
    # sk-... style keys
    re.compile(r"sk-[A-Za-z0-9]{16,}"),
]


class SecretRedactor:
    """Mask known secret patterns in strings / dicts / nested structures.

    Two layers of defense (external review P1-6):
      1. **Pattern-based** — regex over string values (TEST_SECRET_*, Bearer, sk-*,
         ``api_key=...`` assignments). Catches secrets embedded in free text.
      2. **Key-based** — any value under a sensitive key name (api_key, token,
         password, ...) is replaced wholesale. Catches secrets that don't match
         any regex (e.g. ``{"api_key": "sr-gl-123456789abcdef"}``). Better to
         over-redact than to leak.
    """

    MASK = "<REDACTED>"

    # Keys whose values are always masked, regardless of the value's shape.
    SENSITIVE_KEYS = frozenset({
        "api_key", "apikey", "api-key",
        "authorization", "auth",
        "token", "tokens", "access_token", "access-token",
        "refresh_token", "refresh-token",
        "password", "passwd", "pwd",
        "secret", "secrets", "client_secret", "clientsecret",
        "private_key", "privatekey",
        "credential", "credentials",
    })

    def __init__(self, extra_markers: Iterable[str] | None = None) -> None:
        self._extra = [m for m in (extra_markers or []) if m]
        self._compiled_extra = [re.compile(re.escape(m)) for m in self._extra if m]

    def redact_text(self, text: str) -> str:
        if not text:
            return text
        out = text
        for pat in _SECRET_PATTERNS:
            out = pat.sub(self.MASK, out)
        for pat in self._compiled_extra:
            out = pat.sub(self.MASK, out)
        return out

    def redact_dict(self, d: Any) -> Any:
        if isinstance(d, str):
            return self.redact_text(d)
        if isinstance(d, dict):
            return {self._redact_key(k): self._redact_value(k, v) for k, v in d.items()}
        if isinstance(d, (list, tuple)):
            t = type(d)
            return t(self.redact_dict(x) for x in d)
        return d

    def _redact_key(self, key: str) -> str:
        # Keep the key name readable so logs stay debuggable.
        return str(key)

    def _redact_value(self, key: str, value: Any) -> Any:
        # R4-5: mask ANY value under a sensitive key wholesale, regardless of
        # type (str / dict / list / int / None). The previous isinstance(value,
        # str) check let nested dicts under "credentials" recurse and leak
        # inner values that don't match a regex. Better to over-redact than leak.
        if str(key).lower() in self.SENSITIVE_KEYS:
            return self.MASK
        return self.redact_dict(value)

    def __call__(self, value: Any) -> Any:
        return self.redact_dict(value)


_DEFAULT_REDACTOR = SecretRedactor()


def redact(value: Any) -> Any:
    """Module-level convenience redactor."""
    return _DEFAULT_REDACTOR.redact_dict(value)


def redact_text(text: str) -> str:
    return _DEFAULT_REDACTOR.redact_text(text)


def assert_no_secret(text: str, markers: Iterable[str] | None = None) -> None:
    """Self-test helper (plan §43): raise if any marker survives in text."""
    checks = list(markers or [])
    for m in checks:
        if m and m in text:
            raise AssertionError(f"secret marker {m!r} found in output")
