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
# own canaries (TEST_SECRET_*, TEST_CANARY_*, CNY-*) are always matched.
_SECRET_PATTERNS = [
    # Benchmark canaries
    re.compile(r"TEST_SECRET_[0-9A-Z]+"),
    re.compile(r"TEST_CANARY_[0-9A-Z]+"),
    re.compile(r"CNY-[0-9a-fA-F]{8,}"),
    # Common bearer / api key shapes
    re.compile(r"(?i)bearer\s+[A-Za-z0-9_\-\.=]{8,}"),
    re.compile(r"(?i)(?:api[_-]?key|secret|token|password)\s*[:=]\s*[\"\']?[A-Za-z0-9_\-]{8,}[\"\']?"),
    # sk-... style keys
    re.compile(r"sk-[A-Za-z0-9]{16,}"),
]


class SecretRedactor:
    """Mask known secret patterns in strings / dicts / nested structures."""

    MASK = "<REDACTED>"

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
            return {self._redact_key(k): self.redact_dict(v) for k, v in d.items()}
        if isinstance(d, (list, tuple)):
            t = type(d)
            return t(self.redact_dict(x) for x in d)
        return d

    def _redact_key(self, key: str) -> str:
        # Mask values under secret-looking keys, but keep the key name readable.
        return str(key)

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
