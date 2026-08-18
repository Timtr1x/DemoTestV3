"""FakeLineModServer — contract test harness (plan §46).

Returns scripted HTTP responses (200/403/429/503/timeout) so the runner can be
exercised end-to-end without consuming real API quota. Mirrors V2's
FakeSession pattern but exposes a registry of scripted responses.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class FakeResponse:
    status_code: int
    text: str


@dataclass
class FakeLineModSession:
    """A requests.Session-like object that returns scripted responses.

    Responses can be queued (in order) or mapped by a callable. Records every
    POST it receives so contract tests can assert on the request body/headers.
    """

    responses: list[FakeResponse] = field(default_factory=list)
    requests: list[dict[str, Any]] = field(default_factory=list)

    def post(self, url: str, **kwargs: Any) -> FakeResponse:
        self.requests.append({"url": url, **kwargs})
        if not self.responses:
            return FakeResponse(200, '{"choices":[{"message":{"content":"ok"}}]}')
        return self.responses.pop(0)

    @classmethod
    def with_script(cls, script: list[tuple[int, str]]) -> "FakeLineModSession":
        return cls(responses=[FakeResponse(s, t) for s, t in script])


def blocked_body(scanner: str = "prompt_injection", score: float = 0.99) -> str:
    import json
    return json.dumps({
        "error": {"code": "SECURITY_BLOCKED", "scanner": scanner,
                  "policy": "standard", "score": score},
    })


def passed_body(content: str = "ok") -> str:
    import json
    return json.dumps({"choices": [{"message": {"content": content}}]})


def cooldown_body() -> str:
    return "model cooldown excluded_models"


def rate_limited_body() -> str:
    return "Too Many Requests"
