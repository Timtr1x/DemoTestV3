"""Runner abstract base (plan §29)."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from ..core.contracts import CaseResult
from ..core.models import SecurityCase


@dataclass
class RunResult:
    total: int = 0
    skipped: int = 0
    ran: int = 0
    written: int = 0
    retested: int = 0
    errors: int = 0
    results: list[CaseResult] = field(default_factory=list)


class Runner(ABC):
    """A runner knows only SecurityCase + Renderer + TargetAdapter + Oracle.

    It MUST NOT know about E2 / LLMail / AuthBench / specific datasets — that
    isolation is what keeps the framework maintainable long-term (plan §29).
    """

    @abstractmethod
    def run(self, cases: list[SecurityCase], *, dry_run: bool = False) -> RunResult:
        raise NotImplementedError

    @abstractmethod
    def retest(self, cases: list[SecurityCase]) -> RunResult:
        raise NotImplementedError
