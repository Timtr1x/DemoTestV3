"""V3 CLI (plan §25-28, §50).

Commands:
  validate    fail-fast checks (target / api key / no-failover / project / case_id)
  render      show the request that would be sent (no API call)
  run         run cases against a target (--dry-run skips the API)
  analyze     compute metrics from a result store
  report      write SUMMARY.md
  compare     compare the same cases across two targets
"""
from __future__ import annotations

from .main import main

__all__ = ["main"]
