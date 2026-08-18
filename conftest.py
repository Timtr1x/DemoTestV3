"""Root conftest: make ``import demotest`` work without ``pip install -e .``.

V2 modules (``core``, ``adapters``, ``projects``, ``paths``) live at repo root
and are already importable from CWD. This file additionally exposes the V3
``src/`` package on ``sys.path`` so both V2 and V3 coexist in one test run.
"""
from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent
_SRC = _REPO_ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
# also ensure repo root is on path (V2 flat modules) for IDE/standalone runs
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
