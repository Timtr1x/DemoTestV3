"""Renderers — SecurityCase -> rendered text (plan §7, §8).

A renderer is a *transport format*, not an attack-data generator. The attack
payload comes from the real dataset (via a DatasetAdapter); the renderer only
wraps it in a fixed, stable template that tells the gateway *what channel this
content is on* (e.g. "this is a Tool Result").

Every renderer is deterministic: same case + same renderer version ->
byte-identical rendered text (unit-tested). When a wrapper changes, the
renderer's ``version`` bumps (plan §21) so score deltas can be attributed to
either the gateway or the test format.
"""
from __future__ import annotations

from .base import CaseRenderer, RenderFidelity
from .registry import get_renderer, register_renderer, registered_renderers

__all__ = [
    "CaseRenderer",
    "RenderFidelity",
    "get_renderer",
    "register_renderer",
    "registered_renderers",
]
