"""Renderer registry — name -> CaseRenderer class."""
from __future__ import annotations

from typing import Type

from ..core.exceptions import ConfigError
from .base import CaseRenderer

_RENDERERS: dict[str, Type[CaseRenderer]] = {}


def register_renderer(cls: Type[CaseRenderer]) -> Type[CaseRenderer]:
    if not getattr(cls, "renderer_name", None) or cls.renderer_name == "unknown":
        raise ConfigError(f"renderer {cls} has no renderer_name")
    _RENDERERS[cls.renderer_name] = cls
    return cls


def registered_renderers() -> dict[str, Type[CaseRenderer]]:
    # ensure built-in renderers are imported
    from . import user_prompt, external_content, tool_result, tool_call  # noqa: F401
    from . import mcp_definition, memory_write, credential_flow  # noqa: F401
    return dict(_RENDERERS)


def get_renderer(name: str, **kwargs) -> CaseRenderer:
    registry = registered_renderers()
    if name not in registry:
        raise ConfigError(
            f"unknown renderer {name!r}; known: {sorted(registry)}"
        )
    return registry[name](**kwargs)
