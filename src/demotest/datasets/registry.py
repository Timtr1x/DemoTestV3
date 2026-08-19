"""Adapter registry — name -> DatasetAdapter class."""
from __future__ import annotations

from typing import Type

from .base import DatasetAdapter
from ..core.exceptions import ConfigError

_ADAPTERS: dict[str, Type[DatasetAdapter]] = {}


def register_adapter(cls: Type[DatasetAdapter]) -> Type[DatasetAdapter]:
    if not getattr(cls, "dataset_id", None):
        raise ConfigError(f"adapter {cls} has no dataset_id")
    _ADAPTERS[cls.dataset_id] = cls
    return cls


def registered_adapters() -> dict[str, Type[DatasetAdapter]]:
    # ensure built-in adapters are imported
    from . import adapters as _adapters  # noqa: F401  (triggers registration)
    return dict(_ADAPTERS)


def get_adapter(name: str, **kwargs) -> DatasetAdapter:
    registry = registered_adapters()
    if name not in registry:
        raise ConfigError(
            f"unknown dataset adapter {name!r}; known: {sorted(registry)}"
        )
    return registry[name](**kwargs)
