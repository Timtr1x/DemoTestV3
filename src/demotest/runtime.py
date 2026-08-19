"""Project runtime — assemble renderer/target/oracle/runner for a project+target.

This is the glue that the CLI uses: given a project config + target config, build
the concrete components. Cases are grouped by channel (each channel uses one
renderer), so the CLI builds one GatewayRunner per channel group.
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

from .config import ProjectConfig, TargetConfig, get_project, get_target
from .core.exceptions import ConfigError, ValidationError
from .core.ids import compute_run_id, config_hash
from .oracles import BlockPassOracle, CanaryOracle, CompositeOracle
from .oracles.base import Oracle
from .renderers import get_renderer
from .renderers.base import CaseRenderer, RenderFidelity
from .runners import GatewayRunner
from .storage.results import ResultStore
from .targets import LineModTargetAdapter, QwenGuardTargetAdapter
from .targets.base import TargetAdapter


def build_target(tcfg: TargetConfig) -> TargetAdapter:
    if tcfg.type in ("gateway", "openai_gateway"):
        return LineModTargetAdapter(
            url=os.environ.get(tcfg.url_env),
            api_key=os.environ.get(tcfg.key_env),
            model=os.environ.get(tcfg.model_env),
            timeout=tcfg.timeout,
            benchmark_mode=tcfg.benchmark_mode,
            extra_headers=tcfg.headers,
            classification=tcfg.classification,
        )
    if tcfg.type == "classifier":
        return QwenGuardTargetAdapter(
            url=os.environ.get(tcfg.url_env, os.environ.get("QWEN3GUARD_URL")),
            model=os.environ.get(tcfg.model_env, os.environ.get("QWEN3GUARD_MODEL")),
            timeout=tcfg.timeout,
        )
    raise ConfigError(f"unknown target type {tcfg.type!r}")


def build_oracle(name: str) -> Oracle:
    if name == "block_pass":
        return BlockPassOracle()
    if name == "canary":
        return CanaryOracle()
    if name == "composite":
        return CompositeOracle()
    raise ConfigError(f"unknown oracle {name!r}")


def resolve_renderer_name(project: ProjectConfig, channel: str) -> str:
    """Pick the renderer for a channel from the project config, with sane defaults."""
    rmap = project.renderer or {}
    if channel in rmap:
        return rmap[channel].split("/")[0]  # strip version if present
    defaults = {
        "user_prompt": "user_prompt",
        "email": "external_content",
        "web_page": "external_content",
        "rag_document": "external_content",
        "tool_result": "tool_result",
        "tool_call": "tool_call",
        "mcp_definition": "mcp_definition",
        "memory_write": "memory_write",
        "outbound_response": "credential_flow",
    }
    if channel not in defaults:
        raise ConfigError(f"no renderer configured for channel {channel!r}")
    return defaults[channel]


def build_runner(
    project: ProjectConfig,
    target: TargetAdapter,
    renderer: CaseRenderer,
    store_path: Path,
    run_id: str,
    *,
    request_gap: float = 0.5,
    sleep_fn=time.sleep,
    target_cfg: TargetConfig | None = None,
) -> GatewayRunner:
    """Assemble a GatewayRunner.

    F11: the generation profile (temperature / max_tokens) is resolved as
    project.generation > target.request > default(8). Passing ``target_cfg``
    lets the CLI wire the target's profile through; without it the runner falls
    back to the V2 default (max_tokens=8), preserving regression parity.
    """
    oracle = build_oracle(project.oracle)
    store = ResultStore(store_path)
    gen = project.generation_profile(target_cfg)
    return GatewayRunner(
        renderer=renderer,
        target=target,
        oracle=oracle,
        store=store,
        run_id=run_id,
        project=project.project_id,
        request_gap=request_gap,
        sleep_fn=sleep_fn,
        temperature=gen["temperature"],
        max_tokens=gen["max_tokens"],
    )
