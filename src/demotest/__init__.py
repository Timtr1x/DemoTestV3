"""DemoTest V3 — Gateway Security Benchmark Framework.

V3 upgrades the core abstraction from ``Sample.prompt_text`` (a single prompt)
to ``SecurityCase`` — a structured *security event* that flows through the
gateway on a named trust *channel* and *operation*.

Layout::

    src/demotest/
        core/        # SecurityCase, enums, contracts, ids, exceptions
        datasets/    # DatasetAdapter ABC + registry + legacy_v2 bridge
        renderers/   # SecurityCase -> GatewayRequest
        targets/     # LineMod / QwenGuard TargetAdapter
        runners/     # GatewayRunner, retry, scheduler
        oracles/     # BlockPass / Canary / Composite
        metrics/     # detection / leakage / grouping
        analysis/    # analyzer / breakdown / compare
        reporting/   # markdown / summary
        storage/     # manifests / results / cache
        cli/         # validate / render / run / analyze / report / compare

V2 (the legacy ``Sample.prompt_text`` framework under ``core/``, ``adapters/``,
``projects/``) is intentionally left intact and bridged via
``demotest.datasets.adapters.legacy_v2.LegacyV2Adapter`` so historical results
stay comparable.
"""

__version__ = "3.0.0"
