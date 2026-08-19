"""tests/v3/datasets/ — Dataset Integration (Phase 1) tests.

These tests exercise the data-engineering pipeline (source lock, adapters,
dedup, sampler, manifest builder, reproducibility) with synthetic fixtures so
they run fully offline. Real-data smoke is covered by the CLI integration test
that runs against the pinned raw snapshots when present.
"""
