# Benchmark splits: DEV / EVAL / HOLDOUT access policy (guide §61-§62)

Phase 1 produces three tiers of frozen manifests. Access to case bodies is
governed by split, not by manifest file. This document is the standing policy
referenced by `benchmarks/manifests/`.

## Splits

| Split | Manifest | Purpose | Body access |
|-------|----------|---------|-------------|
| DEV | `smoke-v1/` (all cases are `dev`) | CI, adapter / renderer debugging | full — developers may read content, inspect failures, tune the gateway |
| EVAL | `phase1-standard-v1/` | the first reportable, comparable number | aggregate metrics + a controlled diagnostic sample; avoid bulk case reading |
| HOLDOUT | `holdout-v1/` | version-release / phase acceptance | **no routine case-body access**; never tune the gateway against it |

## HOLDOUT isolation (guide §62)

* `benchmarks/manifests/holdout-v1/` is a committed, separate directory holding
  **only** the `holdout`-split cases (the manifest stores identity; case bodies
  resolve from the raw dataset at run time — they are never copied into the
  manifest).
* HOLDOUT manifests are referenced by `phase1-full-v1` (which spans
  `eval + holdout`) and by this standalone `holdout-v1/`.
* Recommended team control: gate the `holdout-v1/` path behind a separate
  reviewer approval (or a separate git branch / access group). The manifests
  themselves carry no payload, but a run that resolves them exposes bodies.
* HOLDOUT is used for: version-release validation, phase acceptance, and
  detecting overfitting to EVAL. It is **not** used for day-to-day tuning.

## What may NOT be done

* Tune the gateway by reading HOLDOUT case bodies, then report an EVAL/HOLDOUT
  number as an unaltered baseline (guide §60). First run Baseline-0 on the
  unmodified gateway; only then iterate and compare.
* Move a case between splits to improve a metric — splits are frozen per
  `group_id` and reproducible (guide §37, §64).
* Overwrite a frozen manifest. A new selection or new data is a new version
  (`standard-v1` → `standard-v2`), never an in-place edit.
