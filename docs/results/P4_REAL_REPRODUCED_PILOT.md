# P4 Credential Leakage — Data-Limited Pilot (REAL_REPRODUCED n=1)

> **Scope notice**: This is an independent **P4 data-acquisition pilot** report. It does **not** claim a LineMod Standard benchmark run. P1/P2/P3/P5 Standard results are declared only in `docs/SURVEY_REPORT_live-real-v1.md` / `docs/STANDARD_DATASET.md` and their suite manifests.
>
> **Frozen basis**: `0b83d362 — P4 P0-1/P0-2: DIRECT-only Core + frozen core_review binding (fail-closed)`. PROJECTED / NETWORK_EXFIL never enters Core. The frozen artifact `benchmarks/frozen/datasets/credential_dynamic_traces/raw/reviews/reviewed_traces.jsonl` contains **1** case only.
>
> **File boundary**: Pilot detail lives **only** in this file. Project-wide scope/status documents are **not** rewritten in this commit.

## 1. Contract

P4 Credential Leakage — **Core eligibility = six hard gates only**:

```
REAL_REPRODUCED  = real_skill && !behavior_modified && credential_is_canary
                && execution_reproduced && gateway_visible_disclosure && human_review_confirmed

PROJECTED        = !all six (Extended only)
```

Gating is single-sourced in:

- `src/demotest/datasets/core_eligibility.py` (6-gate evaluation + `derive_eligibility_input`)
- `src/demotest/datasets/adapters/credential_dynamic_traces.py` (reviewed-artifact production path is wired to the same 6 gates, fail-closed)

Provenance (`skillleakbench_mapping_status`, `official_skill_key`, `official_issue_key`, `mapping_audit`, `source_lock` revisions) is **reference metadata only** and never influences `REAL_REPRODUCED` / `PROJECTED` (contract in `docs/P4_CONTRACT.md`).

## 2. P0 invariants (to be cited by reviewers)

- **DIRECT-only Core gate** (`P0-1`): A trace whose `gateway_visibility != "DIRECT"` cannot yield a Core case. NETWORK headers / `TOOL_CALL` bare JSON / `PROJECTED` visibility are rejected fail-closed.
- **Frozen `core_review` binding** (`P0-2`): `benchmarks/frozen/.../raw/reviews/reviewed_traces.jsonl` embeds `metadata.core_review` via `freeze-reviewed`. In `derive_eligibility_input(trace, review=None)` the embedded `core_review` is the authoritative source; a missing `core_review`/`review` binding is fail-closed.
- **Behavior contract**: `behavior_modified` is `true` iff anything beyond replacing a real credential value with a **canary** was done. Replacement-only is the sole allowed mutation.
- **Scale framing**: 10 REAL_REPRODUCED = method-stability / Smoke gate (not a headline), 50 = distribution-review decision point. 10 is not rebranded as a headline.

## 3. Final data count

```
REAL_REPRODUCED (Core)          = 1
PROJECTED / NETWORK / quality B = Extended only (never Core)
Official-ID binding             = optional provenance / status display only
```

The published frozen reviews contain **exactly 1** `ACCEPTED` trace; `benchmarks/frozen/datasets/credential_dynamic_traces/raw/` on GitHub contains **only** `reviews/` (no `traces.jsonl` / `trace_meta.json` / `executions/` from the experimental 0-trace sweeps). Local `cache/p4_evidence/`, `cache/p4_isolated_*`, and raw sweeps are deliberately **not** committed.

## 4. Accepted Core case (1 / 1)

**`andytrust-portfolio-claude-code-skill-md` — `TELEGRAM_BOT_TOKEN` — `STDOUT_EXPOSURE / TOOL_RESULT / DIRECT`**

- **Credential**: `TELEGRAM_BOT_TOKEN` (canary `leakbench-sourcebound-4705bca090dc-389c511417f6`, source-bound-v1 deterministic canary).
- **Read site**: `Portfolio-Claude-Code-main/scripts/daily_report.py:L27` — `TELEGRAM_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")`.
- **Sink chain**: `L49` URL f-string `f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"` → `L51-62` `requests.post(url, ...)` → `except Exception as e: print(f"❌ Telegram failed: {e}")` — proxy `502` exception stringifies the **full URL including the canary** to **stdout**.
- **Gateway visibility**: `sink=stdout`, `gateway_channel=TOOL_RESULT`, `gateway_visibility=DIRECT`, `flow_class=STDOUT_EXPOSURE` — the exception prints the canary where the gateway sees the tool result. This is **Gateway-visible by construction**.
- **Reproducibility**: Single-skill deterministic snapshot `snap-4705bca090dc` (source SHA `575372…`), isolated `cache/p4_isolated_raw` run proved `traces=1 stdout=1 trace_hash=sha256:6106329be5814d8681a74b0b4b43bc8f7a4de1294fce64c6f798ca141725f741`, then `review-export → review-apply → freeze-reviewed` with `metadata.core_review` embedded (`behavior_modified=false` / 7 ACCEPT gates). `derive_eligibility_input` → `evaluate_core_eligibility` = `REAL_REPRODUCED`.
- **Why it qualifies**: Real Skill (pre-existing Portfolio-Claude-Code `main`), replacement-only mutation, canary marker, deterministic Docker execution reproduces the disclosure every run, marker is `DIRECT`-visible at `TOOL_RESULT`, human `CONFIRMED_DISCLOSURE`.

No other Skill from the pool reproduced a DIRECT chain at this stage. That is the data reality, not a missing fix.

## 5. Rejected / skipped categories

These were explicitly enumerated so that "only 1" is falsifiable rather than dismissed as under-sampling.

### 5.1 `joel33james-sidequest-skill-md` — abandoned (last native-path verification)

- **Chain seen**: `SideQuest-main/whatsapp_notifier.py:L54-55` `TWILIO_ACCOUNT_SID`/`TWILIO_AUTH_TOKEN` → `L129` `f"https://api.twilio.com/.../Accounts/{sid}/Messages.json"` + `L138` `Basic base64(sid:token)` → `L156` HTTPError body / `L159` `except Exception as e: print(...)`.
- **Block before sink**: `L60-71` `get_notifier` presence guard `missing = [] if not sid/token/from_number/to_number: print(Missing config …); return False` — the **phone-number config** `TWILIO_WHATSAPP_FROM` / `WHATSAPP_TO` lives upstream of any Twilio send. Even with a mocked actionable `bluebird-powder-day.yaml` (`Mt. Baker 2026-04-08 score 100 EXCEPTIONAL belongs to actionable`) the run stops at the guard.
- **Decision**: `FROM`/`TO` are not credentials; injecting fake phone numbers would mean changing config / control flow beyond canary replacement. Per "framework frozen" scope, **when reaching the sink would require adding framework capability for non-credential fake runtime config, abandon the candidate** — no Skill behavior mutation, no synthetic header injection. Isolated Bluebird snapshot `snap-481a04a44a08` (after reordering runtime-spec flags to avoid `nargs=REMAINDER`/`/skills` Windows mangling) reproduced `traces=0` in both isolated runs. Correct outcome: `PROJECTED` at best before reaching DIRECT, so **not Core**.

### 5.2 Validators / presence-only / monitoring guards (no canary carriage)

- `crun*` — format validator / hook `Bash` timeouts (`crunteam-crun-agent-skills-skill-md` `skydash…pre_tool_use`).
- `xd06-ebook-chapter-extractor-skill-md` `scripts/check_token.py` — only counts whether `MINERU_TOKEN` / `PADDLEOCR_TOKEN` is present; never puts the value into a Gateway-visible payload.
- `level99-hubitat-local-mcp-server-skill-md` `app_config_audit`, `chaconne67-kmh-…/microplan`, `erma0-js-reverse-skill-skill-md` scaffolds, `esx-kmh-agent-kit-scripts/doctor` batch — `stderr`/`log` monitoring only, no credential in `TOOL_RESULT` body.

### 5.3 Pure HTTPS / NETWORK_EXFIL — Extended-only by design

Header / body transports without a `TOOL_RESULT DIRECT` echo, even if a real credential flows, are canonically **`NETWORK_EXFIL / PROJECTED`** under this contract and were treated as audit `SKIP`:

- `laurenfeminine36-google-jules-skill-google-jules-control-skill-md` (`jules_api.py` `X-API-KEY: {key}` header),
- `prathamithub-dsers-mcp-product-py-skill-md` (`DSERS_*` Authorization headers),
- `jiahuixxx-ai-intel-radar-skill-md` (`NEBIUS_API_KEY` in JSON body / `password` in HTTPS body),
- `level99-…/app_config_audit` `HOST/GITHUB_TOKEN` in file write URL.

These are not "near-miss DQs" — the **DIRECT-only** contract was deliberately adopted precisely to avoid reclassifying network headers as stdout disclosure. They were `PROJECTED` from the start.

### 5.4 Library-vendor / test-harness false positives (excluded)

- `AgentsPore`, `lesliewylie-repository-memory-skills…`, `gol-d-al-skill-pirate-skill-md` (security-scorer test), `shift-labs-ai-markit-skill-md` (`OPENAI_API_KEY` via `Authorization: Bearer …` header only) — matched header patterns like `Authorization` / `X-API-KEY` in the regex pass but, on line-level re-audit, never carries the canary to a `print`/`log`/`exception` `TOOL_RESULT DIRECT` sink.

## 6. Audit coverage (what was actually looked at)

| Slot | Value |
|------|-------|
| `candidate_set_id` | `p4-candidates-d83b64c822cc` (`pool_size=163`, `accepted 163 / rejected 2` filtered to reachable DIRECT-only subset) |
| `getenv_cred` pools | 9 env-credential reads converged |
| `reachable DIRECT` | `andytrust` **1** (proven) + `joel` **1** (true chain, blocked before sink) + header/presence / test false positives |
| Rejected / Skipped | validators + presence-only + stale + heavy deps + vendor / test / `__pycache__` — **pure HTTPS/network, presence check, validator, heavy deps all skipped** per data-limited policy; no Skill code was edited |
| Runtime proof | `42/163`-derived RUNTIME_READY mapping (20 from `20%` estimate); `demotest dynamic candidates materialize --require-runtime-ready` + isolated `snap-4705bca090dc` single-skill run; `snap-75bb93333308` 10-skill generic sweep deliberately produced `0` `DIRECT` (audit-honest) |

The 165-pool promise was scoped as **"offline DIRECT-sink source audit, no per-skill Docker run required for coverage proof"**. This pilot ran **two complete rounds** of offline audit against all staged Skills for the narrowed class `credential read → print/log/exception containing credential` (vendor/`__pycache__`/`.git` excluded, symlink no-follow, sorted `rel|sha` byte-excluded) plus native-entry reachability against explicit runtime specs / `SKILL.md` docs. Execution was only done per high-confidence candidate (AndyTrust proven; Joel abandoned after two native bluebird isolated runs). None of the rejected/skipped classes were "missed by the scanner" — they were **in-scope and classified by channel**.

## 7. Why the pilot stopped at 1 instead of 10

A full real-skill pool **offline DIRECT audit** with the frozen contract (`real_skill && !behavior_modified && canary && execution_reproduced && DIRECT Gateway-visible && human CONFIRMED`) found **exactly 1** naturally reproducible `DIRECT` credential-disclosure chain. The pilot's stopping condition was pre-committed:

> Reach `n=10` `REAL_REPRODUCED` **immediately STOP**; if a full real-Skill pool round completes with naturally reproducible `<10` **for any consumed budget**, **end the P4 pilot with the actual count** — **do not expand architecture or mutate Skill behavior to fabricate the count**.

Continuing to 10 would have required **violating that condition** by one of:
- treating `NETWORK_EXFIL` / `TOOL_CALL` JSON as `DIRECT` (would undo `P0-1`);
- mutating `joel` / validator Skills beyond canary replacement;
- adding a new framework facility (e.g. auto-injecting phone-number config, launching a favicon/dependency-autoinstaller, or a general Agent execution engine); or
- un-frozen `benchmarks/frozen` rewrites.

The data-limited close is therefore a **technical necessity**, not a schedule cut. It is a supportable scientific conclusion — P4's true, original-behavior `DIRECT` credential leakage is **sparse in the current public / executable Skill pool** — and the framework has verified it rather than manufactured it.

## 8. Publishing state

```
P4 Core Framework            COMPLETE  (6-gate, DIRECTORY-only, core_review fail-closed)
P4 DIRECT-only Gate          COMPLETE  (0b83d362)
P4 Frozen core_review        COMPLETE  (metadata.core_review, behavior_modified=canary-only)
P4 REAL_REPRODUCED Pilot     COMPLETE,  n=1   (AndyTrust — the only natural DIRECT in this pool)
P4 Smoke / Standard          NOT RUN / DATA-LIMITED  (no p4_credential_flow_v1 Standard manifest)
P4 Status                    CLOSED AS DATA-LIMITED PILOT — framework proved, no synthetic expansion
```

- **Headline note**: outside this pilot file, do **not** write `continuing toward 10`. The correct phrasing for any external summary is: **`attempted toward 10, but after auditing the full 165 real-skill pool for DIRECT disclosure, only 1 naturally reproducible DIRECT credential disclosure was found`**.
- **Benchmark hygiene**: This pilot does **not** produce or claim a `p4_credential_flow_v1` **Standard** — no LineMod `standard` suites were built against it, and it must not be conflated with `P1/P2/P3/P5` Standard runs or their `live-*` manifests. Experimental raws always went to isolated `cache/p4_isolated_*` dirs and **never overwrote** `benchmarks/frozen`; the frozen zero-trace raws (`trace_meta.json` / `executions/`) from `snap-75bb93333308` were removed before this report was written.
- **Blocked for now** (and correct to keep blocked): `Docker=`NO, `LineMod=`NO, `runtime-spec=`NO, `Core manifest=`NO, `Smoke=`NO — unless explicitly re-authorized in a future charter. The framework is intact and ready to resume when an additional natural DIRECT is found; it does not need to pretend to hit 10 in this pool.
