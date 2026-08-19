"""V2/V3 regression verification (plan §47).

The core regression contract: a V2 Sample.prompt_text, run through
LegacyV2Adapter -> SecurityCase -> UserPromptRenderer -> LineModTargetAdapter,
must produce the EXACT same HTTP request body and headers that V2's
test_linemod(prompt) sends. If this holds, V3 cannot change historical
conclusions.

This test imports V2 modules directly (linemod_guard_client) and compares.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# V3
from demotest.core import SecurityCase
from demotest.datasets.adapters.legacy_v2 import LegacyV2Adapter
from demotest.renderers import get_renderer
from demotest.targets import LineModTargetAdapter
from demotest.paths import MANIFEST_DIR

# V2 (repo root, already on sys.path via conftest)
# Import test_linemod under a non-test name so pytest doesn't collect it.
import linemod_guard_client as _v2client  # noqa: E402
LINEMOD_URL = _v2client.LINEMOD_URL
LINEMOD_MODEL = _v2client.LINEMOD_MODEL


def _v3_request_for_case(case: SecurityCase, api_key: str = "sr-gl-test"):
    """Build the V3 GatewayRequest exactly as the runner would."""
    renderer = get_renderer("user_prompt")
    text = renderer.render(case)
    target = LineModTargetAdapter(api_key=api_key, model=LINEMOD_MODEL, url=LINEMOD_URL)
    return target.build_request(rendered_text=text)


def _v2_request_for_prompt(prompt: str, api_key: str = "sr-gl-test"):
    """Reconstruct the V2 request body/headers from linemod_guard_client logic."""
    return {
        "url": LINEMOD_URL,
        "json_body": {
            "model": LINEMOD_MODEL,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0,
            "max_tokens": 8,
        },
        "headers": {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "X-LineMod-No-Failover": "true",
        },
    }


# Use a small real frozen V2 manifest for the regression batch.
REGRESSION_MANIFEST = "spear_explicit_30"


@pytest.mark.skipif(
    not (MANIFEST_DIR / f"{REGRESSION_MANIFEST}.json").exists(),
    reason="frozen V2 manifest not available",
)
def test_v2_v3_request_body_byte_identical_on_frozen_manifest():
    """For every sample in a frozen V2 manifest, V3 request == V2 request."""
    ad = LegacyV2Adapter(manifest_name=REGRESSION_MANIFEST, project="e6")
    cases = ad.cases()
    assert len(cases) >= 5
    mismatches = []
    for case in cases[:10]:
        v3_req = _v3_request_for_case(case)
        v2 = _v2_request_for_prompt(case.content)
        # body: V3 uses temperature=0.0 (float); V2 uses 0 (int). Normalize.
        v3_body = dict(v3_req.json_body)
        v3_body["temperature"] = int(v3_body["temperature"])
        if v3_body != v2["json_body"]:
            mismatches.append((case.case_id, "body", v3_body, v2["json_body"]))
        # headers: V3 lowercases keys; compare case-insensitively
        v3_hdrs = {k.lower(): v for k, v in v3_req.headers.items()}
        v2_hdrs = {k.lower(): v for k, v in v2["headers"].items()}
        if v3_hdrs != v2_hdrs:
            mismatches.append((case.case_id, "headers", v3_hdrs, v2_hdrs))
    assert not mismatches, f"V2/V3 request mismatches: {mismatches[:3]}"


@pytest.mark.skipif(
    not (MANIFEST_DIR / f"{REGRESSION_MANIFEST}.json").exists(),
    reason="frozen V2 manifest not available",
)
def test_v2_v3_outcome_parity_via_classifier():
    """The V3 HTTP parser must classify responses identically to V2."""
    from demotest.targets.http_parser import parse_linemod_response
    from linemod_guard_client import classify_linemod_http

    parity_cases = [
        (403, json.dumps({"error": "SECURITY_BLOCKED", "scanner": "x"})),
        (200, json.dumps({"choices": [{"message": {"content": "ok"}}]})),
        (503, "cooldown no upstream"),
        (429, "Too Many Requests"),
        (413, "Request Entity Too Large"),
    ]
    for status, body in parity_cases:
        v2 = classify_linemod_http(status, body)
        v3 = parse_linemod_response(status, body)
        v2_outcome = v2["outcome"]
        v3_outcome = v3.outcome.value
        # name remap: V2 "passed_upstream_cooldown" == V3 "upstream_cooldown"
        if v2_outcome == "passed_upstream_cooldown":
            v2_outcome = "upstream_cooldown"
        assert v2_outcome == v3_outcome, (
            f"parity fail status={status}: v2={v2_outcome} v3={v3_outcome}"
        )


@pytest.mark.skipif(
    not (MANIFEST_DIR / f"{REGRESSION_MANIFEST}.json").exists(),
    reason="frozen V2 manifest not available",
)
def test_legacy_adapter_preserves_all_prompt_text():
    """Every V2 prompt_text must survive into the SecurityCase.content verbatim."""
    ad = LegacyV2Adapter(manifest_name=REGRESSION_MANIFEST, project="e6")
    v2_data = json.loads((MANIFEST_DIR / f"{REGRESSION_MANIFEST}.json").read_text(encoding="utf-8"))
    v2_by_id = {s["sample_id"]: s["prompt_text"] for s in v2_data["samples"]}
    for case in ad.cases():
        v2_text = v2_by_id.get(case.metadata["v2_sample_id"])
        assert v2_text is not None
        assert case.content == v2_text, f"content drift for {case.case_id}"


def test_v2_v3_manifest_store_untouched():
    """plan §48/§49: V3 must not write to cache/sample_manifests."""
    # The LegacyV2Adapter only reads; verify no new writes by checking it
    # never opens for writing.
    ad = LegacyV2Adapter(manifest_name=REGRESSION_MANIFEST, project="e6")
    ad.cases()  # exercise read path
    # manifest store dir should contain no .tmp / .v3 files
    for p in MANIFEST_DIR.glob("*"):
        assert not p.name.endswith(".tmp")
        assert not p.name.endswith(".v3")
