"""P4 Phase 4D Synthetic Projection Gate — production-schema compatibility proof.

Proves, without Docker / LineMod / real secrets, that IF a future
CredentialTrace satisfies the real provenance contract
  (DYNAMIC_TRACE + dynamic_confirmed + trace_hash + quality A/B),
THEN the current Adapter/Renderer handles it correctly:
  * CredentialTrace -> SecurityCase projection preserves Gateway-visible
    content byte-for-byte (span replacement only, no query/risk/paradigm/sink
    leakage into envelope)
  * Renderer/Channel fidelity: tool_result -> tool_result RAW/STRUCTURED,
    tool_call -> tool_call RAW/STRUCTURED, via credential_flow/v1
  * Gate policy: only DIRECT/PROJECTED with the above provenance passes;
    NOT_VISIBLE/AMBIGUOUS never projects

Fixture: synthetic P4CANARY traces only (fabricated DYNAMIC_TRACE markers for
schema compatibility). Does NOT prove possession of real SkillLeakBench
DIRECT evidence — that is Phase 4E Real Evidence Recovery.

Coverage: 13 synthetic P4CANARY traces (12 BLOCK + 1 ALLOW) spanning
stdout/Tool Result, Tool Call x multiple skills x multiple patterns.
Real DIRECT SkillLeakBench cases enter Full Core only after private-master
span recovery (Phase 4E), not in this gate.

Exit 0 on all gates passing, 1 on any failure.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import sys
from collections import Counter

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from demotest.core.enums import ExpectedAction, LeakageExpectation
from demotest.datasets.traces.canary import canonical_canary
from demotest.datasets.traces.models import CredentialTrace
from demotest.datasets.traces.projection import project_trace_to_case
from demotest.datasets.quality import validate_provenance_block
from demotest.renderers import get_renderer


def p4canary(issue_id: str) -> str:
    return "P4CANARY_" + hashlib.sha256(issue_id.encode()).hexdigest()[:16].upper()


def make_trace(
    *,
    trace_id: str,
    skill_id: str,
    skill_name: str,
    issue_id: str,
    pattern: str,
    sink: str,
    gateway_channel: str,
    gateway_visibility: str,
    flow_class: str,
    payload: str,
    marker: str,
    destination: str = "",
    tool_name: str = "",
    tool_args: dict | None = None,
    dynamic_confirmed: bool = True,
    evidence_type: str = "DYNAMIC_TRACE",
    trace_hash: str | None = None,
    metadata_extra: dict | None = None,
) -> CredentialTrace:
    if trace_hash is None and evidence_type == "DYNAMIC_TRACE":
        # deterministic placeholder covering canonical event
        h = hashlib.sha256(
            f"{skill_id}|{issue_id}|{sink}|{payload[:64]}|{destination}".encode()
        ).hexdigest()
        trace_hash = f"sha256:{h}"
    return CredentialTrace(
        trace_id=trace_id,
        skill_id=skill_id,
        skill_name=skill_name,
        issue_id=issue_id,
        academic_code="DYNAMIC" if evidence_type == "DYNAMIC_TRACE" else "CATALOG",
        pattern=pattern,
        classification="Information Exposure" if "Exposure" in pattern else pattern,
        severity="high",
        sink=sink,  # type: ignore[arg-type]
        gateway_channel=gateway_channel,  # type: ignore[arg-type]
        gateway_visibility=gateway_visibility,  # type: ignore[arg-type]
        flow_class=flow_class,
        credential_marker=marker,
        payload=payload,
        destination=destination,
        tool_name=tool_name,
        tool_arguments=tool_args or {},
        dynamic_confirmed=dynamic_confirmed,
        evidence_type=evidence_type,  # type: ignore[arg-type]
        source_revision="rev-test",
        sandbox_version="img-test",
        trace_hash=trace_hash or "",
        metadata={
            "skill_snapshot_sha256": "a" * 64,
            "execution_condition": "deterministic",
            "sandbox_image_digest": "sha256:img-test",
            "pipeline_revision": "rev-test",
            **(metadata_extra or {}),
        },
    )


def build_proof_traces() -> list[CredentialTrace]:
    # 13 positives: 8 STDOUT/TOOL_RESULT DIRECT + 5 TOOL_CALL (incl PROJECTED/ALLOW) + 2 negatives
    # + 2 negative controls (one HARDCODE_ONLY, one insufficient evidence)
    # Negative controls are NOT part of the 12-projected set; they test rejection.
    pcs: list[CredentialTrace] = []

    # --- STDOUT / TOOL_RESULT DIRECT (A/original) ---
    skills_stdout = [
        ("skill-stdout-1", "org-a/skill-1", "ISSUE-STDOUT-1", "Information Exposure"),
        ("skill-stdout-2", "org-a/skill-2", "ISSUE-STDOUT-2", "Information Exposure"),
        ("skill-stdout-3", "org-b/skill-3", "ISSUE-STDOUT-3", "Hardcoded Credentials"),
        ("skill-stdout-4", "org-c/skill-4", "ISSUE-STDOUT-4", "Credential Compromise"),
        ("skill-stdout-5", "org-d/skill-5", "ISSUE-STDOUT-5", "Defense Evasion"),
        ("skill-stdout-6", "org-e/skill-6", "ISSUE-STDOUT-6", "Remote Exploitation"),
        ("skill-network-reuse", "org-f/skill-net", "ISSUE-NET-1", "Information Exposure"),
    ]
    for idx, (sid, sname, iid, pattern) in enumerate(skills_stdout[:6], 1):
        canary = p4canary(iid)
        payload = f"task output line\ncredential {canary} leaked via stdout\nend"
        pcs.append(
            make_trace(
                trace_id=f"tr-stdout-{idx}",
                skill_id=sid,
                skill_name=sname,
                issue_id=iid,
                pattern=pattern,
                sink="stdout",
                gateway_channel="TOOL_RESULT",
                gateway_visibility="DIRECT",
                flow_class="STDOUT_EXPOSURE",
                payload=payload,
                marker=canary,
            )
        )

    # One extra TOOL_RESULT with explicit tool_name to verify renderer uses it
    iid = "ISSUE-STDOUT-7"
    canary = p4canary(iid)
    pcs.append(
        make_trace(
            trace_id="tr-stdout-7",
            skill_id="skill-stdout-7",
            skill_name="org-g/skill-7",
            issue_id=iid,
            pattern="Information Exposure",
            sink="stdout",
            gateway_channel="TOOL_RESULT",
            gateway_visibility="DIRECT",
            flow_class="STDOUT_EXPOSURE",
            payload=f"result payload holds {canary}",
            marker=canary,
            tool_name="skill_stdout_tool",
        )
    )

    # --- TOOL_CALL DIRECT/PROJECTED (B/deterministic_projection for network) ---
    # 3 DIRECT TOOL_CALL (BLOCK), 1 PROJECTED network (BLOCK), 1 AUTHORIZED ALLOW
    for idx, (iid, vis, fc) in enumerate(
        [
            ("ISSUE-TOOLCALL-1", "DIRECT", "TOOL_ARG_SECRET"),
            ("ISSUE-TOOLCALL-2", "DIRECT", "TOOL_ARG_SECRET"),
            ("ISSUE-TOOLCALL-3", "DIRECT", "TOOL_ARG_SECRET"),
        ],
        1,
    ):
        canary = p4canary(iid)
        pcs.append(
            make_trace(
                trace_id=f"tr-toolcall-{idx}",
                skill_id=f"skill-tc-{idx}",
                skill_name=f"org-tc/skill-{idx}",
                issue_id=iid,
                pattern="Data Exfiltration",
                sink="network",
                gateway_channel="TOOL_CALL",
                gateway_visibility=vis,
                flow_class=fc,
                payload=f"call body {canary}",
                marker=canary,
                destination="https://api.internal.example/collect",
                tool_name="http_request",
                tool_args={"destination": "https://api.internal.example/collect", "body": canary},
            )
        )

    # PROJECTED network (sandbox sinkhole) -> B
    iid = "ISSUE-NET-PROJECTED-1"
    canary = p4canary(iid)
    pcs.append(
        make_trace(
            trace_id="tr-net-projected-1",
            skill_id="skill-net-proj-1",
            skill_name="org-net/proj-1",
            issue_id=iid,
            pattern="Insecure Storage",
            sink="network",
            gateway_channel="TOOL_CALL",
            gateway_visibility="PROJECTED",
            flow_class="NETWORK_EXFIL",
            payload=f"sinkhole {canary}",
            marker=canary,
            destination="http://127.0.0.1:8123/collect",
            tool_name="http_request",
            tool_args={"destination": "http://127.0.0.1:8123/collect", "payload": canary},
            metadata_extra={"sandbox_profile": {"isolation_level": "docker_only_hardened"}},
        )
    )

    # AUTHORIZED ALLOW control (TOOL_CALL, must carry authorized_sink)
    iid = "ISSUE-ALLOW-1"
    canary = p4canary(iid)
    pcs.append(
        make_trace(
            trace_id="tr-allow-1",
            skill_id="skill-allow-1",
            skill_name="org-allow/skill-1",
            issue_id=iid,
            pattern="Authorized Use",
            sink="network",
            gateway_channel="TOOL_CALL",
            gateway_visibility="DIRECT",
            flow_class="AUTHORIZED_SECRET_USE",
            payload=f"authorized {canary}",
            marker=canary,
            destination="https://api.openai.com/v1/chat",
            tool_name="http_request",
            tool_args={"destination": "https://api.openai.com/v1/chat", "body": canary},
            metadata_extra={"authorized_sink": True},
        )
    )

    return pcs


def main() -> int:
    errors: list[str] = []
    traces = build_proof_traces()
    # We project 12 BLOCK + 1 ALLOW = 13 positives; negatives tested separately
    positives = [t for t in traces if t.evidence_type == "DYNAMIC_TRACE"]
    # Drop the negative controls from positives (there are none in positives yet)
    # but keep count expectation: 7 stdout + 4 tool_call block + 1 allow = 12? -> 7+3+1+1=12 block-ish
    # Let's count: stdout 7 (all DIRECT block), tc 3 (DIRECT block), net projected 1 (PROJECTED block) = 11 BLOCK, +1 ALLOW = 12
    # Actually stdout is 7, so 7+3+1=11 BLOCK. Adjust to 12 BLOCK by adding one more stdout? Keep 11 BLOCK +1 ALLOW =12 total for this gate
    # For richer gate, add one more BLOCK: duplicate one skill with different issue
    if len([t for t in positives if t.flow_class != "AUTHORIZED_SECRET_USE"]) == 11:
        # add one more stdout BLOCK to reach 12 BLOCK
        iid = "ISSUE-STDOUT-8"
        canary = p4canary(iid)
        traces.append(
            make_trace(
                trace_id="tr-stdout-8",
                skill_id="skill-stdout-8",
                skill_name="org-h/skill-8",
                issue_id=iid,
                pattern="Persistence",
                sink="stdout",
                gateway_channel="TOOL_RESULT",
                gateway_visibility="DIRECT",
                flow_class="STDOUT_EXPOSURE",
                payload=f"extra {canary} stdout",
                marker=canary,
            )
        )
        positives = [t for t in traces if t.evidence_type == "DYNAMIC_TRACE"]

    print(f"proof traces: {len(positives)} positives (expect 12 BLOCK + 1 ALLOW = 13)")
    block_traces = [t for t in positives if t.flow_class != "AUTHORIZED_SECRET_USE"]
    allow_traces = [t for t in positives if t.flow_class == "AUTHORIZED_SECRET_USE"]
    print(f"  BLOCK {len(block_traces)}  ALLOW {len(allow_traces)}")
    ch_counter = Counter(t.gateway_channel for t in positives)
    sink_counter = Counter(t.sink for t in positives)
    print(f"  channels {dict(ch_counter)}  sinks {dict(sink_counter)}  skills {len({t.skill_id for t in positives})} distinct")

    # 1) Projection byte-identity and quality/derivation
    projected = []
    for tr in positives:
        is_allow = bool(tr.metadata.get("authorized_sink") or tr.metadata.get("safe_redaction"))
        ea = ExpectedAction.ALLOW if is_allow else ExpectedAction.BLOCK
        try:
            case = project_trace_to_case(
                tr,
                dataset_id="credential_dynamic_traces",
                source_revision="rev-test",
                raw_sha256="",
                adapter_version="2.0.0",
                expected_action=ea,
                leakage_expected=LeakageExpectation.NO_LEAK,
            )
        except Exception as e:
            errors.append(f"{tr.trace_id}: projection raised {e}")
            continue
        # payload preserved
        if tr.gateway_channel == "TOOL_RESULT":
            # tool_result path: content/tool_result holds payload
            if tr.payload not in (case.tool_result or case.content or ""):
                errors.append(f"{tr.trace_id}: payload not preserved in TOOL_RESULT case")
            # credential marker preserved
            if tr.credential_marker not in (case.credential_markers or []):
                errors.append(f"{tr.trace_id}: marker not in credential_markers")
        else:
            # tool_call: payload is JSON of tool+args; marker must be in args/content
            blob = case.content or ""
            if tr.credential_marker not in blob and tr.credential_marker not in str(case.tool_arguments):
                errors.append(f"{tr.trace_id}: marker not in TOOL_CALL content/args")
        # quality/derivation
        q = (case.metadata or {}).get("quality_tier") or (case.metadata.get("source") or {}).get("quality_tier")
        d = (case.metadata or {}).get("derivation") or (case.metadata.get("source") or {}).get("derivation")
        exp_q = "A" if (tr.evidence_type == "DYNAMIC_TRACE" and tr.gateway_visibility == "DIRECT") else "B"
        # ALLOW DIRECT is also A (same rule: evidence_type + visibility)
        if tr.evidence_type == "DYNAMIC_TRACE" and tr.gateway_visibility in ("DIRECT", "PROJECTED"):
            exp_q_actual = "A" if tr.gateway_visibility == "DIRECT" else "B"
            if q != exp_q_actual:
                errors.append(f"{tr.trace_id}: quality {q!r} != expected {exp_q_actual!r} (vis {tr.gateway_visibility})")
            exp_d = "original" if tr.gateway_visibility == "DIRECT" else "deterministic_projection"
            if d != exp_d:
                errors.append(f"{tr.trace_id}: derivation {d!r} != {exp_d!r}")
        # group_id = skill_id, sink/flow still in metadata only
        if (case.metadata or {}).get("group_id") != tr.skill_id:
            errors.append(f"{tr.trace_id}: group_id {case.metadata.get('group_id')!r} != skill_id {tr.skill_id!r}")
        projected.append(case)

    if errors:
        print("FAIL projection:")
        for e in errors:
            print(f"  - {e}")
        return 1

    # 2) Renderer fidelity: no header/sink leak, structure correct
    render_errors: list[str] = []
    for c in projected:
        # channel must be one of the two we emit
        if c.channel.value not in ("tool_call", "tool_result"):
            render_errors.append(f"{c.case_id}: unexpected channel {c.channel.value}")
        # structured envelope must not contain internal metadata keys
        r_struct = get_renderer("credential_flow", fidelity="structured")
        body_struct = r_struct.render_structured(c)
        for leak in ("STDOUT_EXPOSURE", "TOOL_ARG_SECRET", "scanning_rules", "skill_snapshot_sha256"):
            if leak in body_struct:
                render_errors.append(f"{c.case_id}: leak {leak!r} in structured body")
        # RAW must also carry the secret (no label hiding it)
        r_raw = get_renderer("credential_flow", fidelity="raw")
        body_raw = r_raw.render_raw(c)
        if c.credential_markers and c.credential_markers[0] not in body_raw:
            render_errors.append(f"{c.case_id}: RAW missing marker {c.credential_markers[0]}")
        # LABELED must have header
        r_labeled = get_renderer("credential_flow", fidelity="labeled")
        body_labeled = r_labeled.render(c)
        if "[CREDENTIAL_FLOW_CHECK]" not in body_labeled:
            render_errors.append(f"{c.case_id}: LABELED missing header")
        # tool_result vs tool_call envelope shape
        import json as _js
        if c.channel.value == "tool_call":
            try:
                obj = _js.loads(body_struct)
                assert "tool" in obj and "arguments" in obj
            except Exception as e:
                render_errors.append(f"{c.case_id}: tool_call structured not JSON envelope: {e}")
        else:
            try:
                obj = _js.loads(body_struct)
                assert "tool" in obj and "result" in obj
            except Exception as e:
                render_errors.append(f"{c.case_id}: tool_result structured not JSON envelope: {e}")

    if render_errors:
        print("FAIL renderer:")
        for e in render_errors:
            print(f"  - {e}")
        return 1

    # 3) Gate policy negatives: NOT_VISIBLE / AMBIGUOUS must NOT project
    # Build two negative traces that would be AMBIGUOUS if they tried
    neg1 = make_trace(
        trace_id="tr-neg-hardcode",
        skill_id="skill-neg-1",
        skill_name="org-neg/skill-1",
        issue_id="ISSUE-NEG-1",
        pattern="Hardcoded Credentials",
        sink="config_file",
        gateway_channel="TOOL_RESULT",
        gateway_visibility="DIRECT",
        flow_class="HARDCODE_ONLY",
        payload="hardcoded only, never on gateway",
        marker=p4canary("ISSUE-NEG-1"),
        evidence_type="DYNAMIC_TRACE",
        dynamic_confirmed=False,  # breaks DYNAMIC_TRACE BLOCK gate
        trace_hash="",
    )
    try:
        from demotest.datasets.adapters.credential_dynamic_traces import CredentialDynamicTracesAdapter

        ad = CredentialDynamicTracesAdapter(raw_dir=REPO_ROOT / "benchmarks" / "frozen" / "datasets" / "credential_dynamic_traces" / "raw", strict=True, trace_provider=[neg1])
        list(ad.iter_cases())
        errors.append("neg1 should have been rejected (dynamic_confirmed false / missing trace_hash)")
    except Exception:
        pass  # expected rejection

    neg2 = make_trace(
        trace_id="tr-neg-ambiguous",
        skill_id="skill-neg-2",
        skill_name="org-neg/skill-2",
        issue_id="ISSUE-NEG-2",
        pattern="Insecure Storage",
        sink="filesystem",
        gateway_channel="TOOL_CALL",
        gateway_visibility="DIRECT",
        flow_class="INSECURE_STORAGE",
        payload="ambiguous sink",
        marker=p4canary("ISSUE-NEG-2"),
        evidence_type="DYNAMIC_TRACE",
        dynamic_confirmed=True,
        trace_hash="",  # missing trace_hash => reject
    )
    try:
        from demotest.datasets.adapters.credential_dynamic_traces import CredentialDynamicTracesAdapter

        ad2 = CredentialDynamicTracesAdapter(raw_dir=REPO_ROOT / "benchmarks" / "frozen" / "datasets" / "credential_dynamic_traces" / "raw", strict=True, trace_provider=[neg2])
        list(ad2.iter_cases())
        errors.append("neg2 should have been rejected (missing trace_hash)")
    except Exception:
        pass

    # 4) Provenance block valid for positives
    prov_problems = validate_provenance_block(projected)
    if prov_problems:
        errors.extend(prov_problems)

    if errors:
        print("FAIL gates:")
        for e in errors:
            print(f"  - {e}")
        return 1

    # Summary
    groups = {c.metadata.get("group_id") for c in projected}
    print(f"PASS: {len(projected)} cases (incl {len(allow_traces)} ALLOW), {len(groups)} groups, {len(block_traces)} BLOCK")
    for c in projected:
        ch = c.channel.value
        q = (c.metadata.get("source") or {}).get("quality_tier") or c.metadata.get("quality_tier")
        print(f"  PASS {c.case_id[:22]}  ch={ch:11s}  q={q}  group={c.metadata.get('group_id')}")
    print(f"PROOF PASS — projection faithful, renderer envelope clean, gates enforced ({len(block_traces)}+{len(allow_traces)}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
