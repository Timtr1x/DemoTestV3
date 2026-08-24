"""LLMail label audit (Phase 1.5 step 1) — official {attack_attempt, reason} -> BLOCK/ALLOW.

Streams the pinned raw labelled_unique_submissions files through the SAME
adapter code path used by dataset prepare (_iter_prompt_value_pairs +
_is_attack), censuses every raw label value, and exports stratified samples
for human review to cache/exports/llmail_label_audit.json.

Read-only: never writes raw/, normalized/, or any benchmark artifact.
"""
from __future__ import annotations

import json
import random
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from demotest.datasets.adapters.llmail import (  # noqa: E402
    _is_attack,
    _iter_prompt_value_pairs,
    _phase_of,
    _prompt_sha,
    LLMailAdapter,
)

SEED = 42
OUT = ROOT / "cache" / "exports" / "llmail_label_audit.json"


class Reservoir:
    def __init__(self, k: int, seed: int = SEED) -> None:
        self.k = k
        self.n = 0
        self.items: list[dict] = []
        self._rng = random.Random(seed)

    def add(self, item: dict) -> None:
        self.n += 1
        if len(self.items) < self.k:
            self.items.append(item)
        else:
            j = self._rng.randrange(self.n)
            if j < self.k:
                self.items[j] = item


CANONICAL_TRUE = {"true", "1", "1.0", "yes"}
CANONICAL_FALSE = {"false", "0", "0.0", "no", "unclear", ""}


def bucket_of(raw_label) -> str:
    """Where does this raw attack_attempt value fall in _is_attack's logic."""
    if raw_label is None:
        return "null"
    s = str(raw_label).strip()
    low = s.lower()
    if low in CANONICAL_TRUE:
        return "canonical_true"
    if low in CANONICAL_FALSE:
        return "canonical_false"
    if "true" in low:
        return "list_contains_true"
    return "unrecognized_falsy"


def main() -> int:
    ad = LLMailAdapter()
    value_census: Counter = Counter()
    reason_census: Counter = Counter()
    per_phase_action: Counter = Counter()
    res_attack = {"phase1": Reservoir(30), "phase2": Reservoir(30)}
    res_api = Reservoir(25)
    res_judge = Reservoir(25)
    res_ambig = Reservoir(30)
    seen_source_ids: set[str] = set()
    non_string_keys = 0

    # normalized snapshot map + subset-consistency accumulators (must exist
    # BEFORE the stream so per-row checks can run inline)
    snap: dict[str, str] = {}
    norm_path = ROOT / "cache" / "datasets_v3" / "normalized" / "llmail" / "cases.jsonl"
    for line in norm_path.read_text(encoding="utf-8").splitlines():
        c = json.loads(line)
        snap[c["source_id"]] = c["expected_action"]
    mismatches: list[dict] = []
    snap_block_seen: set[str] = set()
    snap_allow_seen: set[str] = set()

    for fp in ad._attack_files():
        phase = _phase_of(str(fp))
        for prompt, labels in _iter_prompt_value_pairs(fp):
            if not isinstance(prompt, str) or not prompt.strip():
                if not isinstance(prompt, str):
                    non_string_keys += 1
                continue
            labels = labels if isinstance(labels, dict) else {}
            raw_label = labels.get("attack_attempt")
            reason = str(labels.get("reason") or "")
            is_att = _is_attack(raw_label)
            b = bucket_of(raw_label)
            value_census[repr(raw_label)] += 1
            reason_census[reason or "<missing>"] += 1
            per_phase_action[(phase, "block" if is_att else "skipped")] += 1

            raw_sha = _prompt_sha(prompt)
            source_id = f"llmail:{phase}:{raw_sha[:16]}"
            dup = source_id in seen_source_ids
            if not is_att or dup:
                continue
            seen_source_ids.add(source_id)
            sample = {
                "source_id": source_id,
                "prompt_sha256": raw_sha,
                "excerpt": prompt[:180],
                "raw_attack_attempt": raw_label if raw_label is None else str(raw_label),
                "bucket": b,
                "reason": reason,
                "mapped_action": "BLOCK",
            }
            res_attack[phase].add(sample)
            if b not in ("canonical_true",):
                res_ambig.add(sample)
            if reason == "api_triggered":
                res_api.add(sample)
            elif reason == "judge":
                res_judge.add(sample)
            # full-stream subset consistency: any snapshot case built from
            # this row must carry the SAME action the audit mapping gives.
            if source_id in snap:
                if snap[source_id] != "block":
                    mismatches.append({"source_id": source_id,
                                       "snapshot_action": snap[source_id],
                                       "audit_expected": "block"})
                snap_block_seen.add(source_id)

    # benign FP emails
    n_benign_rows = 0
    res_benign = Reservoir(30)
    for fp in ad._benign_files():
        data = json.loads(fp.read_text(encoding="utf-8"))
        prompts = data if isinstance(data, list) else list(data.keys())
        for prompt in prompts:
            if not isinstance(prompt, str) or not prompt.strip():
                continue
            n_benign_rows += 1
            raw_sha = _prompt_sha(prompt)
            sid = f"llmail:benign:{raw_sha[:16]}"
            res_benign.add({
                "source_id": sid,
                "prompt_sha256": raw_sha,
                "excerpt": prompt[:180],
                "raw_attack_attempt": None,
                "bucket": "benign_fp_file",
                "reason": "",
                "mapped_action": "ALLOW",
            })
            if sid in snap:
                if snap[sid] != "allow":
                    mismatches.append({"source_id": sid,
                                       "snapshot_action": snap[sid],
                                       "audit_expected": "allow"})
                snap_allow_seen.add(sid)

    # cross-check against the committed-normalized snapshot.
    # NOTE: prepare materializes a BOUNDED pool (llmail.yaml bounded_pool,
    # total_attack=3700) from the full raw attack pool via deterministic
    # hash-rank Top-K, so snapshot size << raw pool is BY DESIGN. What must
    # hold: every snapshot case resolves back to a real raw row with the SAME
    # expected_action, and no raw row maps to a different action in the
    # snapshot (subset consistency, not equality).
    def _check(sample: dict, expected: str) -> None:
        sid, act = sample["source_id"], snap.get(sample["source_id"])
        if act is None:
            return  # outside the materialized bounded pool -> fine
        if act != expected:
            mismatches.append({"source_id": sid, "snapshot_action": act,
                               "audit_expected": expected})
        (snap_block_seen if act == "block" else snap_allow_seen).add(sid)

    checked = len(res_attack["phase1"].items) + len(res_attack["phase2"].items) \
        + len(res_api.items) + len(res_judge.items) + len(res_ambig.items)
    for s in (res_attack["phase1"].items + res_attack["phase2"].items
              + res_api.items + res_judge.items + res_ambig.items):
        _check(s, "block")
    for s in res_benign.items:
        _check(s, "allow")

    snap_ids_block = {k for k, v in snap.items() if v == "block"}
    snap_ids_allow = {k for k, v in snap.items() if v == "allow"}
    unresolved_block = sorted(snap_ids_block - snap_block_seen)
    unresolved_allow = sorted(snap_ids_allow - snap_allow_seen)
    report = {
        "audit": "llmail_label_mapping_v1",
        "pinned_revision": ad._lock_revision(),
        "adapter_version": LLMailAdapter.adapter_version,
        "mapping_rule": {
            "canonical_true -> BLOCK": sorted(CANONICAL_TRUE),
            "canonical_false -> skipped": sorted(CANONICAL_FALSE),
            "list_contains_true -> BLOCK (per-objective lists)": True,
            "unrecognized -> skipped (conservative)": True,
        },
        "bounded_pool_note": (
            "raw attack pool is much larger than the materialized snapshot by "
            "design (llmail.yaml bounded_pool Top-K hash-rank selection); "
            "audit checks subset consistency, not pool equality"
        ),
        "totals": {
            "attack_rows_scanned_phase1": per_phase_action[("phase1", "block")]
                                         + per_phase_action[("phase1", "skipped")],
            "attack_rows_scanned_phase2": per_phase_action[("phase2", "block")]
                                         + per_phase_action[("phase2", "skipped")],
            "mapped_block_unique_source_ids": len(seen_source_ids),
            "benign_fp_rows": n_benign_rows,
            "non_string_prompt_keys_skipped": non_string_keys,
        },
        "per_phase_action": {f"{p}|{a}": n for (p, a), n in sorted(per_phase_action.items())},
        "label_value_census_top": dict(value_census.most_common(40)),
        "distinct_label_values": len(value_census),
        "reason_census": dict(reason_census),
        "samples": {
            "phase1_attack": res_attack["phase1"].items,
            "phase2_attack": res_attack["phase2"].items,
            "api_triggered": res_api.items,
            "judge": res_judge.items,
            "ambiguous_or_list_labels": res_ambig.items,
            "benign_fp": res_benign.items,
        },
        "cross_check_vs_normalized_snapshot": {
            "sampled_cases_checked": checked,
            "mismatches": mismatches,
            "snapshot_block_total": len(snap_ids_block),
            "snapshot_allow_total": len(snap_ids_allow),
            "snapshot_block_unresolved_to_raw": unresolved_block,
            "snapshot_allow_unresolved_to_raw": unresolved_allow,
        },
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=1, ensure_ascii=False), encoding="utf-8")

    print(f"wrote {OUT}")
    print(f"mapped BLOCK unique ids: {len(seen_source_ids)}  "
          f"(snapshot block={report['cross_check_vs_normalized_snapshot']['snapshot_block_total']})")
    print(f"benign rows: {n_benign_rows} "
          f"(snapshot allow={report['cross_check_vs_normalized_snapshot']['snapshot_allow_total']})")
    print(f"distinct label values: {len(value_census)}; census top: "
          f"{dict(value_census.most_common(8))}")
    print(f"reasons: {dict(reason_census)}")
    print(f"samples checked vs snapshot: {checked}, mismatches: {len(mismatches)}")
    print(f"snapshot block unresolved to raw rows: {len(unresolved_block)}; "
          f"allow unresolved: {len(unresolved_allow)}")
    amb = len(res_ambig.items)
    print(f"ambiguous/list-label samples captured: {amb}")
    ok = (len(mismatches) == 0 and not unresolved_block and not unresolved_allow
          and n_benign_rows >= len(snap_ids_allow))
    print("VERDICT:", "PASS" if ok else "REVIEW NEEDED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
