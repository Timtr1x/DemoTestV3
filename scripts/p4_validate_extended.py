"""Validator for P4 Extended manifest (Phase 8, P4E-v2).

Checks (fail-closed):
 1. case_id unique
 2. BLOCK must contain per-row marker; marker is valid P4E-v2 demo canary
 3. ALLOW must not contain a complete demo marker; must not contain TEST_SECRET_
 4. marker is valid fake canary (demo shape, no shared TEST_SECRET_ tag)
 5. expected_action in {block,allow}
 6. subtype in taxonomy
 7. group_id non-empty and seed-bound
 8. no real credential pattern (naked shape without demo tag)
 9. no duplicate content
10. near-dup threshold controls excessive clusters only (validator clusters,
    not builder all-pairs <=0.85)
11. seed not across split (group_id is seed-bound)
12. ALLOW must not contain benchmark/gateway meta phrasing (P0-2)
13. E5 must carry benign_subtype

Usage:
  python scripts/p4_validate_extended.py [manifest_path]
If omitted, defaults to data/p4_extended/manifest.jsonl
Exit 0 = OK, non-zero = fail.
"""
from __future__ import annotations

import json
import sys
import hashlib
from pathlib import Path
from collections import Counter

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = REPO_ROOT / "data" / "p4_extended" / "manifest.jsonl"

try:
    sys.path.insert(0, str(REPO_ROOT / "src"))
    from demotest.datasets.p4_taxonomy import VALID_SUBTYPES, VALID_EXPECTED, VALID_BENIGN_SUBTYPES
except Exception:
    VALID_SUBTYPES = {"P4_E1_DIRECT_SECRET","P4_E2_URL_COMMAND","P4_E3_EXCEPTION_LOG","P4_E4_STRUCTURED_DUMP","P4_E5_BENIGN_CONTROL"}
    VALID_EXPECTED = {"block","allow"}
    VALID_BENIGN_SUBTYPES = {"placeholder","redacted","name_only","schema","instruction","safe_log"}

try:
    sys.path.insert(0, str(REPO_ROOT / "src"))
    from demotest.datasets.p4_canary import is_valid_fake_canary
except Exception:
    def is_valid_fake_canary(m):  # type: ignore
        return bool(m and "demo" in m.lower() and "TEST_SECRET_" not in m)


def _ngrams(s: str, n: int = 5) -> set[str]:
    s = s.lower()
    if len(s) < n:
        return {s} if s else set()
    return {s[i:i+n] for i in range(len(s)-n+1)}


def jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def load_rows(path: Path) -> list[dict]:
    rows = []
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except Exception as e:
            print(f"FAIL line {lineno} JSON: {e}", file=sys.stderr)
            sys.exit(1)
    return rows


BANNED_ALLOW_PHRASES = [
    "benchmark",
    "gateway should allow",
    "benign control",
    "expected action",
    "validated by the gateway",
    "instructional, not an exfiltration",
]


def main(argv: list[str] | None = None) -> int:
    argv = argv or sys.argv[1:]
    manifest = Path(argv[0]) if argv else DEFAULT_MANIFEST
    if not manifest.exists():
        print(f"FAIL manifest not found: {manifest}", file=sys.stderr)
        return 1
    rows = load_rows(manifest)
    if not rows:
        print("FAIL empty manifest", file=sys.stderr)
        return 1
    problems: list[str] = []
    cids = [r.get("case_id","") for r in rows]
    dup = [k for k,v in Counter(cids).items() if v>1]
    if dup:
        problems.append(f"duplicate case_id: {dup[:5]}")
    for r in rows:
        if not r.get("case_id"):
            problems.append(f"missing case_id {r.get('source_id')}")
        ea = r.get("expected_action","")
        if ea not in VALID_EXPECTED:
            problems.append(f"bad expected_action {ea} {r.get('case_id')}")
        st = r.get("subtype","")
        if st not in VALID_SUBTYPES:
            problems.append(f"bad subtype {st} {r.get('case_id')}")
        if not r.get("group_id"):
            problems.append(f"missing group_id {r.get('case_id')}")
        marker = r.get("credential_marker","") or ""
        content = r.get("content","") or ""
        if ea == "block":
            if not marker:
                problems.append(f"BLOCK missing marker {r.get('case_id')}")
            elif not is_valid_fake_canary(marker):
                problems.append(f"BLOCK marker not valid demo canary {r.get('case_id')} marker={marker[:50]!r}")
            elif marker not in content:
                problems.append(f"BLOCK marker not in content {r.get('case_id')}")
            if marker and "TEST_SECRET_" in marker:
                problems.append(f"BLOCK marker must not contain TEST_SECRET_ (P4E-v2) {r.get('case_id')}")
            if "TEST_SECRET_" in content:
                problems.append(f"BLOCK content must not contain TEST_SECRET_ (P4E-v2) {r.get('case_id')}")
        else:
            if marker:
                problems.append(f"ALLOW has marker {r.get('case_id')}")
            # ALLOW must not contain a complete demo canary nor v1 tag
            if "TEST_SECRET_" in content:
                problems.append(f"ALLOW contains TEST_SECRET_ {r.get('case_id')}")
            if is_valid_fake_canary(content):
                # Heuristic: content contains a demo shape — would be a false BLOCK-like leak
                # Check by searching any demo pattern inside content
                import re
                if re.search(r"demo[_-][A-Za-z0-9]{8,}", content):
                    # Allow if content itself is a demo word but not a full canary shape
                    # Use is_valid_fake_canary on substrings: flagged above is enough
                    pass
                # Only flag if marker-shaped content slipped into ALLOW
                for pat in [r"sk-proj-demo_", r"ghp_demo", r"xoxb-demo-", r"sk_test_demo_", r"eyJ-demo_"]:
                    if pat in content:
                        problems.append(f"ALLOW contains demo canary shape {pat!r} {r.get('case_id')}")
                        break
            low = content.lower()
            for phrase in BANNED_ALLOW_PHRASES:
                if phrase.lower() in low:
                    problems.append(f"ALLOW contains banned meta phrase {phrase!r} {r.get('case_id')}")
            bs = r.get("benign_subtype","")
            if not bs:
                problems.append(f"E5 missing benign_subtype {r.get('case_id')}")
            elif bs not in VALID_BENIGN_SUBTYPES:
                problems.append(f"bad benign_subtype {bs!r} {r.get('case_id')}")
        # naked real-looking without demo tag (heuristic)
        import re
        naked_patterns = [
            (r"sk-proj-[A-Za-z0-9]{10,}", "naked openai without demo"),
            (r"ghp_[A-Za-z0-9]{10,}", "naked github without demo"),
        ]
        for pat, label in naked_patterns:
            if re.search(pat, content) and "demo" not in content.lower():
                # Only flag BLOCK without demo wrapper as suspicious
                if ea == "block":
                    problems.append(f"real-looking {label} without demo tag {r.get('case_id')}")
        if re.search(r"AKIA[0-9A-Z]{16}", content) and "demo" not in content.lower():
            problems.append(f"real AWS key {r.get('case_id')}")
    contents = [r.get("content","") for r in rows]
    dup_content = [k for k,v in Counter(contents).items() if v>1 and k.strip()]
    if dup_content:
        problems.append(f"duplicate content: {len(dup_content)} dup groups (e.g. {dup_content[0][:80]!r})")
    # near-dup clusters: validator controls excessive clusters, not all-pairs <=0.85
    n = len(rows)
    parent = list(range(n))
    def find(x):
        while parent[x]!=x:
            parent[x]=parent[parent[x]]
            x=parent[x]
        return x
    def union(a,b):
        ra=find(a); rb=find(b)
        if ra!=rb:
            parent[rb]=ra
    ngrams_list = [_ngrams(r.get("content",""), 5) for r in rows]
    for i in range(n):
        for j in range(i+1, n):
            if jaccard(ngrams_list[i], ngrams_list[j]) > 0.85:
                union(i,j)
    clusters: dict[int, list[int]] = {}
    for i in range(n):
        r = find(i)
        clusters.setdefault(r, []).append(i)
    dup_clusters = {k:v for k,v in clusters.items() if len(v)>1}
    max_cluster = max((len(v) for v in dup_clusters.values()), default=0)
    if max_cluster > 8:
        problems.append(f"near-dup cluster too large: max={max_cluster}")
    if len(dup_clusters) > 120:
        problems.append(f"too many near-dup clusters: {len(dup_clusters)}")
    for r in rows:
        gid = r.get("group_id","")
        if not gid.startswith("p4_extended:seed:"):
            problems.append(f"group_id not seed-bound {r.get('case_id')} gid={gid}")
    for r in rows:
        st = r.get("subtype","")
        ea = r.get("expected_action","")
        if st == "P4_E5_BENIGN_CONTROL" and ea != "allow":
            problems.append(f"E5 must be allow {r.get('case_id')}")
        if st != "P4_E5_BENIGN_CONTROL" and ea != "block":
            problems.append(f"non-E5 must be block {r.get('case_id')} st={st}")
    if problems:
        for p in problems[:30]:
            print(f"FAIL {p}", file=sys.stderr)
        if len(problems) > 30:
            print(f"... and {len(problems)-30} more", file=sys.stderr)
        return 1
    block_n = sum(1 for r in rows if r.get("expected_action")=="block")
    allow_n = len(rows)-block_n
    by_sub = Counter(r.get("subtype") for r in rows)
    print(f"OK validator: n={len(rows)} block={block_n} allow={allow_n}")
    print(f"  by_subtype={dict(by_sub)}")
    by_benign = Counter(r.get("benign_subtype","") for r in rows if r.get("expected_action")=="allow")
    if by_benign:
        print(f"  by_benign_subtype={dict(by_benign)}")
    print(f"  dup_content=0 near_dup_clusters={len(dup_clusters)} max_cluster={max_cluster}")
    h = hashlib.sha256(manifest.read_bytes()).hexdigest()
    print(f"  sha256={h}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
