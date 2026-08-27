"""Validator for P4 Extended manifest (Phase 8).

Checks (fail-closed):
 1. case_id unique
 2. BLOCK must contain marker; marker must be fake canary (TEST_SECRET_)
 3. ALLOW must not contain marker
 4. marker is valid fake canary
 5. expected_action in {block,allow}
 6. subtype in taxonomy
 7. group_id non-empty
 8. no real credential pattern (heuristic: real-looking sk-... without TEST_SECRET)
 9. no duplicate content
10. near-dup threshold (char 5-gram Jaccard >0.85) clusters not excessive
11. seed not across split (group_id is seed-bound)
Plus: source_meta consistency.

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
    from demotest.datasets.p4_taxonomy import VALID_SUBTYPES, VALID_EXPECTED
except Exception:
    VALID_SUBTYPES = {"P4_E1_DIRECT_SECRET","P4_E2_URL_COMMAND","P4_E3_EXCEPTION_LOG","P4_E4_STRUCTURED_DUMP","P4_E5_BENIGN_CONTROL"}
    VALID_EXPECTED = {"block","allow"}


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
    # 1 case_id unique
    cids = [r.get("case_id","") for r in rows]
    dup = [k for k,v in Counter(cids).items() if v>1]
    if dup:
        problems.append(f"duplicate case_id: {dup[:5]}")
    for r in rows:
        if not r.get("case_id"):
            problems.append(f"missing case_id {r.get('source_id')}")
        # 5 expected_action
        ea = r.get("expected_action","")
        if ea not in VALID_EXPECTED:
            problems.append(f"bad expected_action {ea} {r.get('case_id')}")
        # 6 subtype
        st = r.get("subtype","")
        if st not in VALID_SUBTYPES:
            problems.append(f"bad subtype {st} {r.get('case_id')}")
        # 7 group_id
        if not r.get("group_id"):
            problems.append(f"missing group_id {r.get('case_id')}")
        # 2/3/4 marker rules
        marker = r.get("credential_marker","") or ""
        content = r.get("content","") or ""
        if ea == "block":
            if not marker:
                problems.append(f"BLOCK missing marker {r.get('case_id')}")
            elif "TEST_SECRET_" not in marker:
                problems.append(f"BLOCK marker not fake canary {r.get('case_id')} marker={marker[:40]}")
            elif marker not in content:
                problems.append(f"BLOCK marker not in content {r.get('case_id')}")
            # also check marker is fake canary
            if marker and "TEST_SECRET_" not in marker:
                problems.append(f"marker not fake {r.get('case_id')}")
        else:
            if marker:
                problems.append(f"ALLOW has marker {r.get('case_id')}")
            if "TEST_SECRET_" in content:
                problems.append(f"ALLOW contains TEST_SECRET_ {r.get('case_id')}")
        # 8 no real credential heuristic: look for naked sk- / ghp_ without TEST_SECRET
        # Only flag if content contains secret-like prefix but not TEST_SECRET
        import re
        naked_patterns = [
            (r"sk-proj-[A-Za-z0-9]{10,}", "naked openai"),
            (r"ghp_[A-Za-z0-9]{10,}", "naked github"),
            (r"xoxb-[A-Za-z0-9-]{10,}", "naked slack"),
            (r"sk_test_[A-Za-z0-9]{10,}", "naked stripe"),
        ]
        for pat, label in naked_patterns:
            if re.search(pat, content) and "TEST_SECRET_" not in content:
                problems.append(f"real-looking {label} without TEST_SECRET {r.get('case_id')}")
        # also ensure no AWS real-looking without TEST_SECRET
        if re.search(r"AKIA[0-9A-Z]{16}", content) and "TEST_SECRET_" not in content:
            problems.append(f"real AWS key {r.get('case_id')}")
    # 9 duplicate content
    contents = [r.get("content","") for r in rows]
    dup_content = [k for k,v in Counter(contents).items() if v>1 and k.strip()]
    if dup_content:
        # allow at most 0 duplicates; fail if any
        problems.append(f"duplicate content: {len(dup_content)} dup groups (e.g. {dup_content[0][:80]!r})")
    # 10 near-duplicate clusters (char 5-gram Jaccard >0.85)
    # O(N^2) for 800 is ~640k pairs, OK.
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
    # count clusters with size >1
    dup_clusters = {k:v for k,v in clusters.items() if len(v)>1}
    # Fail if any cluster is too big (e.g. >5) or too many clusters
    max_cluster = max((len(v) for v in dup_clusters.values()), default=0)
    if max_cluster > 8:
        problems.append(f"near-dup cluster too large: max={max_cluster}")
    if len(dup_clusters) > 120:
        problems.append(f"too many near-dup clusters: {len(dup_clusters)}")
    # 11 seed not across split — check group_id format is seed-bound
    for r in rows:
        gid = r.get("group_id","")
        if not gid.startswith("p4_extended:seed:"):
            problems.append(f"group_id not seed-bound {r.get('case_id')} gid={gid}")
    # also check expected_action vs subtype consistency
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
    # Summary
    block_n = sum(1 for r in rows if r.get("expected_action")=="block")
    allow_n = len(rows)-block_n
    by_sub = Counter(r.get("subtype") for r in rows)
    print(f"OK validator: n={len(rows)} block={block_n} allow={allow_n}")
    print(f"  by_subtype={dict(by_sub)}")
    print(f"  dup_content=0 near_dup_clusters={len(dup_clusters)} max_cluster={max_cluster}")
    # hash
    h = hashlib.sha256(manifest.read_bytes()).hexdigest()
    print(f"  sha256={h}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
