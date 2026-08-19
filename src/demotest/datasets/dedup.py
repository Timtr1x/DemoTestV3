"""Three-level de-duplication for normalized cases (guide §12-§16).

Level 1 — Exact hash (raw_sha256): identical payloads collapse to one case,
          the kept case records ``duplicate_count``. Never silently deletes;
          the *kept* case is the first-seen.

Level 2 — Normalized exact hash: a conservative normalization that does NOT
          change attack semantics — Unicode NFC, CRLF->LF, strip BOM, rstrip.
          Lowercasing / punctuation stripping / HTML stripping are FORBIDDEN
          (guide §14) because they can themselves be the attack.

Level 3 — Near-duplicate clustering: character n-gram Jaccard similarity groups
          same-family attacks. The result is a ``near_dup_cluster_id`` stored in
          metadata — used by the sampler to cap a family's share and by splitting
          to keep a family in one split. Payloads are NEVER auto-rewritten
          (guide §15).

The module operates on ``SecurityCase`` lists and returns *new* lists with
provenance/metadata updated. It never mutates inputs (cases are frozen).
"""
from __future__ import annotations

import hashlib
import unicodedata
from dataclasses import dataclass
from typing import Any

from ..core.models import SecurityCase


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


# --------------------------------------------------------------------------
# Level 2 normalization (guide §14)
# --------------------------------------------------------------------------
def normalize_text(text: str) -> str:
    """Conservative normalization that preserves attack semantics."""
    if not text:
        return ""
    # strip BOM
    if text.startswith("\ufeff"):
        text = text[1:]
    # Unicode NFC
    text = unicodedata.normalize("NFC", text)
    # CRLF / CR -> LF
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    # trailing whitespace per line + overall rstrip
    lines = [ln.rstrip() for ln in text.split("\n")]
    text = "\n".join(lines).rstrip()
    return text


# --------------------------------------------------------------------------
# Level 1 — exact raw hash
# --------------------------------------------------------------------------
@dataclass
class DedupReport:
    n_in: int
    n_kept: int
    n_exact_duplicates: int
    n_normalized_duplicates: int
    n_clusters: int


def _with_meta(case: SecurityCase, **updates: Any) -> SecurityCase:
    """Return a copy of ``case`` with fields merged into ``metadata`` (top-level
    case metadata, NOT the source provenance block). Used for duplicate_count
    and near_dup_cluster_id, which are quality metadata, not source lineage.
    """
    d = case.to_dict()
    meta = dict(d.get("metadata") or {})
    meta.update(updates)
    d["metadata"] = meta
    return SecurityCase.from_dict(d)


def exact_dedup(cases: list[SecurityCase]) -> tuple[list[SecurityCase], DedupReport]:
    """Level 1: collapse identical content (raw sha256 of ``content``).

    Recomputes the hash from ``content`` so dedup is robust to adapters that
    forget to set ``raw_sha256`` and identical across reruns.
    """
    seen: dict[str, int] = {}
    kept: list[SecurityCase] = []
    n_dup = 0
    for c in cases:
        raw = _sha(c.content)
        if raw in seen:
            seen[raw] += 1
            n_dup += 1
            continue
        seen[raw] = 1
        kept.append(c)
    # stamp duplicate_count onto the kept cases
    out: list[SecurityCase] = []
    for c in kept:
        raw = _sha(c.content)
        out.append(_with_meta(c, duplicate_count=seen[raw]) if seen[raw] > 1 else c)
    return out, DedupReport(
        n_in=len(cases),
        n_kept=len(out),
        n_exact_duplicates=n_dup,
        n_normalized_duplicates=0,
        n_clusters=0,
    )


# --------------------------------------------------------------------------
# Level 2 — normalized exact
# --------------------------------------------------------------------------
def normalized_dedup(cases: list[SecurityCase]) -> tuple[list[SecurityCase], DedupReport]:
    """Level 2: collapse on normalized content hash (conservative normalization).

    Always recomputes the normalized hash from ``content`` rather than trusting
    a stored provenance field, so dedup is robust to adapters that forget to set
    ``normalized_sha256`` and identical across reruns.
    """
    seen: dict[str, int] = {}
    kept: list[SecurityCase] = []
    n_dup = 0
    for c in cases:
        nsha = _sha(normalize_text(c.content))
        if nsha in seen:
            seen[nsha] += 1
            n_dup += 1
            continue
        seen[nsha] = 1
        kept.append(c)
    return kept, DedupReport(
        n_in=len(cases),
        n_kept=len(kept),
        n_exact_duplicates=0,
        n_normalized_duplicates=n_dup,
        n_clusters=0,
    )


# --------------------------------------------------------------------------
# Level 3 — near-duplicate clustering (char n-gram Jaccard)
# --------------------------------------------------------------------------
def _ngrams(text: str, n: int = 5) -> set[str]:
    t = normalize_text(text)
    if len(t) < n:
        return {t} if t else set()
    return {t[i : i + n] for i in range(len(t) - n + 1)}


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    inter = len(a & b)
    return inter / (len(a) | len(b))


def near_duplicate_clusters(
    cases: list[SecurityCase], *, n: int = 5, threshold: float = 0.85
) -> tuple[list[SecurityCase], DedupReport]:
    """Level 3: assign ``near_dup_cluster_id`` via single-link clustering.

    Cases within ``threshold`` Jaccard (char n-gram) join a cluster. The cluster
    id is a short hash of the first member's content. We use a simple union-find
    so the result is deterministic regardless of input order (clusters are
    canonicalized by sorted member source_id before id assignment).
    """
    n_in = len(cases)
    parent = list(range(n_in))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)

    grams = [_ngrams(c.content, n=n) for c in cases]
    for i in range(n_in):
        for j in range(i + 1, n_in):
            if _jaccard(grams[i], grams[j]) >= threshold:
                union(i, j)

    # group indices by root
    groups: dict[int, list[int]] = {}
    for i in range(n_in):
        groups.setdefault(find(i), []).append(i)

    # canonical cluster id: hash of sorted member source_ids in the cluster
    out = list(cases)
    cluster_ids: dict[int, str] = {}
    for root, members in groups.items():
        members_sorted = sorted(members, key=lambda i: cases[i].source_id)
        seed = "|".join(cases[i].source_id for i in members_sorted)
        cluster_ids[root] = "ndc-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:10]

    stamped: list[SecurityCase] = []
    for i, c in enumerate(out):
        root = find(i)
        cid = cluster_ids[root]
        if (c.metadata or {}).get("near_dup_cluster_id") == cid:
            stamped.append(c)
        else:
            stamped.append(_with_meta(c, near_dup_cluster_id=cid))
    return stamped, DedupReport(
        n_in=n_in,
        n_kept=n_in,
        n_exact_duplicates=0,
        n_normalized_duplicates=0,
        n_clusters=len(groups),
    )


# --------------------------------------------------------------------------
# Combined pipeline (guide §12 "at least three levels")
# --------------------------------------------------------------------------
def run_dedup(
    cases: list[SecurityCase],
    *,
    do_exact: bool = True,
    do_normalized: bool = True,
    do_near_duplicate: bool = True,
    near_n: int = 5,
    near_threshold: float = 0.85,
) -> tuple[list[SecurityCase], DedupReport]:
    """Run all three levels in order. Returns surviving cases + aggregate report."""
    n_in = len(cases)
    n_exact = 0
    n_norm = 0
    n_clusters = 0
    out = list(cases)
    if do_exact:
        out, r = exact_dedup(out)
        n_exact = r.n_exact_duplicates
    if do_normalized:
        out, r = normalized_dedup(out)
        n_norm = r.n_normalized_duplicates
    if do_near_duplicate:
        out, r = near_duplicate_clusters(out, n=near_n, threshold=near_threshold)
        n_clusters = r.n_clusters
    return out, DedupReport(
        n_in=n_in,
        n_kept=len(out),
        n_exact_duplicates=n_exact,
        n_normalized_duplicates=n_norm,
        n_clusters=n_clusters,
    )
