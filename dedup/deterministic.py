"""Deterministic dedup: exact (host, CVE) grouping first, then exact
(host, port, normalized_title) grouping for CVE-less findings. Both passes union
matched findings into groups via a UnionFind; finalize_groups() (called after the
fuzzy + LLM passes have had a chance to add more unions) picks one canonical
finding per group and marks the rest as duplicates.
"""
from __future__ import annotations

import hashlib
import re

from ingest.schema import Finding

_SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "informational": 1}

# Priority order for which method gets recorded on a duplicate when multiple edges
# connect it into its group — deterministic methods are the most confident/explainable.
_METHOD_PRIORITY = ["exact_cve_host", "exact_title_host_port", "fuzzy", "llm_semantic"]


class UnionFind:
    def __init__(self, n: int):
        self.parent = list(range(n))

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def normalize_title(title: str) -> str:
    cleaned = re.sub(r"[^a-z0-9\s]", "", title.lower())
    return re.sub(r"\s+", " ", cleaned).strip()


def annotate_normalized_titles(findings: list[Finding]) -> None:
    for f in findings:
        f.normalized_title = normalize_title(f.title)


def group_by_cve_host(findings: list[Finding], uf: UnionFind,
                       edge_method: dict[frozenset, str]) -> None:
    key_to_indices: dict[tuple[str, str], list[int]] = {}
    for i, f in enumerate(findings):
        for cve in f.cve_ids:
            key_to_indices.setdefault((f.host, cve), []).append(i)

    for indices in key_to_indices.values():
        if len(indices) < 2:
            continue
        base = indices[0]
        for other in indices[1:]:
            uf.union(base, other)
            edge_method[frozenset((base, other))] = "exact_cve_host"


def group_by_title_host_port(findings: list[Finding], uf: UnionFind,
                              edge_method: dict[frozenset, str]) -> None:
    key_to_indices: dict[tuple, list[int]] = {}
    for i, f in enumerate(findings):
        if f.cve_ids:
            continue  # already eligible for CVE-based grouping above
        key = (f.host, f.port, f.normalized_title)
        key_to_indices.setdefault(key, []).append(i)

    for indices in key_to_indices.values():
        if len(indices) < 2:
            continue
        base = indices[0]
        for other in indices[1:]:
            uf.union(base, other)
            edge_method[frozenset((base, other))] = "exact_title_host_port"


def _canonical_score(f: Finding) -> tuple:
    return (
        bool(f.cve_ids),
        _SEVERITY_RANK.get(f.scanner_severity.lower(), 0),
        len(f.description or ""),
        len(f.raw_evidence or {}),
    )


def compute_dedup_key(canonical: Finding) -> str:
    """Stable hash used both as the merge identity and as a GitHub label for
    ticket idempotency — same (host, primary signal) always yields the same key."""
    primary = sorted(canonical.cve_ids)[0] if canonical.cve_ids else canonical.normalized_title
    raw = f"{canonical.host}|{primary}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def finalize_groups(findings: list[Finding], uf: UnionFind,
                     edge_method: dict[frozenset, str]) -> None:
    groups: dict[int, list[int]] = {}
    for i in range(len(findings)):
        groups.setdefault(uf.find(i), []).append(i)

    for indices in groups.values():
        canonical_idx = max(indices, key=lambda i: _canonical_score(findings[i]))
        canonical = findings[canonical_idx]
        canonical.contributing_scanners = sorted({findings[i].source_scanner for i in indices})
        canonical.dedup_key = compute_dedup_key(canonical)

        for i in indices:
            if i == canonical_idx:
                continue
            member = findings[i]
            member.is_duplicate = True
            member.duplicate_of = canonical.finding_id
            member_methods = [v for k, v in edge_method.items() if i in k]
            member.dedup_method = (min(member_methods, key=_METHOD_PRIORITY.index)
                                    if member_methods else None)
