"""Fuzzy fallback dedup pass for findings the deterministic pass couldn't group
(no shared CVE, no exact title match) — e.g. a ZAP alert and a Nuclei template
describing the same missing-header issue in different words.
"""
from __future__ import annotations

from itertools import combinations

from rapidfuzz import fuzz

from dedup.deterministic import UnionFind
from ingest.schema import Finding


def find_candidates(findings: list[Finding], uf: UnionFind, edge_method: dict[frozenset, str],
                     auto_merge_threshold: int, candidate_threshold: int) -> list[tuple[int, int, float]]:
    """Compares findings within the same host only (bucketing avoids O(n^2) over the
    whole dataset). Scores >= auto_merge_threshold are unioned immediately as
    'fuzzy'. Scores in [candidate_threshold, auto_merge_threshold) are returned as
    candidates for the LLM semantic pass rather than merged outright, to avoid
    false collapses on borderline text similarity."""
    candidates: list[tuple[int, int, float]] = []

    by_host: dict[str, list[int]] = {}
    for i, f in enumerate(findings):
        by_host.setdefault(f.host, []).append(i)

    for indices in by_host.values():
        for i, j in combinations(indices, 2):
            if uf.find(i) == uf.find(j):
                continue  # already merged by the deterministic pass

            fi, fj = findings[i], findings[j]
            text_i = f"{fi.title} {fi.description or ''}"
            text_j = f"{fj.title} {fj.description or ''}"
            score = fuzz.token_sort_ratio(text_i, text_j)

            if score >= auto_merge_threshold:
                uf.union(i, j)
                edge_method[frozenset((i, j))] = "fuzzy"
            elif score >= candidate_threshold:
                candidates.append((i, j, score))

    return candidates
