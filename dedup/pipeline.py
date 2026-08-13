"""Orchestrates the full dedup phase: deterministic grouping -> fuzzy fallback ->
LLM semantic pass -> canonical selection -> suppression -> metrics.
"""
from __future__ import annotations

import json

from common.config import scoring_config
from common.paths import deduped_path, llm_dedup_log_path, normalized_path
from dedup.deterministic import (UnionFind, annotate_normalized_titles, finalize_groups,
                                  group_by_cve_host, group_by_title_host_port)
from dedup.fuzzy import find_candidates
from dedup.llm_semantic import resolve_candidates
from dedup.metrics import compute_metrics
from dedup.suppress import apply_suppressions
from ingest.schema import Finding, load_findings, save_findings


def run_dedup_phase(scan_id: str) -> tuple[list[Finding], dict]:
    findings = load_findings(normalized_path(scan_id))
    annotate_normalized_titles(findings)

    uf = UnionFind(len(findings))
    edge_method: dict[frozenset, str] = {}

    group_by_cve_host(findings, uf, edge_method)
    group_by_title_host_port(findings, uf, edge_method)

    dedup_cfg = scoring_config()["dedup"]
    candidates = find_candidates(findings, uf, edge_method,
                                  dedup_cfg["fuzzy_auto_merge_threshold"],
                                  dedup_cfg["fuzzy_candidate_threshold"])

    llm_log: list[dict] = []
    resolve_candidates(findings, candidates, uf, edge_method, llm_log)

    finalize_groups(findings, uf, edge_method)
    apply_suppressions(findings)
    metrics = compute_metrics(findings, scan_id)

    save_findings(findings, deduped_path(scan_id))

    log_path = llm_dedup_log_path(scan_id)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "w") as f:
        json.dump(llm_log, f, indent=2)

    return findings, metrics


if __name__ == "__main__":
    import click

    @click.command()
    @click.option("--scan-id", required=True)
    def main(scan_id):
        findings, metrics = run_dedup_phase(scan_id)
        print(json.dumps(metrics, indent=2))

    main()
