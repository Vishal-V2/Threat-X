"""Applies scoring + SLA/ownership to every actionable finding, ranks them, and
(if GEMINI_API_KEY is set) drafts an AI 'why this matters' summary for the
top-ranked findings. Writes data/processed/<scan_id>/final_scored.parquet — the
artifact that satisfies Key Criteria #3 and #4.
"""
from __future__ import annotations

from common.config import scoring_config
from common.paths import enriched_path, final_scored_path
from ingest.schema import Finding, load_findings, save_findings
from score.formula import get_asset_criticality, score_finding
from score.sla import apply_sla_and_ownership

# How many top findings get an AI-drafted summary — bounded to control API cost/latency.
AI_SUMMARY_TOP_N = 15


def apply_scoring(findings: list[Finding]) -> list[Finding]:
    cfg = scoring_config()
    for f in findings:
        if f.is_duplicate or f.suppressed:
            continue
        f.asset_criticality = get_asset_criticality(f.host)
        f.risk_score, f.score_breakdown = score_finding(f, cfg, f.asset_criticality)
        apply_sla_and_ownership(f, cfg)
    return findings


def ranked(findings: list[Finding]) -> list[Finding]:
    actionable = [f for f in findings if not f.is_duplicate and not f.suppressed]
    return sorted(actionable, key=lambda f: -(f.risk_score or 0.0))


def apply_ai_summaries(top_findings: list[Finding]) -> None:
    from ai.client import is_available
    from ai.summary_prompt import summarize_finding

    if not is_available():
        return
    for f in top_findings:
        try:
            f.ai_summary = summarize_finding(f)
        except Exception as e:  # keep pipeline resilient to transient API failures
            f.ai_summary = None
            print(f"  [warn] AI summary failed for '{f.title[:40]}': {e}")


def run_score_phase(scan_id: str, with_ai_summaries: bool = True) -> list[Finding]:
    findings = load_findings(enriched_path(scan_id))
    apply_scoring(findings)

    if with_ai_summaries:
        apply_ai_summaries(ranked(findings)[:AI_SUMMARY_TOP_N])

    save_findings(findings, final_scored_path(scan_id))
    return findings


if __name__ == "__main__":
    import click

    @click.command()
    @click.option("--scan-id", required=True)
    @click.option("--no-ai-summaries", is_flag=True)
    def main(scan_id, no_ai_summaries):
        findings = run_score_phase(scan_id, with_ai_summaries=not no_ai_summaries)
        for i, f in enumerate(ranked(findings)[:15], 1):
            print(f"{i:2d}. [{f.risk_score:5.1f}] {f.sla_tier:8s} {f.title[:45]:45s} "
                  f"owner={f.owner} due={f.sla_due_date}")

    main()
