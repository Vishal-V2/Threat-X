"""Top-level CLI orchestrator: ingest -> dedup -> enrich -> score -> ticket.

Each phase is also runnable standalone (python -m ingest.run_scanners, etc.) —
this just chains them for the one-command demo path (see scripts/demo.sh).
"""
from __future__ import annotations

import json

import click
from dotenv import load_dotenv

from common.config import scoring_config
from common.paths import final_scored_path, normalized_path
from dedup.pipeline import run_dedup_phase
from enrich.enrich_pipeline import run_enrich_phase
from ingest.run_scanners import ingest as run_ingest
from ingest.schema import load_findings, save_findings
from score.rank import run_score_phase
from ticket.github_issues import create_tickets

load_dotenv()


@click.group()
def cli():
    """Threat-X: risk prioritization & deduplication pipeline."""


@cli.command(name="ingest")
@click.option("--scan-id", required=True)
@click.option("--nuclei-path", default=None)
@click.option("--nmap-path", default=None)
@click.option("--zap-path", default=None)
@click.option("--use-fixtures", is_flag=True, help="Ingest from tests/fixtures/ instead of live scan output")
def ingest_cmd(scan_id, nuclei_path, nmap_path, zap_path, use_fixtures):
    if use_fixtures:
        nuclei_path = nuclei_path or "tests/fixtures/nuclei_sample.jsonl"
        nmap_path = nmap_path or "tests/fixtures/nmap_sample.xml"
        zap_path = zap_path or "tests/fixtures/zap_sample.json"
    missing = [n for n, p in [("--nuclei-path", nuclei_path), ("--nmap-path", nmap_path),
                              ("--zap-path", zap_path)] if not p]
    if missing:
        raise click.UsageError(f"Missing required paths: {', '.join(missing)} (or pass --use-fixtures)")
    findings = run_ingest(scan_id, nuclei_path, nmap_path, zap_path)
    click.echo(f"Ingested {len(findings)} findings from 3 scanners -> {normalized_path(scan_id)}")


@cli.command(name="dedup")
@click.option("--scan-id", required=True)
def dedup_cmd(scan_id):
    _, metrics = run_dedup_phase(scan_id)
    click.echo(json.dumps(metrics, indent=2))


@cli.command(name="enrich")
@click.option("--scan-id", required=True)
def enrich_cmd(scan_id):
    findings = run_enrich_phase(scan_id)
    n = sum(not f.is_duplicate and not f.suppressed for f in findings)
    click.echo(f"Enriched {n} non-duplicate, non-suppressed findings with NVD/KEV/EPSS/Exploit-DB data.")


@cli.command(name="score")
@click.option("--scan-id", required=True)
@click.option("--no-ai-summaries", is_flag=True)
def score_cmd(scan_id, no_ai_summaries):
    findings = run_score_phase(scan_id, with_ai_summaries=not no_ai_summaries)
    n = sum(not f.is_duplicate and not f.suppressed for f in findings)
    click.echo(f"Scored and ranked {n} findings -> {final_scored_path(scan_id)}")


@cli.command(name="ticket")
@click.option("--scan-id", required=True)
def ticket_cmd(scan_id):
    cfg = scoring_config()["ticketing"]
    findings = load_findings(final_scored_path(scan_id))
    create_tickets(scan_id, findings, cfg["min_score_to_ticket"], cfg["top_n"])
    save_findings(findings, final_scored_path(scan_id))


@cli.command()
@click.option("--scan-id", required=True)
@click.option("--use-fixtures", is_flag=True)
@click.option("--no-ai-summaries", is_flag=True)
@click.option("--no-ticket", is_flag=True)
@click.pass_context
def run(ctx, scan_id, use_fixtures, no_ai_summaries, no_ticket):
    """Runs the full pipeline end-to-end: ingest -> dedup -> enrich -> score -> ticket."""
    ctx.invoke(ingest_cmd, scan_id=scan_id, use_fixtures=use_fixtures)
    ctx.invoke(dedup_cmd, scan_id=scan_id)
    ctx.invoke(enrich_cmd, scan_id=scan_id)
    ctx.invoke(score_cmd, scan_id=scan_id, no_ai_summaries=no_ai_summaries)
    if not no_ticket:
        ctx.invoke(ticket_cmd, scan_id=scan_id)


if __name__ == "__main__":
    cli()
