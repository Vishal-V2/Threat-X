"""Top-level CLI orchestrator: ingest -> dedup -> enrich -> score -> ticket.

Each phase is also runnable standalone (python -m ingest.run_scanners, etc.) —
this just chains them for the one-command demo path (see scripts/demo.sh).
"""
from __future__ import annotations

import json
import shutil
import subprocess
from urllib.parse import urlparse

import click
from dotenv import load_dotenv

from common.config import scoring_config
from common.paths import final_scored_path, normalized_path, raw_dir
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


def _check_live_scan_prereqs() -> None:
    missing = []
    if shutil.which("nuclei") is None:
        missing.append("nuclei (https://docs.projectdiscovery.io/tools/nuclei/install)")
    if shutil.which("nmap") is None:
        missing.append("nmap (apt install nmap / brew install nmap)")
    try:
        subprocess.run(["docker", "info"], capture_output=True, check=True, timeout=10)
    except Exception:
        missing.append("a running Docker daemon (needed for the ZAP container)")
    if missing:
        raise click.UsageError(
            "Missing prerequisites for a live scan:\n  - " + "\n  - ".join(missing) +
            "\n\n(You can still exercise the pipeline without these via --use-fixtures)"
        )


@cli.command(name="ingest")
@click.option("--scan-id", required=True)
@click.option("--nuclei-path", default=None)
@click.option("--nmap-path", default=None)
@click.option("--zap-path", default=None)
@click.option("--use-fixtures", is_flag=True, help="Ingest from tests/fixtures/ instead of live scan output")
@click.option("--target-url", default=None,
              help="Run a live scan (Nuclei+Nmap+ZAP) against this URL first, then ingest its output")
@click.option("--nmap-target", multiple=True,
              help="Extra host/IP for Nmap (repeatable); defaults to --target-url's hostname")
@click.option("--fast", is_flag=True,
              help="Trim scanner scope for a much quicker (less thorough) live scan")
def ingest_cmd(scan_id, nuclei_path, nmap_path, zap_path, use_fixtures, target_url, nmap_target, fast):
    if target_url:
        if use_fixtures or nuclei_path or nmap_path or zap_path:
            raise click.UsageError("--target-url can't be combined with --use-fixtures or explicit --*-path options.")

        _check_live_scan_prereqs()
        from ingest.run_scanners import run_scanners

        host = urlparse(target_url).hostname
        if not host:
            raise click.UsageError(f"Couldn't parse a hostname out of '{target_url}' — "
                                    "pass a full URL, e.g. https://example.com")
        targets = list(nmap_target) or [host]

        subprocess.run(["docker", "network", "create", "threatx-net"], capture_output=True)
        click.echo(f"Scanning {target_url} (host: {host}){' [fast mode]' if fast else ''}...")
        run_scanners(scan_id, target_url, targets, fast=fast)

        raw = raw_dir(scan_id)
        nuclei_path = str(raw / "nuclei" / "juice-shop.jsonl")
        nmap_path = str(raw / "nmap" / "scan.xml")
        zap_path = str(raw / "zap" / "zap-report.json")
    elif use_fixtures:
        nuclei_path = nuclei_path or "tests/fixtures/nuclei_sample.jsonl"
        nmap_path = nmap_path or "tests/fixtures/nmap_sample.xml"
        zap_path = zap_path or "tests/fixtures/zap_sample.json"

    missing = [n for n, p in [("--nuclei-path", nuclei_path), ("--nmap-path", nmap_path),
                              ("--zap-path", zap_path)] if not p]
    if missing:
        raise click.UsageError(f"Missing required paths: {', '.join(missing)} "
                                "(or pass --use-fixtures / --target-url)")
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


@cli.command(name="assign")
@click.argument("issue")
@click.option("--user", "-u", multiple=True,
              help="GitHub username to assign (repeatable: -u alice -u bob). "
                   "Omit entirely to unassign everyone.")
def assign_cmd(issue, user):
    """Assign (or unassign) a GitHub issue — replaces its current assignee
    list. ISSUE can be a bare number (5) or a full issue URL."""
    import os
    import re

    match = re.search(r"(\d+)/?$", issue)
    if not match:
        raise click.UsageError(f"Couldn't find an issue number in '{issue}'")
    issue_number = int(match.group(1))

    token = os.environ.get("GITHUB_TOKEN")
    repo_name = os.environ.get("GITHUB_REPO")
    if not token or not repo_name:
        raise click.UsageError("GITHUB_TOKEN and GITHUB_REPO must be set (see .env)")

    from github import Auth, Github
    from github.GithubException import GithubException

    gh = Github(auth=Auth.Token(token))
    repo = gh.get_repo(repo_name)
    try:
        gh_issue = repo.get_issue(issue_number)
        gh_issue.edit(assignees=list(user))
    except GithubException as e:
        raise click.ClickException(f"GitHub API error ({e.status}): {e.data}")

    if user:
        click.echo(f"Issue #{issue_number} assigned to: {', '.join(user)}")
    else:
        click.echo(f"Issue #{issue_number} unassigned.")


@cli.command()
@click.option("--scan-id", required=True)
@click.option("--use-fixtures", is_flag=True)
@click.option("--target-url", default=None,
              help="Run a live scan (Nuclei+Nmap+ZAP) against this URL instead of using fixtures")
@click.option("--nmap-target", multiple=True,
              help="Extra host/IP for Nmap (repeatable); defaults to --target-url's hostname")
@click.option("--fast", is_flag=True,
              help="Trim scanner scope for a much quicker (less thorough) live scan")
@click.option("--no-ai-summaries", is_flag=True)
@click.option("--no-ticket", is_flag=True)
@click.pass_context
def run(ctx, scan_id, use_fixtures, target_url, nmap_target, fast, no_ai_summaries, no_ticket):
    """Runs the full pipeline end-to-end: ingest -> dedup -> enrich -> score -> ticket."""
    ctx.invoke(ingest_cmd, scan_id=scan_id, use_fixtures=use_fixtures,
               target_url=target_url, nmap_target=nmap_target, fast=fast)
    ctx.invoke(dedup_cmd, scan_id=scan_id)
    ctx.invoke(enrich_cmd, scan_id=scan_id)
    ctx.invoke(score_cmd, scan_id=scan_id, no_ai_summaries=no_ai_summaries)
    if not no_ticket:
        ctx.invoke(ticket_cmd, scan_id=scan_id)


if __name__ == "__main__":
    cli()
