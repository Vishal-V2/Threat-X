"""Maps a risk_score to an SLA tier/remediation window, and a host to its ticket
owner/team, per config/scoring.yaml and config/assets.yaml.
"""
from __future__ import annotations

from datetime import date, timedelta

from common.config import assets_config, scoring_config
from ingest.schema import Finding


def get_owner_team(host: str) -> tuple[str, str]:
    cfg = assets_config()
    assets = cfg.get("assets", {})
    if host in assets:
        a = assets[host]
        return a.get("owner", "@triage"), a.get("team", "Unassigned")
    default = cfg.get("default", {})
    return default.get("owner", "@triage"), default.get("team", "Unassigned")


def get_github_assignee(host: str) -> str | None:
    """A real GitHub login to assign the ticket to (GitHub's Assignees field),
    separate from `owner` — `owner` is a free-text display label (e.g.
    "@appsec-lead") that never has to be a valid account; this must be an
    actual GitHub username with at least read access to the repo, or GitHub
    silently drops it as an assignee without erroring the issue creation."""
    cfg = assets_config()
    assets = cfg.get("assets", {})
    if host in assets:
        username = assets[host].get("github_username")
    else:
        username = cfg.get("default", {}).get("github_username")
    return username or None


def sla_for_score(score: float, cfg: dict) -> tuple[str, int]:
    for tier in cfg["sla_tiers"]:
        if score >= tier["min"]:
            return tier["tier"], tier["sla_days"]
    return "low", 90


def apply_sla_and_ownership(f: Finding, cfg: dict, scan_date: date | None = None) -> None:
    scan_date = scan_date or date.today()
    tier, sla_days = sla_for_score(f.risk_score or 0.0, cfg)
    f.sla_tier = tier
    f.sla_due_date = scan_date + timedelta(days=sla_days)
    f.owner, f.team = get_owner_team(f.host)
