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
