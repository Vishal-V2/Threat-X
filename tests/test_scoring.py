from datetime import date

from common.config import load_yaml
from ingest.schema import Finding
from score.formula import get_asset_criticality, score_finding
from score.sla import (
    apply_sla_and_ownership,
    get_github_assignee,
    get_owner_team,
    sla_for_score,
)

CFG = load_yaml("scoring.yaml")


def _finding(**kwargs) -> Finding:
    defaults = dict(scan_id="test", source_scanner="nuclei", host="h", title="t",
                     scanner_severity="high")
    defaults.update(kwargs)
    return Finding(**defaults)


def test_score_is_clipped_to_0_100():
    f = _finding(cvss_v3_score=10.0, epss_score=1.0, in_kev=True, exploit_db_available=True)
    score, breakdown = score_finding(f, CFG, criticality="critical")
    assert 0.0 <= score <= 100.0
    assert breakdown["final_score"] == score


def test_kev_and_exploitdb_boosts_dont_double_count():
    base = _finding(cvss_v3_score=5.0, epss_score=0.1, in_kev=True, exploit_db_available=True)
    score_with_both, breakdown = score_finding(base, CFG, criticality="medium")
    assert breakdown["kev_boost"] == CFG["kev_boost"]
    assert breakdown["exploitdb_boost"] == 0.0  # suppressed because KEV already applied


def test_low_epss_finding_scores_lower_than_high_epss_despite_equal_cvss():
    """This is the 'not raw CVSS alone' criterion in miniature: two findings with
    identical CVSS but different real-world exploitation likelihood must not
    score the same."""
    low_epss = _finding(cvss_v3_score=9.0, epss_score=0.02)
    high_epss = _finding(cvss_v3_score=9.0, epss_score=0.95)
    score_low, _ = score_finding(low_epss, CFG, criticality="medium")
    score_high, _ = score_finding(high_epss, CFG, criticality="medium")
    assert score_high > score_low


def test_asset_criticality_moves_the_score():
    f_low_asset = _finding(cvss_v3_score=6.0, epss_score=0.3)
    f_high_asset = _finding(cvss_v3_score=6.0, epss_score=0.3)
    score_low, _ = score_finding(f_low_asset, CFG, criticality="low")
    score_high, _ = score_finding(f_high_asset, CFG, criticality="critical")
    assert score_high > score_low


def test_sla_tier_boundaries():
    assert sla_for_score(95, CFG) == ("critical", 3)
    assert sla_for_score(70, CFG) == ("high", 7)
    assert sla_for_score(69.9, CFG) == ("medium", 30)
    assert sla_for_score(0, CFG) == ("low", 90)


_ASSETS_FIXTURE = {
    "assets": {
        "known-host": {"owner": "@appsec-lead", "team": "AppSec", "github_username": "realuser"},
        "no-assignee-host": {"owner": "@netsec-lead", "team": "NetSec", "github_username": None},
    },
    "default": {"owner": "@triage", "team": "Unassigned", "github_username": None},
}


def test_get_owner_team_uses_configured_host(monkeypatch):
    import score.sla as sla_mod
    monkeypatch.setattr(sla_mod, "assets_config", lambda: _ASSETS_FIXTURE)
    assert get_owner_team("known-host") == ("@appsec-lead", "AppSec")


def test_get_owner_team_falls_back_to_default_for_unknown_host(monkeypatch):
    import score.sla as sla_mod
    monkeypatch.setattr(sla_mod, "assets_config", lambda: _ASSETS_FIXTURE)
    assert get_owner_team("never-configured-host") == ("@triage", "Unassigned")


def test_get_github_assignee_returns_configured_username(monkeypatch):
    """github_username is a separate, real-GitHub-login field from `owner` --
    `owner` is free display text (e.g. '@appsec-lead') that's never validated
    against a real account, so it must never be the thing passed as a GitHub
    issue assignee."""
    import score.sla as sla_mod
    monkeypatch.setattr(sla_mod, "assets_config", lambda: _ASSETS_FIXTURE)
    assert get_github_assignee("known-host") == "realuser"


def test_get_github_assignee_is_none_when_unset(monkeypatch):
    import score.sla as sla_mod
    monkeypatch.setattr(sla_mod, "assets_config", lambda: _ASSETS_FIXTURE)
    assert get_github_assignee("no-assignee-host") is None
    assert get_github_assignee("never-configured-host") is None


_CRITICALITY_ASSETS_FIXTURE = {
    "assets": {
        "known-host": {"criticality": "high", "owner": "@appsec-lead", "team": "AppSec"},
        "incomplete-host": {"owner": "@netsec-lead", "team": "NetSec"},
    },
    "default": {"criticality": "medium", "owner": "@triage", "team": "Unassigned"},
}


def test_get_asset_criticality_returns_configured_value_for_known_host(monkeypatch):
    import score.formula as formula_mod
    monkeypatch.setattr(formula_mod, "assets_config", lambda: _CRITICALITY_ASSETS_FIXTURE)
    assert get_asset_criticality("known-host") == "high"


def test_get_asset_criticality_falls_back_to_default_for_unknown_host(monkeypatch):
    import score.formula as formula_mod
    monkeypatch.setattr(formula_mod, "assets_config", lambda: _CRITICALITY_ASSETS_FIXTURE)
    assert get_asset_criticality("never-configured-host") == "medium"


def test_get_asset_criticality_returns_unknown_when_host_entry_lacks_criticality(monkeypatch):
    import score.formula as formula_mod
    monkeypatch.setattr(formula_mod, "assets_config", lambda: _CRITICALITY_ASSETS_FIXTURE)
    assert get_asset_criticality("incomplete-host") == "unknown"


def test_apply_sla_and_ownership_sets_high_tier_due_date_and_owner():
    f = _finding(host="juice-shop", risk_score=75.0)
    apply_sla_and_ownership(f, CFG, scan_date=date(2026, 1, 15))
    assert f.sla_tier == "high"
    assert f.sla_due_date == date(2026, 1, 22)
    assert f.owner == "@Vishal-V2"
    assert f.team == "AppSec"
