"""The explainable, deterministic scoring formula. No LLM in this path — ranking
explainability is a judged criterion, so every point of the final score traces to
a named, weighted component stored in score_breakdown.

CVSS is deliberately capped at 35% of the weight (config/scoring.yaml) so the
score is driven by real threat intel — EPSS (actual exploitation likelihood),
KEV (confirmed active exploitation), Exploit-DB (public exploit exists), and
asset criticality — not raw CVSS alone.
"""
from __future__ import annotations

from common.config import assets_config
from ingest.schema import Finding


def get_asset_criticality(host: str) -> str:
    cfg = assets_config()
    assets = cfg.get("assets", {})
    if host in assets:
        return assets[host].get("criticality", "unknown")
    return cfg.get("default", {}).get("criticality", "unknown")


def score_finding(f: Finding, cfg: dict, criticality: str) -> tuple[float, dict]:
    w = cfg["weights"]
    asset_scores = cfg["asset_criticality_scores"]

    cvss = f.cvss_v3_score or 0.0
    epss = f.epss_score or 0.0

    cvss_component = (cvss / 10 * 100) * w["cvss"]
    epss_component = epss * 100 * w["epss"]
    asset_component = asset_scores.get(criticality, asset_scores.get("unknown", 50)) * w["asset_criticality"]

    kev_boost = cfg["kev_boost"] if f.in_kev else 0
    # Avoid double-counting: KEV already implies active real-world exploitation,
    # so only add the (smaller) Exploit-DB boost when KEV didn't already apply.
    exploitdb_boost = cfg["exploitdb_boost"] if (f.exploit_db_available and not f.in_kev) else 0

    raw_total = cvss_component + epss_component + asset_component + kev_boost + exploitdb_boost
    final_score = round(max(0.0, min(100.0, raw_total)), 2)

    breakdown = {
        "cvss_component": round(cvss_component, 2),
        "epss_component": round(epss_component, 2),
        "asset_component": round(asset_component, 2),
        "kev_boost": float(kev_boost),
        "exploitdb_boost": float(exploitdb_boost),
        "raw_total_before_clip": round(raw_total, 2),
        "final_score": round(final_score, 2),
    }
    return final_score, breakdown
