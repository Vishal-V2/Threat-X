"""CISA Known Exploited Vulnerabilities (KEV) catalog — single JSON feed, no auth."""
from __future__ import annotations

import requests

from enrich.cache import get_or_fetch

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_TTL_DAYS = 1


def _fetch_feed() -> dict:
    resp = requests.get(KEV_URL, timeout=20)
    resp.raise_for_status()
    data = resp.json()
    entries = {}
    for vuln in data.get("vulnerabilities", []):
        entries[vuln["cveID"]] = {
            "date_added": vuln.get("dateAdded"),
            "ransomware_known": vuln.get("knownRansomwareCampaignUse", "Unknown") == "Known",
        }
    return entries


def get_kev_index() -> dict:
    """Fetches (or returns cached) the full KEV catalog as
    cve_id -> {date_added, ransomware_known}."""
    return get_or_fetch("kev", "catalog", _fetch_feed, CACHE_TTL_DAYS) or {}
