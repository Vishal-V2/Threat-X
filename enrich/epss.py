"""FIRST.org EPSS (Exploit Prediction Scoring System) client — no auth, batched."""
from __future__ import annotations

import requests

from enrich.cache import get_or_fetch

EPSS_URL = "https://api.first.org/data/v1/epss"
CACHE_TTL_DAYS = 1  # EPSS recomputes daily
BATCH_SIZE = 100


def _fetch_batch(cve_ids: tuple[str, ...]) -> dict:
    resp = requests.get(EPSS_URL, params={"cve": ",".join(cve_ids)}, timeout=15)
    resp.raise_for_status()
    data = resp.json()
    return {
        row["cve"]: {"score": float(row["epss"]), "percentile": float(row["percentile"])}
        for row in data.get("data", [])
    }


def get_epss_scores(cve_ids: list[str]) -> dict:
    """Returns cve_id -> {'score','percentile'} for as many of the given CVEs as
    EPSS has scored (unscored/very-new CVEs are simply absent from the result)."""
    results: dict[str, dict] = {}
    unique = sorted(set(cve_ids))
    for start in range(0, len(unique), BATCH_SIZE):
        batch = tuple(unique[start:start + BATCH_SIZE])
        try:
            batch_result = get_or_fetch("epss", ",".join(batch), lambda b=batch: _fetch_batch(b),
                                         CACHE_TTL_DAYS)
        except Exception as e:
            print(f"  [warn] EPSS fetch failed for a batch, continuing without EPSS data: {e}")
            batch_result = {}
        results.update(batch_result or {})
    return results
