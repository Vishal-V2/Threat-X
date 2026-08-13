"""NVD API v2.0 client — per-CVE CVSS v3.1 (falls back to v3.0, then v2 if a CVE
predates v3 scoring). Unauthenticated rate limit is 5 req/30s; an optional free
NVD_API_KEY raises that to 50 req/30s.
"""
from __future__ import annotations

import os

import requests
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from enrich.cache import get_or_fetch

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_TTL_DAYS = 7  # CVSS is static once NVD publishes it


class NvdRateLimitError(Exception):
    pass


@retry(retry=retry_if_exception_type(NvdRateLimitError), stop=stop_after_attempt(5),
       wait=wait_exponential(multiplier=2, min=2, max=30), reraise=True)
def _fetch_raw(cve_id: str) -> dict:
    headers = {}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
    resp = requests.get(NVD_BASE, params={"cveId": cve_id}, headers=headers, timeout=15)
    if resp.status_code in (403, 429):
        raise NvdRateLimitError(f"NVD rate limited (status {resp.status_code}) for {cve_id}")
    resp.raise_for_status()
    return resp.json()


def _extract_cvss(vuln: dict) -> dict | None:
    metrics = (vuln.get("cve", {}) or {}).get("metrics", {}) or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            data = entries[0]["cvssData"]
            return {
                "score": data.get("baseScore"),
                "vector": data.get("vectorString"),
                "severity": data.get("baseSeverity") or data.get("severity"),
                "version": key,
            }
    return None


def get_cvss(cve_id: str) -> dict | None:
    """Returns {'score','vector','severity','version'}, or None if NVD has no
    published CVSS for this CVE yet (e.g. very recently reserved)."""
    def fetch():
        try:
            raw = _fetch_raw(cve_id)
        except NvdRateLimitError:
            return None
        vulns = (raw or {}).get("vulnerabilities") or []
        return _extract_cvss(vulns[0]) if vulns else None

    return get_or_fetch("nvd", cve_id, fetch, CACHE_TTL_DAYS)
