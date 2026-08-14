"""Attaches CVSS (NVD), EPSS, KEV, and Exploit-DB data to every non-duplicate,
non-suppressed finding. Multi-CVE findings use the max CVSS/EPSS across their CVE
list; in_kev/exploit_db_available are true if ANY of their CVEs qualify.
"""
from __future__ import annotations

from datetime import datetime, timezone

from common.config import scoring_config
from common.paths import deduped_path, enriched_path
from enrich import epss, exploitdb, kev, nvd
from ingest.schema import Finding, load_findings, save_findings


def _severity_fallback_cvss(finding: Finding, table: dict) -> float:
    return table.get(finding.scanner_severity.lower(), table.get("info", 0.5))


def _safe_get_cvss(cve: str) -> dict | None:
    """NVD's API is occasionally flaky (transient 404/5xx on a request that
    succeeds moments later) — our retry logic only covers 403/429, so any
    other transient failure would otherwise crash the entire enrichment phase
    over a single CVE. One CVE's lookup failing degrades to the
    severity-fallback CVSS for that finding, same as if it had no CVE data at all."""
    try:
        return nvd.get_cvss(cve)
    except Exception as e:
        print(f"  [warn] NVD lookup failed for {cve}: {e}")
        return None


def enrich_findings(findings: list[Finding]) -> list[Finding]:
    targets = [f for f in findings if not f.is_duplicate and not f.suppressed]
    all_cves = sorted({c for f in targets for c in f.cve_ids})

    kev_index = kev.get_kev_index()
    epss_scores = epss.get_epss_scores(all_cves) if all_cves else {}
    fallback_table = scoring_config()["severity_fallback_cvss"]

    for f in targets:
        if f.cve_ids:
            cvss_hits = [c for c in (_safe_get_cvss(cve) for cve in f.cve_ids) if c and c.get("score") is not None]
            if cvss_hits:
                best = max(cvss_hits, key=lambda c: c["score"])
                f.cvss_v3_score = best["score"]
                f.cvss_v3_vector = best["vector"]
                f.cvss_source = "nvd"
            else:
                f.cvss_v3_score = _severity_fallback_cvss(f, fallback_table)
                f.cvss_source = "scanner_severity_fallback"

            epss_hits = [epss_scores[c] for c in f.cve_ids if c in epss_scores]
            if epss_hits:
                best_epss = max(epss_hits, key=lambda e: e["score"])
                f.epss_score = best_epss["score"]
                f.epss_percentile = best_epss["percentile"]

            kev_hits = [kev_index[c] for c in f.cve_ids if c in kev_index]
            if kev_hits:
                f.in_kev = True
                f.kev_date_added = kev_hits[0]["date_added"]
                f.kev_ransomware_known = any(h["ransomware_known"] for h in kev_hits)

            exploit_ids: set[str] = set()
            for c in f.cve_ids:
                exploit_ids.update(exploitdb.get_exploit_ids(c))
            f.exploit_db_ids = sorted(exploit_ids)
            f.exploit_db_available = bool(exploit_ids)
        else:
            f.cvss_v3_score = _severity_fallback_cvss(f, fallback_table)
            f.cvss_source = "scanner_severity_fallback"

        f.enrichment_fetched_at = datetime.now(timezone.utc)

    return findings


def run_enrich_phase(scan_id: str) -> list[Finding]:
    findings = load_findings(deduped_path(scan_id))
    enrich_findings(findings)
    save_findings(findings, enriched_path(scan_id))
    return findings


if __name__ == "__main__":
    import click

    @click.command()
    @click.option("--scan-id", required=True)
    def main(scan_id):
        findings = run_enrich_phase(scan_id)
        enriched = [f for f in findings if not f.is_duplicate and not f.suppressed]
        print(f"Enriched {len(enriched)} findings.")
        for f in sorted(enriched, key=lambda f: -(f.cvss_v3_score or 0)):
            print(f"  {f.title[:45]:45s} cvss={f.cvss_v3_score!s:6s} "
                  f"src={f.cvss_source!s:26s} epss={f.epss_score!s:8s} "
                  f"kev={f.in_kev!s:5s} exploit={f.exploit_db_available}")

    main()
