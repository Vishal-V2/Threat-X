import time

import enrich.enrich_pipeline as ep
from enrich.cache import get_or_fetch
from enrich.enrich_pipeline import _severity_fallback_cvss
from ingest.schema import Finding


def _finding(**kwargs) -> Finding:
    defaults = dict(scan_id="test", source_scanner="zap", host="h", title="t",
                     scanner_severity="medium")
    defaults.update(kwargs)
    return Finding(**defaults)


def test_cache_returns_fresh_value_without_refetching(tmp_path, monkeypatch):
    from common import paths
    monkeypatch.setattr(paths, "cache_db_path", lambda: tmp_path / "cache.db")
    # enrich.cache imports cache_db_path directly, so patch it there too
    import enrich.cache as cache_mod
    monkeypatch.setattr(cache_mod, "cache_db_path", lambda: tmp_path / "cache.db")

    calls = []

    def fetch():
        calls.append(1)
        return {"score": 9.8}

    first = get_or_fetch("nvd", "CVE-TEST-0001", fetch, ttl_days=7)
    second = get_or_fetch("nvd", "CVE-TEST-0001", fetch, ttl_days=7)

    assert first == {"score": 9.8}
    assert second == {"score": 9.8}
    assert len(calls) == 1  # second call served from cache, fetch_fn not invoked again


def test_cache_expires_after_ttl(tmp_path, monkeypatch):
    import enrich.cache as cache_mod
    monkeypatch.setattr(cache_mod, "cache_db_path", lambda: tmp_path / "cache.db")

    calls = []

    def fetch():
        calls.append(1)
        return {"n": len(calls)}

    get_or_fetch("src", "key", fetch, ttl_days=1e-9)  # effectively instant expiry
    time.sleep(0.01)
    get_or_fetch("src", "key", fetch, ttl_days=1e-9)

    assert len(calls) == 2


def test_severity_fallback_cvss_for_cveless_finding():
    table = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.5}
    assert _severity_fallback_cvss(_finding(scanner_severity="high"), table) == 7.5
    assert _severity_fallback_cvss(_finding(scanner_severity="info"), table) == 0.5
    assert _severity_fallback_cvss(_finding(scanner_severity="unknown-severity"), table) == 0.5


def test_safe_get_cvss_returns_none_on_exception(monkeypatch):
    """NVD's API is occasionally flaky -- a live run hit a transient 404 for a
    CVE that a direct curl fetched fine (HTTP 200, full record) moments
    later. Our retry logic only covers 403/429, so any other failure must be
    swallowed here rather than propagate and crash the whole enrichment phase
    over a single CVE."""
    def boom(cve):
        raise RuntimeError("simulated transient NVD failure")

    monkeypatch.setattr(ep.nvd, "get_cvss", boom)
    assert ep._safe_get_cvss("CVE-2023-48795") is None


def test_enrich_findings_survives_a_failing_nvd_lookup(monkeypatch):
    """End-to-end: one finding's only CVE fails its NVD lookup -- enrichment
    must still complete and fall back to the severity-based pseudo-CVSS,
    exactly as if the finding had no CVE at all, instead of crashing the
    batch for every other finding too."""
    monkeypatch.setattr(ep.kev, "get_kev_index", lambda: {})
    monkeypatch.setattr(ep.epss, "get_epss_scores", lambda cves: {})
    monkeypatch.setattr(ep.exploitdb, "get_exploit_ids", lambda cve: [])

    def flaky_get_cvss(cve):
        raise RuntimeError("simulated transient NVD failure")

    monkeypatch.setattr(ep.nvd, "get_cvss", flaky_get_cvss)

    f = _finding(cve_ids=["CVE-2023-48795"], scanner_severity="medium")
    findings = ep.enrich_findings([f])

    assert findings[0].cvss_source == "scanner_severity_fallback"
    assert findings[0].cvss_v3_score is not None
