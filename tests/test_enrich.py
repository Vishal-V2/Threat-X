import time

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
