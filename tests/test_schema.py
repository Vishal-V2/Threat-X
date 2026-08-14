from ingest.schema import Finding


def test_cve_ids_normalized_to_uppercase():
    """NVD/EPSS/KEV all do exact-string CVE lookups -- a real Nuclei community
    template (CVE-2023-48795.yaml) had 'cve-2023-48795' lowercase in its own
    YAML metadata, which silently 404'd against NVD's API during a live run.
    Every Finding must normalize CVE IDs at construction time regardless of
    which scanner/template produced them."""
    f = Finding(scan_id="t", source_scanner="nuclei", host="h", title="t",
                scanner_severity="medium",
                cve_ids=["cve-2023-48795", "CVE-2021-44228", "Cve-2019-1010"])
    assert f.cve_ids == ["CVE-2023-48795", "CVE-2021-44228", "CVE-2019-1010"]


def test_cve_ids_empty_list_stays_empty():
    f = Finding(scan_id="t", source_scanner="nuclei", host="h", title="t",
                scanner_severity="medium")
    assert f.cve_ids == []
