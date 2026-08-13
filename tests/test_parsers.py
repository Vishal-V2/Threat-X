from ingest import nmap_parser, nuclei_parser, zap_parser

FIXTURES = "tests/fixtures"


def test_nuclei_parser():
    findings = nuclei_parser.parse_file(f"{FIXTURES}/nuclei_sample.jsonl", "test")
    assert len(findings) == 5
    assert all(f.source_scanner == "nuclei" for f in findings)
    log4j = next(f for f in findings if "Log4j" in f.title)
    assert log4j.cve_ids == ["CVE-2021-44228"]
    assert log4j.scanner_severity == "critical"
    assert log4j.host == "juice-shop"
    assert log4j.port == 3000


def test_nmap_parser():
    findings = nmap_parser.parse_file(f"{FIXTURES}/nmap_sample.xml", "test")
    assert len(findings) == 4
    assert all(f.source_scanner == "nmap" for f in findings)
    vsftpd = next(f for f in findings if "CVE-2011-2523" in f.cve_ids)
    assert vsftpd.host == "metasploitable"
    assert vsftpd.port == 21
    assert vsftpd.scanner_severity == "critical"


def test_zap_parser():
    findings = zap_parser.parse_file(f"{FIXTURES}/zap_sample.json", "test")
    assert len(findings) == 5
    assert all(f.source_scanner == "zap" for f in findings)
    lodash = next(f for f in findings if "Lodash" in f.title)
    assert lodash.cve_ids == ["CVE-2019-10744"]
    assert lodash.scanner_severity == "medium"
    assert lodash.scanner_confidence == "high"


def test_cross_scanner_cve_overlap_exists_in_fixtures():
    """Sanity check that our fixtures actually exercise cross-scanner dedup:
    CVE-2021-44228 should appear in both nuclei and nmap output, and
    CVE-2019-10744 in both nuclei and zap output."""
    nuclei = nuclei_parser.parse_file(f"{FIXTURES}/nuclei_sample.jsonl", "test")
    nmap = nmap_parser.parse_file(f"{FIXTURES}/nmap_sample.xml", "test")
    zap = zap_parser.parse_file(f"{FIXTURES}/zap_sample.json", "test")

    nuclei_cves = {c for f in nuclei for c in f.cve_ids}
    nmap_cves = {c for f in nmap for c in f.cve_ids}
    zap_cves = {c for f in zap for c in f.cve_ids}

    assert "CVE-2021-44228" in nuclei_cves & nmap_cves
    assert "CVE-2019-10744" in nuclei_cves & zap_cves
