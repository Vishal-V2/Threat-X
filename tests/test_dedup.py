from dedup.deterministic import (UnionFind, annotate_normalized_titles, finalize_groups,
                                  group_by_cve_host, group_by_title_host_port)
from dedup.metrics import compute_metrics
from ingest.schema import Finding


def _finding(**kwargs) -> Finding:
    defaults = dict(scan_id="test", source_scanner="nuclei", host="h", title="t",
                     scanner_severity="medium")
    defaults.update(kwargs)
    return Finding(**defaults)


def test_exact_cve_host_merge():
    findings = [
        _finding(source_scanner="nuclei", title="Log4Shell RCE", cve_ids=["CVE-2021-44228"]),
        _finding(source_scanner="nmap", title="vulners log4j finding", cve_ids=["CVE-2021-44228"]),
        _finding(source_scanner="zap", title="Unrelated finding", cve_ids=["CVE-9999-0001"]),
    ]
    annotate_normalized_titles(findings)
    uf = UnionFind(len(findings))
    edge_method: dict[frozenset, str] = {}
    group_by_cve_host(findings, uf, edge_method)
    group_by_title_host_port(findings, uf, edge_method)
    finalize_groups(findings, uf, edge_method)

    duplicates = [f for f in findings if f.is_duplicate]
    canonical = [f for f in findings if not f.is_duplicate]
    assert len(duplicates) == 1
    assert len(canonical) == 2
    assert duplicates[0].dedup_method == "exact_cve_host"
    log4j_canonical = next(f for f in canonical if f.cve_ids == ["CVE-2021-44228"])
    assert sorted(log4j_canonical.contributing_scanners) == ["nmap", "nuclei"]


def test_exact_title_host_port_merge_for_cveless_findings():
    findings = [
        _finding(source_scanner="nuclei", title="Missing CSP Header", port=3000),
        _finding(source_scanner="zap", title="missing csp header!!", port=3000),
    ]
    annotate_normalized_titles(findings)
    uf = UnionFind(len(findings))
    edge_method: dict[frozenset, str] = {}
    group_by_cve_host(findings, uf, edge_method)
    group_by_title_host_port(findings, uf, edge_method)
    finalize_groups(findings, uf, edge_method)

    assert sum(f.is_duplicate for f in findings) == 1
    dup = next(f for f in findings if f.is_duplicate)
    assert dup.dedup_method == "exact_title_host_port"


def test_metrics_computed_from_dedup_and_suppression_state():
    findings = [
        _finding(is_duplicate=False, suppressed=False),
        _finding(is_duplicate=True, suppressed=False, dedup_method="exact_cve_host"),
        _finding(is_duplicate=False, suppressed=True),
        _finding(is_duplicate=False, suppressed=False),
    ]
    metrics = compute_metrics(findings, "test-metrics-scan")
    assert metrics["raw_count"] == 4
    assert metrics["duplicate_count"] == 1
    assert metrics["suppressed_count"] == 1
    assert metrics["final_count"] == 2
    assert metrics["dedup_pct"] == 25.0
    assert metrics["fp_removed_pct"] == 25.0
    assert metrics["noise_reduction_pct"] == 50.0
