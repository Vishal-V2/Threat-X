"""Parses `nmap -sV -sC --script vuln,vulners -oX` XML output into Findings.

Only script output that actually names a CVE becomes a Finding — plain open-port/
service-banner data isn't a vulnerability finding on its own in this schema. One
Finding is emitted per (host, port, script) that contains >=1 CVE, with all CVEs
found in that script's output attached to it.

Uses stdlib xml.etree rather than an external nmap-parsing library to keep this
parser dependency-free and predictable.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from ingest.schema import Finding

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
# vulners-style lines look like: "\tCVE-2011-2523\t10.0\thttps://vulners.com/... *EXPLOIT*"
_CVE_SCORE_RE = re.compile(r"(CVE-\d{4}-\d{4,7})\s+([\d.]+)")


def _severity_from_score(score: float | None) -> str:
    if score is None:
        return "medium"
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def _max_score_for_cves(cves: list[str], script_output: str) -> float | None:
    scores = {m.group(1): float(m.group(2)) for m in _CVE_SCORE_RE.finditer(script_output)}
    relevant = [scores[c] for c in cves if c in scores]
    return max(relevant) if relevant else None


def parse_file(path: str | Path, scan_id: str) -> list[Finding]:
    path = Path(path)
    tree = ET.parse(path)
    root = tree.getroot()
    findings: list[Finding] = []

    for host_el in root.findall("host"):
        addr_el = host_el.find("address")
        ip = addr_el.get("addr") if addr_el is not None else None
        hostname_el = host_el.find("hostnames/hostname")
        host = hostname_el.get("name") if hostname_el is not None else ip
        if host is None:
            continue

        ports_el = host_el.find("ports")
        if ports_el is None:
            continue

        for port_el in ports_el.findall("port"):
            port = int(port_el.get("portid"))
            service_el = port_el.find("service")
            service = service_el.get("name") if service_el is not None else None
            product = service_el.get("product") if service_el is not None else None
            version = service_el.get("version") if service_el is not None else None

            for script_el in port_el.findall("script"):
                script_id = script_el.get("id", "")
                output = script_el.get("output", "")
                cves = sorted(set(_CVE_RE.findall(output)))
                if not cves:
                    continue

                score = _max_score_for_cves(cves, output)
                product_label = " ".join(filter(None, [product, version]))
                findings.append(Finding(
                    scan_id=scan_id,
                    source_scanner="nmap",
                    host=host,
                    port=port,
                    service=service,
                    title=f"{script_id} findings on {port}/{service or 'unknown'}"
                          + (f" ({product_label})" if product_label else ""),
                    description=output.strip()[:2000],
                    cve_ids=cves,
                    scanner_severity=_severity_from_score(score),
                    raw_evidence={
                        "script_id": script_id,
                        "output": output,
                        "product": product,
                        "version": version,
                        "ip": ip,
                    },
                ))

    return findings
