"""Parses an OWASP ZAP baseline scan JSON report into Findings.

Report shape (zap-baseline.py -J report.json):
{
  "site": [
    {
      "@name": "http://juice-shop:3000",
      "alerts": [
        {
          "name": "Content Security Policy (CSP) Header Not Set",
          "riskdesc": "Medium (Medium)",
          "desc": "...",
          "cweid": "693",
          "reference": "https://...",
          "instances": [{"uri": "...", "method": "GET", "param": "", "evidence": ""}]
        }
      ]
    }
  ]
}

ZAP alerts almost never carry a CVE — this is expected, and exactly the case the
LLM semantic-dedup pass exists to catch (e.g. a ZAP header alert and a Nuclei
exposure template both describing the same underlying issue with no CVE at all).
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlparse

from ingest.schema import Finding

_RISKDESC_RE = re.compile(r"^\s*(\w+)\s*\((\w+)\)")
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
_DEFAULT_PORTS = {"http": 80, "https": 443}


def _parse_riskdesc(riskdesc: str) -> tuple[str, str]:
    m = _RISKDESC_RE.match(riskdesc or "")
    if not m:
        return "info", "unknown"
    return m.group(1).lower(), m.group(2).lower()


def parse_file(path: str | Path, scan_id: str) -> list[Finding]:
    path = Path(path)
    with open(path) as f:
        report = json.load(f)

    findings: list[Finding] = []
    for site in report.get("site", []):
        parsed = urlparse(site.get("@name", ""))
        host = parsed.hostname or site.get("@name", "unknown")
        port = parsed.port or _DEFAULT_PORTS.get(parsed.scheme)

        for alert in site.get("alerts", []):
            risk, confidence = _parse_riskdesc(alert.get("riskdesc", ""))
            text_blob = " ".join(filter(None, [alert.get("desc"), alert.get("reference")]))
            cve_ids = sorted(set(_CVE_RE.findall(text_blob)))

            findings.append(Finding(
                scan_id=scan_id,
                source_scanner="zap",
                host=host,
                port=port,
                title=alert.get("name", "Unnamed ZAP alert"),
                description=alert.get("desc"),
                cve_ids=cve_ids,
                scanner_severity=risk,
                scanner_confidence=confidence,
                raw_evidence={
                    "pluginid": alert.get("pluginid"),
                    "cweid": alert.get("cweid"),
                    "reference": alert.get("reference"),
                    "instances": alert.get("instances", []),
                },
            ))

    return findings
