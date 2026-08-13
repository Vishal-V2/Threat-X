"""Parses `nuclei -jsonl` output into Findings.

Each line is a JSON object roughly shaped like:
{
  "template-id": "CVE-2021-44228-log4j",
  "info": {
    "name": "Apache Log4j RCE",
    "severity": "critical",
    "description": "...",
    "classification": {"cve-id": ["CVE-2021-44228"], "cvss-score": 10.0}
  },
  "host": "http://juice-shop:3000",
  "matched-at": "http://juice-shop:3000/rest/",
  "ip": "172.19.0.2",
  "timestamp": "2026-08-13T10:00:00.000000000Z"
}

Most findings against a target like Juice Shop are exposure/misconfig/tech-detect
templates with no CVE at all — that's expected, not a parsing gap.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from ingest.schema import Finding

_DEFAULT_PORTS = {"http": 80, "https": 443}


def _parse_timestamp(raw: str | None) -> datetime:
    if not raw:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)


def _host_and_port(record: dict) -> tuple[str, int | None]:
    url = record.get("matched-at") or record.get("host") or ""
    parsed = urlparse(url)
    host = parsed.hostname or record.get("ip") or url
    port = parsed.port or _DEFAULT_PORTS.get(parsed.scheme)
    return host, port


def _cve_ids(info: dict) -> list[str]:
    raw = (info.get("classification") or {}).get("cve-id") or []
    if isinstance(raw, str):
        return [raw]
    return list(raw)


def parse_line(line: str, scan_id: str) -> Finding | None:
    line = line.strip()
    if not line:
        return None
    record = json.loads(line)
    info = record.get("info", {})
    host, port = _host_and_port(record)

    return Finding(
        scan_id=scan_id,
        source_scanner="nuclei",
        host=host,
        port=port,
        title=info.get("name", record.get("template-id", "Unnamed nuclei finding")),
        description=info.get("description"),
        cve_ids=_cve_ids(info),
        scanner_severity=(info.get("severity") or "info").lower(),
        scanner_confidence=None,
        raw_evidence=record,
        first_seen=_parse_timestamp(record.get("timestamp")),
    )


def parse_file(path: str | Path, scan_id: str) -> list[Finding]:
    path = Path(path)
    findings = []
    with open(path) as f:
        for line in f:
            finding = parse_line(line, scan_id)
            if finding is not None:
                findings.append(finding)
    return findings
