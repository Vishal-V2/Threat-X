"""Orchestrates scanner invocation (on a machine with Docker/nuclei/nmap installed)
and/or parsing of already-produced raw scanner output into the normalized dataset.

Two independent steps, callable separately so a demo without live Docker/scanner
access can still exercise the full ingest->dedup->enrich->score pipeline against
fixture raw output:

    run_scanners(scan_id, juice_shop_url, nmap_targets)   # invokes real scanner CLIs
    ingest(scan_id, nuclei_path, nmap_path, zap_path)      # parses raw files -> normalized.parquet
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from common.paths import normalized_path, raw_dir
from ingest import nmap_parser, nuclei_parser, zap_parser
from ingest.schema import Finding, save_findings

ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"


def run_nuclei(target_url: str, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["nuclei", "-u", target_url, "-jsonl", "-o", str(out_path), "-severity",
         "info,low,medium,high,critical", "-rate-limit", "50"],
        check=True,
    )


def run_nmap(targets: list[str], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["nmap", "-sV", "-sC", "--script", "vuln,vulners", "-oX", str(out_path), *targets],
        check=True,
    )


def run_zap(target_url: str, out_dir: Path, docker_network: str = "threatx-net") -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["docker", "run", "--rm", "--network", docker_network,
         "-v", f"{out_dir}:/zap/wrk/:rw", "-t", ZAP_IMAGE,
         "zap-baseline.py", "-t", target_url, "-J", "zap-report.json", "-I"],
        check=True,
    )


def run_scanners(scan_id: str, juice_shop_url: str, nmap_targets: list[str]) -> None:
    """Invokes the three real scanner CLIs. Requires nuclei/nmap on PATH and a
    running Docker daemon on `threatx-net` (see scripts/setup_target.sh)."""
    raw = raw_dir(scan_id)
    run_nuclei(juice_shop_url, raw / "nuclei" / "juice-shop.jsonl")
    run_nmap(nmap_targets, raw / "nmap" / "scan.xml")
    run_zap(juice_shop_url, raw / "zap")


def ingest(scan_id: str, nuclei_path: str | Path, nmap_path: str | Path,
           zap_path: str | Path) -> list[Finding]:
    """Parses raw scanner output already on disk (real scan output or fixtures)
    into the normalized Finding dataset and writes it to
    data/normalized/<scan_id>/normalized.parquet. This is the artifact that
    satisfies Key Criterion #1 (>=2 scanner outputs merged into one dataset)."""
    findings: list[Finding] = []
    findings += nuclei_parser.parse_file(nuclei_path, scan_id)
    findings += nmap_parser.parse_file(nmap_path, scan_id)
    findings += zap_parser.parse_file(zap_path, scan_id)

    save_findings(findings, normalized_path(scan_id))
    return findings


if __name__ == "__main__":
    import click

    @click.command()
    @click.option("--scan-id", required=True)
    @click.option("--nuclei-path", default=None, help="Path to nuclei JSONL output")
    @click.option("--nmap-path", default=None, help="Path to nmap XML output")
    @click.option("--zap-path", default=None, help="Path to ZAP JSON report")
    @click.option("--use-fixtures", is_flag=True, help="Ingest from tests/fixtures/ instead")
    def main(scan_id, nuclei_path, nmap_path, zap_path, use_fixtures):
        if use_fixtures:
            nuclei_path = nuclei_path or "tests/fixtures/nuclei_sample.jsonl"
            nmap_path = nmap_path or "tests/fixtures/nmap_sample.xml"
            zap_path = zap_path or "tests/fixtures/zap_sample.json"
        missing = [name for name, p in [("--nuclei-path", nuclei_path),
                                         ("--nmap-path", nmap_path),
                                         ("--zap-path", zap_path)] if not p]
        if missing:
            raise click.UsageError(f"Missing required paths: {', '.join(missing)} "
                                    "(or pass --use-fixtures)")
        findings = ingest(scan_id, nuclei_path, nmap_path, zap_path)
        print(f"Ingested {len(findings)} findings from 3 scanners into "
              f"{normalized_path(scan_id)}")

    main()
