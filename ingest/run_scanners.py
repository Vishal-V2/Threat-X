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


def run_nuclei(target_url: str, out_path: Path, fast: bool = False) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["nuclei", "-u", target_url, "-jsonl", "-o", str(out_path)]
    if fast:
        # Full default run: ~10.5k templates, several minutes even against one
        # host. Fast mode trims to the templates most likely to matter and
        # raises the request rate, at the cost of coverage.
        cmd += ["-severity", "medium,high,critical", "-tags", "cve,exposure,misconfig,default-login",
                "-rate-limit", "150"]
    else:
        cmd += ["-severity", "info,low,medium,high,critical", "-rate-limit", "50"]
    subprocess.run(cmd, check=True)


def run_nmap(targets: list[str], out_path: Path, fast: bool = False) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # The `vulners` script does a live network lookup per detected service —
    # it's the single biggest time cost (minutes, not seconds) and the first
    # thing to drop for speed; `vuln` alone still catches plenty via local
    # NSE checks. Note: `vulners.nse` self-registers under nmap's "vuln"
    # category too, so naming just "vuln" does NOT exclude it — has to be
    # explicitly subtracted via nmap's script-selection boolean expression.
    scripts = "vuln and not vulners" if fast else "vuln,vulners"
    cmd = ["nmap", "-sV", "-sC", "--script", scripts, "-oX", str(out_path)]
    if fast:
        cmd += ["--top-ports", "100"]
    cmd += targets
    subprocess.run(cmd, check=True)


def run_zap(target_url: str, out_dir: Path, docker_network: str = "threatx-net",
            fast: bool = False) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    # The ZAP container runs as its own internal user, unrelated to the host
    # UID that owns this bind-mounted directory — without world-writable
    # permissions here, ZAP can't write its config or report into the mount
    # at all (a well-documented ZAP-in-Docker gotcha, not scan-specific).
    out_dir.chmod(0o777)

    cmd = ["docker", "run", "--rm", "--network", docker_network,
           "-v", f"{out_dir}:/zap/wrk/:rw", "-t", ZAP_IMAGE,
           "zap-baseline.py", "-t", target_url, "-J", "zap-report.json", "-I"]
    if fast:
        cmd += ["-m", "2"]  # cap the spider phase at 2 minutes
    result = subprocess.run(cmd)

    # zap-baseline.py's exit code reflects alerts found (0=none, 1=warn,
    # 2=fail) — that's success, not a process failure, so we deliberately
    # don't `check=True` here. The only real failure signal is "no report
    # was produced at all".
    if not (out_dir / "zap-report.json").exists():
        raise RuntimeError(
            f"ZAP baseline scan did not produce a report (docker exit code "
            f"{result.returncode}). Check Docker/network connectivity to the target."
        )


def run_scanners(scan_id: str, juice_shop_url: str, nmap_targets: list[str],
                  fast: bool = False) -> None:
    """Invokes the three real scanner CLIs. Requires nuclei/nmap on PATH and a
    running Docker daemon on `threatx-net` (see scripts/setup_target.sh).
    fast=True trims each scanner's scope for a much quicker (less thorough) run."""
    raw = raw_dir(scan_id)
    run_nuclei(juice_shop_url, raw / "nuclei" / "juice-shop.jsonl", fast=fast)
    run_nmap(nmap_targets, raw / "nmap" / "scan.xml", fast=fast)
    run_zap(juice_shop_url, raw / "zap", fast=fast)


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
