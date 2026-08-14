from unittest.mock import MagicMock, patch

import pytest

from ingest.run_scanners import run_nmap, run_zap


def test_fast_mode_excludes_vulners_script(tmp_path):
    """vulners.nse self-registers under nmap's 'vuln' category too (confirmed
    via `nmap --script-help`), so naming just 'vuln' does NOT exclude it --
    fast mode must explicitly subtract it via a script-selection expression,
    or it silently keeps the slow external vulners.com lookups it's supposed
    to drop."""
    out_path = tmp_path / "scan.xml"
    with patch("ingest.run_scanners.subprocess.run") as mock_run:
        run_nmap(["example.com"], out_path, fast=True)

    cmd = mock_run.call_args[0][0]
    script_idx = cmd.index("--script")
    assert cmd[script_idx + 1] == "vuln and not vulners"
    assert "--top-ports" in cmd


def test_normal_mode_still_includes_vulners(tmp_path):
    out_path = tmp_path / "scan.xml"
    with patch("ingest.run_scanners.subprocess.run") as mock_run:
        run_nmap(["example.com"], out_path, fast=False)

    cmd = mock_run.call_args[0][0]
    script_idx = cmd.index("--script")
    assert cmd[script_idx + 1] == "vuln,vulners"
    assert "--top-ports" not in cmd


def _zap_call_that_writes_report(out_dir, returncode):
    """Simulates a real docker/zap-baseline.py invocation: writes the report
    file as a side effect and returns some exit code, without touching Docker."""
    def fake_run(cmd, *args, **kwargs):
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "zap-report.json").write_text('{"alerts": []}')
        return MagicMock(returncode=returncode)
    return fake_run


def test_zap_makes_output_dir_world_writable(tmp_path):
    """ZAP's container runs as its own internal user, unrelated to the host
    UID that owns this bind-mounted directory -- a live run failed with
    'Permission denied' writing into it until this chmod was added."""
    out_dir = tmp_path / "zap"
    with patch("ingest.run_scanners.subprocess.run",
               side_effect=_zap_call_that_writes_report(out_dir, returncode=0)):
        run_zap("http://example.com", out_dir)

    assert (out_dir.stat().st_mode & 0o777) == 0o777


@pytest.mark.parametrize("returncode", [0, 1, 2])
def test_zap_nonzero_exit_with_a_report_is_not_an_error(tmp_path, returncode):
    """zap-baseline.py's exit code reflects alerts found (0=none, 1=warn,
    2=fail) -- that's success, not a process failure. A live run was crashing
    on this before `check=True` was removed, even when ZAP worked correctly."""
    out_dir = tmp_path / "zap"
    with patch("ingest.run_scanners.subprocess.run",
               side_effect=_zap_call_that_writes_report(out_dir, returncode=returncode)):
        run_zap("http://example.com", out_dir)  # must not raise for any of these

    assert (out_dir / "zap-report.json").exists()


def test_zap_missing_report_raises_even_with_a_zero_exit(tmp_path):
    """The only trustworthy failure signal is 'no report was produced at
    all' -- exit code alone isn't (see test above), so a clean-looking exit
    with no report must still be treated as a real failure."""
    out_dir = tmp_path / "zap"
    with patch("ingest.run_scanners.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        with pytest.raises(RuntimeError, match="did not produce a report"):
            run_zap("http://example.com", out_dir)
