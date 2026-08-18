"""Tests for the AI Remediation Assistant module (ai/remediation.py)."""
from unittest.mock import MagicMock, patch

import pytest
from ai.remediation import (
    RemediationGuidanceSchema,
    extract_vulnerability_context,
    format_guidance_markdown,
    generate_remediation_guidance,
)
from ingest.schema import Finding


@pytest.fixture
def sample_finding():
    return Finding(
        scan_id="test_scan",
        source_scanner="nuclei",
        host="web.example.com",
        port=443,
        service="https",
        title="Apache Log4j RCE (CVE-2021-44228)",
        description="Remote Code Execution vulnerability in Log4j2.",
        cve_ids=["CVE-2021-44228"],
        scanner_severity="critical",
        cvss_v3_score=10.0,
        epss_score=0.97,
        in_kev=True,
        raw_evidence={"matched_at": "https://web.example.com/login", "template_id": "cve-2021-44228"},
        risk_score=98.5,
        sla_tier="critical",
        github_issue_number=101,
        github_issue_url="https://github.com/example/repo/issues/101",
    )


def test_vulnerability_data_extraction(sample_finding):
    """2. Vulnerability data extraction."""
    ctx = extract_vulnerability_context(sample_finding)
    assert ctx["title"] == "Apache Log4j RCE (CVE-2021-44228)"
    assert ctx["host"] == "web.example.com"
    assert ctx["cve_ids"] == ["CVE-2021-44228"]
    assert ctx["port"] == 443
    assert ctx["risk_score"] == 98.5
    assert ctx["in_kev"] is True


def test_missing_cve_handling():
    """3. Missing CVE handling."""
    f = Finding(
        scan_id="test_scan",
        source_scanner="zap",
        host="app.example.com",
        title="Missing Anti-Clickjacking Header",
        scanner_severity="low",
        cve_ids=[],
    )
    ctx = extract_vulnerability_context(f)
    assert ctx["cve_ids"] == []
    assert ctx["title"] == "Missing Anti-Clickjacking Header"


def test_missing_software_version_and_evidence_handling():
    """4. Missing software version / evidence handling."""
    f = Finding(
        scan_id="test_scan",
        source_scanner="nmap",
        host="db.example.com",
        title="Open MySQL Port",
        scanner_severity="info",
        raw_evidence={},
    )
    ctx = extract_vulnerability_context(f)
    assert ctx["raw_evidence"] == {}
    assert ctx["port"] is None
    assert ctx["service"] is None


def test_missing_gemini_api_key_handling(sample_finding):
    """5. Missing GEMINI_API_KEY handling."""
    with patch("ai.remediation.is_available", return_value=False):
        res = generate_remediation_guidance(sample_finding)
        assert res["success"] is False
        assert res["error_type"] == "missing_api_key"
        assert "GEMINI_API_KEY" in res["message"]


def test_ai_api_failure_handling(sample_finding):
    """6. AI API failure handling."""
    with patch("ai.remediation.is_available", return_value=True), patch(
        "ai.remediation.generate_content", side_effect=Exception("API connection timeout")
    ):
        res = generate_remediation_guidance(sample_finding)
        assert res["success"] is False
        assert res["error_type"] == "api_error"
        assert "API connection timeout" in res["message"]


def test_successful_ai_response_handling(sample_finding):
    """7. Successful AI response handling with mocked Gemini API."""
    mock_schema = RemediationGuidanceSchema(
        vulnerability_summary="Log4j RCE vulnerability allows remote attacker to execute arbitrary code.",
        why_it_matters="Critical risk of full server compromise.",
        root_cause="Vulnerable Log4j library version < 2.17.0 parsing JNDI lookup strings.",
        recommended_fix="Upgrade log4j2 to version 2.17.1 or higher.",
        step_by_step_resolution=[
            "Identify all Java artifacts using log4j-core.",
            "Upgrade dependency to log4j-core 2.17.1.",
            "Rebuild and restart application service.",
            "Verify version with scanner.",
        ],
        commands_and_config="Example command (verify before execution):\nmvn dependency:tree | grep log4j",
        verification="Re-run Nuclei scan against https://web.example.com to confirm fix.",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
    )

    mock_resp = MagicMock()
    mock_resp.text = mock_schema.model_dump_json()

    with patch("ai.remediation.is_available", return_value=True), patch(
        "ai.remediation.generate_content", return_value=mock_resp
    ):
        res = generate_remediation_guidance(sample_finding)
        assert res["success"] is True
        assert res["guidance"]["vulnerability_summary"].startswith("Log4j RCE")
        assert "### 1. Vulnerability Summary" in res["markdown"]
        assert "### 5. Step-by-Step Resolution" in res["markdown"]
        assert "### 8. References" in res["markdown"]


def test_remediation_prompt_generation(sample_finding):
    """1. Remediation prompt generation."""
    with patch("ai.remediation.is_available", return_value=True), patch(
        "ai.remediation.generate_content"
    ) as mock_gen:
        mock_resp = MagicMock()
        mock_resp.text = RemediationGuidanceSchema(
            vulnerability_summary="Summary",
            why_it_matters="Impact",
            root_cause="Cause",
            recommended_fix="Fix",
            step_by_step_resolution=["Step 1"],
            commands_and_config="Example: echo test",
            verification="Verify",
            references=[],
        ).model_dump_json()
        mock_gen.return_value = mock_resp

        generate_remediation_guidance(sample_finding)

        assert mock_gen.called
        call_kwargs = mock_gen.call_args.kwargs
        contents = call_kwargs["contents"]
        assert "Apache Log4j RCE" in contents
        assert "CVE-2021-44228" in contents
        assert "web.example.com" in contents


def test_safety_guarantee_no_command_execution(sample_finding):
    """9. Ensure AI remediation does NOT execute commands automatically."""
    mock_schema = RemediationGuidanceSchema(
        vulnerability_summary="Summary",
        why_it_matters="Impact",
        root_cause="Cause",
        recommended_fix="Fix",
        step_by_step_resolution=["Step 1"],
        commands_and_config="EXAMPLE ONLY: sudo systemctl restart nginx",
        verification="Check status",
        references=[],
    )
    mock_resp = MagicMock()
    mock_resp.text = mock_schema.model_dump_json()

    with patch("ai.remediation.is_available", return_value=True), patch(
        "ai.remediation.generate_content", return_value=mock_resp
    ), patch("subprocess.run") as mock_sub, patch("os.system") as mock_sys:
        res = generate_remediation_guidance(sample_finding)
        assert res["success"] is True
        # Verify no system commands were executed during remediation generation
        assert not mock_sub.called
        assert not mock_sys.called


def test_dashboard_integration_format():
    """8. Dashboard integration structure."""
    dummy_dict = {
        "vulnerability_summary": "Test summary",
        "why_it_matters": "Test impact",
        "root_cause": "Test root cause",
        "recommended_fix": "Test fix",
        "step_by_step_resolution": ["Check version", "Update package"],
        "commands_and_config": "EXAMPLE: apt-get update",
        "verification": "Re-run scan",
        "references": ["https://example.com/ref"],
    }
    md = format_guidance_markdown(dummy_dict)
    for section_header in [
        "### 1. Vulnerability Summary",
        "### 2. Why It Matters",
        "### 3. Root Cause",
        "### 4. Recommended Fix",
        "### 5. Step-by-Step Resolution",
        "### 6. Commands / Configuration",
        "### 7. Verification",
        "### 8. References",
    ]:
        assert section_header in md
