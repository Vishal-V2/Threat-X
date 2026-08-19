"""AI-Powered Remediation Guidance module for Threat-X.

Analyzes normalized vulnerability findings and generates structured, step-by-step
remediation guidance for security analysts and developers.

SAFETY GUARANTEE:
This module is strictly advisory. It never executes commands, connects to scanned targets,
modifies servers, or performs autonomous fixing actions.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Union

import pandas as pd
from google.genai import types
from pydantic import BaseModel, Field

from ai.client import DEFAULT_MODEL, generate_content, is_available
from ingest.schema import Finding


class RemediationGuidanceSchema(BaseModel):
    vulnerability_summary: str = Field(
        description="Brief explanation of what the vulnerability is."
    )
    why_it_matters: str = Field(
        description="Security impact in simple technical language."
    )
    root_cause: str = Field(
        description="What configuration, software version, service, or code is causing the vulnerability."
    )
    recommended_fix: str = Field(
        description="High-level recommended remediation strategy."
    )
    step_by_step_resolution: List[str] = Field(
        description="Clear numbered resolution steps (e.g. 1. Check version, 2. Upgrade, 3. Restart, 4. Verify, 5. Rescan)."
    )
    commands_and_config: str = Field(
        description="Example commands or configuration changes. MUST explicitly note these are examples that require verification before execution."
    )
    verification: str = Field(
        description="Instructions explaining how the developer can verify the vulnerability has been resolved."
    )
    references: List[str] = Field(
        default_factory=list,
        description="Reliable reference links/sources provided in finding or official NVD/vendor links. Do not fabricate references."
    )


_SYSTEM_PROMPT = (
    "You are the Threat-X AI Remediation Assistant. Your role is purely advisory.\n"
    "You analyze security findings and provide clear, structured remediation guidance to help security analysts and developers fix vulnerabilities.\n\n"
    "CRITICAL SAFETY & OPERATIONAL DIRECTIVES:\n"
    "1. You are an advisory assistant ONLY. You MUST NOT execute commands, connect to target systems, modify servers, change databases, deploy patches, close tickets, or run exploits.\n"
    "2. Provide ONLY guidance and instructions.\n"
    "3. All commands or configuration snippets MUST be explicitly marked as EXAMPLES and MUST warn the user to verify them before execution.\n"
    "4. Rely ONLY on the facts provided in the finding details. Do not invent software versions, CVEs, or evidence that were not provided.\n"
    "5. If CVE IDs, software versions, or scanner evidence are missing, explicitly note that they were not present in the finding context rather than hallucinating them.\n"
    "6. Do NOT invent fake reference URLs. If no reliable references exist in the context, leave the references list empty or cite official vendor/NVD resources matching the exact CVE.\n"
)


def _clean_val(val: Any) -> Any:
    """Helper to clean pandas NaN and missing markers into None."""
    if val is None:
        return None
    if isinstance(val, float) and pd.isna(val):
        return None
    if str(val).strip().lower() in ("nan", "<na>", "none"):
        return None
    return val


def _extract_field(data: Union[Finding, Dict[str, Any], Any], key: str, default: Any = None) -> Any:
    """Safely extracts a field from a Finding object, dictionary, or pandas Series."""
    if isinstance(data, Finding):
        val = getattr(data, key, default)
    elif isinstance(data, dict):
        val = data.get(key, default)
    elif hasattr(data, "__getitem__"):
        try:
            val = data[key]
        except (KeyError, IndexError, TypeError):
            val = default
    else:
        val = getattr(data, key, default)

    cleaned = _clean_val(val)
    return cleaned if cleaned is not None else default


def extract_vulnerability_context(finding: Union[Finding, Dict[str, Any], Any]) -> Dict[str, Any]:
    """Extracts structured vulnerability facts from a finding object or row dict."""
    cve_ids_raw = _extract_field(finding, "cve_ids", [])
    if isinstance(cve_ids_raw, str):
        try:
            cve_ids_raw = json.loads(cve_ids_raw)
        except Exception:
            cve_ids_raw = [cve_ids_raw] if cve_ids_raw.strip() else []
    cve_ids = [str(c).upper() for c in cve_ids_raw if c] if isinstance(cve_ids_raw, list) else []

    contributing_raw = _extract_field(finding, "contributing_scanners", [])
    if isinstance(contributing_raw, str):
        try:
            contributing_raw = json.loads(contributing_raw)
        except Exception:
            contributing_raw = [contributing_raw] if contributing_raw.strip() else []
    
    source_scanner = _extract_field(finding, "source_scanner", "Unknown")
    scanners = contributing_raw if isinstance(contributing_raw, list) and contributing_raw else [source_scanner]

    evidence_raw = _extract_field(finding, "raw_evidence", {})
    if isinstance(evidence_raw, str):
        try:
            evidence_raw = json.loads(evidence_raw)
        except Exception:
            evidence_raw = {"text": evidence_raw}
    if not isinstance(evidence_raw, dict):
        evidence_raw = {"evidence": str(evidence_raw)}

    return {
        "finding_id": str(_extract_field(finding, "finding_id", "N/A")),
        "title": str(_extract_field(finding, "title", "Untitled Vulnerability")),
        "description": _extract_field(finding, "description", None),
        "host": str(_extract_field(finding, "host", "Unknown Host")),
        "port": _extract_field(finding, "port", None),
        "service": _extract_field(finding, "service", None),
        "cve_ids": cve_ids,
        "scanner_severity": str(_extract_field(finding, "scanner_severity", "unknown")),
        "sla_tier": _extract_field(finding, "sla_tier", None),
        "risk_score": _extract_field(finding, "risk_score", None),
        "cvss_v3_score": _extract_field(finding, "cvss_v3_score", None),
        "epss_score": _extract_field(finding, "epss_score", None),
        "in_kev": bool(_extract_field(finding, "in_kev", False)),
        "scanners": scanners,
        "raw_evidence": evidence_raw,
        "github_issue_number": _extract_field(finding, "github_issue_number", None),
        "github_issue_url": _extract_field(finding, "github_issue_url", None),
    }


def format_guidance_markdown(guidance: Union[RemediationGuidanceSchema, Dict[str, Any]]) -> str:
    """Formats structured AI remediation guidance into the required 8-section Markdown format."""
    if isinstance(guidance, RemediationGuidanceSchema):
        data = guidance.model_dump()
    else:
        data = guidance

    summary = data.get("vulnerability_summary", "").strip()
    why_matters = data.get("why_it_matters", "").strip()
    root_cause = data.get("root_cause", "").strip()
    recommended_fix = data.get("recommended_fix", "").strip()
    steps = data.get("step_by_step_resolution", [])
    commands = data.get("commands_and_config", "").strip()
    verification = data.get("verification", "").strip()
    refs = data.get("references", [])

    steps_md = "\n".join(f"{i+1}. {step.strip()}" for i, step in enumerate(steps) if step.strip())
    if not steps_md:
        steps_md = "1. Consult component documentation and vendor advisories for resolution steps."

    refs_md = "\n".join(f"- {ref.strip()}" for ref in refs if ref.strip())
    if not refs_md:
        refs_md = "None available in finding context."

    # Bold inline labels, not markdown headers (###) — this renders inside a
    # compact answer panel (the Fix tab), and h3 there would inherit the
    # page's own big section-header styling (border-bottom, large spacing)
    # meant for top-level sections like "Ranked action list", making an AI
    # answer look like a giant page section instead of part of the panel.
    return f"""**1. Vulnerability Summary**
{summary}

**2. Why It Matters**
{why_matters}

**3. Root Cause**
{root_cause}

**4. Recommended Fix**
{recommended_fix}

**5. Step-by-Step Resolution**
{steps_md}

**6. Commands / Configuration**
{commands}

**7. Verification**
{verification}

**8. References**
{refs_md}
"""


def generate_remediation_guidance(finding: Union[Finding, Dict[str, Any], Any]) -> Dict[str, Any]:
    """Generates AI remediation guidance for a given Threat-X finding.

    Returns dict containing:
      - success (bool)
      - error_type (str or None)
      - message (str)
      - guidance (dict or None)
      - markdown (str)
    """
    if not is_available():
        msg = "AI remediation guidance is unavailable because GEMINI_API_KEY is not configured."
        return {
            "success": False,
            "error_type": "missing_api_key",
            "message": msg,
            "guidance": None,
            "markdown": f"⚠️ **{msg}**\n\nPlease set `GEMINI_API_KEY` in your `.env` file to enable AI remediation recommendations.",
        }

    ctx = extract_vulnerability_context(finding)

    prompt_lines = [
        f"Analyze the following security finding and generate step-by-step remediation guidance:\n",
        f"- Title: {ctx['title']}",
        f"- Affected Host: {ctx['host']}",
        f"- Affected Port: {ctx['port'] or 'Not specified'}",
        f"- Affected Service: {ctx['service'] or 'Not specified'}",
        f"- CVE ID(s): {', '.join(ctx['cve_ids']) if ctx['cve_ids'] else 'None reported in scan'}",
        f"- Severity / SLA Tier: {ctx['sla_tier'] or ctx['scanner_severity']}",
        f"- Risk Score: {f'{ctx['risk_score']:.1f}/100' if ctx['risk_score'] is not None else 'Unscored'}",
        f"- CVSS v3 Score: {ctx['cvss_v3_score'] if ctx['cvss_v3_score'] is not None else 'N/A'}",
        f"- EPSS Score: {ctx['epss_score'] if ctx['epss_score'] is not None else 'N/A'}",
        f"- CISA KEV (Known Exploited Vulnerability): {'YES (Confirmed active exploitation)' if ctx['in_kev'] else 'No'}",
        f"- Detecting Scanner(s): {', '.join(ctx['scanners'])}",
        f"- Existing GitHub Ticket: {ctx['github_issue_url'] or 'None'}",
    ]

    if ctx["description"]:
        prompt_lines.append(f"- Vulnerability Description: {ctx['description']}")

    evidence_str = json.dumps(ctx["raw_evidence"], indent=2)
    if len(evidence_str) > 1500:
        evidence_str = evidence_str[:1500] + "... (truncated)"
    prompt_lines.append(f"- Scanner Evidence:\n{evidence_str}\n")

    prompt_lines.append(
        "Generate structured guidance adhering strictly to the response schema. "
        "Under commands_and_config, explicitly state that commands are EXAMPLES only and MUST be manually verified before execution."
    )

    try:
        response = generate_content(
            model=DEFAULT_MODEL,
            contents="\n".join(prompt_lines),
            config=types.GenerateContentConfig(
                system_instruction=_SYSTEM_PROMPT,
                response_mime_type="application/json",
                response_schema=RemediationGuidanceSchema,
            ),
        )

        text = (response.text or "").strip()
        if not text:
            raise ValueError("Gemini API returned an empty response.")

        guidance_obj = RemediationGuidanceSchema.model_validate_json(text)
        guidance_dict = guidance_obj.model_dump()
        markdown_text = format_guidance_markdown(guidance_obj)

        return {
            "success": True,
            "error_type": None,
            "message": "AI remediation guidance generated successfully.",
            "guidance": guidance_dict,
            "markdown": markdown_text,
        }

    except Exception as e:
        err_msg = f"Failed to generate AI remediation guidance: {str(e)}"
        return {
            "success": False,
            "error_type": "api_error",
            "message": err_msg,
            "guidance": None,
            "markdown": f"⚠️ **AI Remediation Unavailable:** {err_msg}",
        }
