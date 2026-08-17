"""Tickets API routes: check issue status and assign/unassign GitHub users."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from backend.routes.findings import load_findings_for_scan
from backend.schemas import TicketAssignRequest, TicketAssignResponse, TicketDetailResponse
from ticket.github_issues import assign_issue, get_issue_assignees, is_configured

router = APIRouter(tags=["tickets"])


@router.get("/api/scans/{scan_id}/findings/{finding_id}/ticket", response_model=TicketDetailResponse)
def get_finding_ticket_detail(scan_id: str, finding_id: str):
    findings = load_findings_for_scan(scan_id)
    matched = next((f for f in findings if f["finding_id"] == finding_id), None)
    if not matched:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found in scan '{scan_id}'.")

    configured = is_configured()
    issue_number = matched.get("github_issue_number")
    issue_url = matched.get("github_issue_url")

    if not issue_number:
        return TicketDetailResponse(
            issue_number=None,
            issue_url=None,
            github_configured=configured,
            assignees=[],
            error=None,
        )

    assignees = []
    error_msg = None
    if configured:
        try:
            assignees = get_issue_assignees(int(issue_number))
        except Exception as e:
            error_msg = f"Failed to fetch assignees: {str(e)}"

    return TicketDetailResponse(
        issue_number=int(issue_number),
        issue_url=issue_url,
        github_configured=configured,
        assignees=assignees,
        error=error_msg,
    )


@router.post("/api/tickets/{issue_number}/assign", response_model=TicketAssignResponse)
def assign_ticket(issue_number: int, req: TicketAssignRequest):
    if not is_configured():
        raise HTTPException(
            status_code=400,
            detail="GitHub integration is not configured. Set GITHUB_TOKEN and GITHUB_REPO in .env",
        )

    usernames = [u.strip() for u in req.usernames if u.strip()]
    if not usernames:
        raise HTTPException(status_code=422, detail="At least one GitHub username is required.")

    try:
        from github.GithubException import GithubException
    except ImportError:
        GithubException = Exception

    try:
        assign_issue(issue_number, usernames)
        return TicketAssignResponse(
            success=True,
            issue_number=issue_number,
            assignees=usernames,
            message=f"Issue #{issue_number} assigned to: {', '.join(usernames)}",
        )
    except GithubException as e:
        status = getattr(e, "status", 500)
        data = getattr(e, "data", str(e))
        raise HTTPException(
            status_code=400 if status in (404, 422) else 502,
            detail=f"GitHub API error ({status}): {data}. Ensure username is a repository collaborator.",
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/tickets/{issue_number}/unassign", response_model=TicketAssignResponse)
def unassign_ticket(issue_number: int):
    if not is_configured():
        raise HTTPException(
            status_code=400,
            detail="GitHub integration is not configured. Set GITHUB_TOKEN and GITHUB_REPO in .env",
        )

    try:
        from github.GithubException import GithubException
    except ImportError:
        GithubException = Exception

    try:
        assign_issue(issue_number, [])
        return TicketAssignResponse(
            success=True,
            issue_number=issue_number,
            assignees=[],
            message=f"Issue #{issue_number} unassigned.",
        )
    except GithubException as e:
        status = getattr(e, "status", 500)
        data = getattr(e, "data", str(e))
        raise HTTPException(status_code=502, detail=f"GitHub API error ({status}): {data}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
