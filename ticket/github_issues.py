"""Creates one GitHub Issue per top-ranked finding. No-ops cleanly (with a log
message, not an error) if GITHUB_TOKEN/GITHUB_REPO aren't set, so every earlier
phase and the dashboard work fine without them.

Idempotent across re-runs: the stable dedup_key set during dedup becomes a
GitHub label. Before creating an issue, checks a local ticket_state.json cache
and then the repo's existing issues for that label, skipping (or reusing) a
match instead of creating a duplicate.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from common.paths import ticket_state_path
from ingest.schema import Finding
from ticket.templates import issue_body, issue_labels, issue_title


def is_configured() -> bool:
    return bool(os.environ.get("GITHUB_TOKEN") and os.environ.get("GITHUB_REPO"))


def _load_state(scan_id: str) -> dict:
    path = ticket_state_path(scan_id)
    if path.exists():
        return json.loads(path.read_text())
    return {}


def _save_state(scan_id: str, state: dict) -> None:
    path = ticket_state_path(scan_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2))


def _dedup_label(f: Finding) -> str:
    return f"dedupkey:{(f.dedup_key or '')[:12]}"


def create_tickets(scan_id: str, findings: list[Finding], min_score: float, top_n: int) -> list[Finding]:
    if not is_configured():
        print("[ticket] GITHUB_TOKEN/GITHUB_REPO not set — skipping ticket creation.")
        return findings

    from github import Github

    candidates = sorted(
        (f for f in findings if not f.is_duplicate and not f.suppressed
         and (f.risk_score or 0) >= min_score),
        key=lambda f: -(f.risk_score or 0),
    )[:top_n]

    if not candidates:
        print(f"[ticket] No findings scored >= {min_score}; nothing to ticket.")
        return findings

    gh = Github(os.environ["GITHUB_TOKEN"])
    repo = gh.get_repo(os.environ["GITHUB_REPO"])
    state = _load_state(scan_id)

    for f in candidates:
        label = _dedup_label(f)

        if label in state:
            f.github_issue_number = state[label]["issue_number"]
            f.github_issue_url = state[label]["issue_url"]
            print(f"[ticket] Skipping (cached, issue #{f.github_issue_number}): {f.title[:50]}")
            continue

        existing = list(repo.get_issues(state="all", labels=[label]))
        if existing:
            issue = existing[0]
            f.github_issue_number = issue.number
            f.github_issue_url = issue.html_url
            state[label] = {"issue_number": issue.number, "issue_url": issue.html_url}
            print(f"[ticket] Skipping (already exists, issue #{issue.number}): {f.title[:50]}")
            continue

        issue = repo.create_issue(title=issue_title(f), body=issue_body(f), labels=issue_labels(f))
        f.github_issue_number = issue.number
        f.github_issue_url = issue.html_url
        f.ticket_created_at = datetime.now(timezone.utc)
        state[label] = {"issue_number": issue.number, "issue_url": issue.html_url}
        print(f"[ticket] Created issue #{issue.number}: {f.title[:50]}")

    _save_state(scan_id, state)
    return findings


if __name__ == "__main__":
    import click

    from common.config import scoring_config
    from common.paths import final_scored_path
    from ingest.schema import load_findings, save_findings

    @click.command()
    @click.option("--scan-id", required=True)
    def main(scan_id):
        cfg = scoring_config()["ticketing"]
        findings = load_findings(final_scored_path(scan_id))
        create_tickets(scan_id, findings, cfg["min_score_to_ticket"], cfg["top_n"])
        save_findings(findings, final_scored_path(scan_id))

    main()
