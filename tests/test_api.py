"""Tests for Threat-X FastAPI backend routes."""
import pytest
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)


def test_health():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_list_scans():
    response = client.get("/api/scans")
    assert response.status_code == 200
    data = response.json()
    assert "scans" in data
    assert isinstance(data["scans"], list)
    # Check that demo scan is detected if present
    scan_ids = [s["scan_id"] for s in data["scans"]]
    assert "demo" in scan_ids
    demo_scan = next(s for s in data["scans"] if s["scan_id"] == "demo")
    assert demo_scan["raw_count"] is not None
    assert demo_scan["final_count"] is not None


def test_get_scan_detail_valid():
    response = client.get("/api/scans/demo")
    assert response.status_code == 200
    data = response.json()
    assert data["scan_id"] == "demo"
    assert "metrics" in data
    assert data["metrics"].get("raw_count") == 14
    assert data["metrics"].get("final_count") in (9, 10)


def test_get_scan_detail_invalid():
    response = client.get("/api/scans/non_existent_scan_xyz")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_get_findings_valid():
    response = client.get("/api/scans/demo/findings")
    assert response.status_code == 200
    data = response.json()
    assert data["scan_id"] == "demo"
    assert data["total"] >= 10
    assert data["actionable_count"] in (9, 10)
    assert len(data["findings"]) == data["total"]

    # Validate schema & clean typing of findings
    for f in data["findings"]:
        assert isinstance(f["finding_id"], str)
        assert isinstance(f["title"], str)
        assert isinstance(f["host"], str)
        assert isinstance(f["cve_ids"], list)
        assert isinstance(f["is_duplicate"], bool)
        assert isinstance(f["suppressed"], bool)
        assert isinstance(f["in_kev"], bool)
        assert isinstance(f["contributing_scanners"], list)
        assert isinstance(f["contributing_label"], str)
        assert isinstance(f["raw_evidence"], dict)
        if f["score_breakdown"] is not None:
            assert isinstance(f["score_breakdown"], dict)
        if f["risk_score"] is not None:
            assert isinstance(f["risk_score"], (int, float))


def test_get_findings_invalid_scan():
    response = client.get("/api/scans/non_existent_scan_xyz/findings")
    assert response.status_code == 404


def test_get_ticket_detail():
    # Fetch demo findings to get a finding_id
    findings_resp = client.get("/api/scans/demo/findings")
    assert findings_resp.status_code == 200
    first_finding = findings_resp.json()["findings"][0]
    finding_id = first_finding["finding_id"]

    ticket_resp = client.get(f"/api/scans/demo/findings/{finding_id}/ticket")
    assert ticket_resp.status_code == 200
    ticket_data = ticket_resp.json()
    assert "github_configured" in ticket_data
    assert isinstance(ticket_data["assignees"], list)


def test_assign_ticket_validation():
    # Empty username list should return 422
    response = client.post("/api/tickets/1/assign", json={"usernames": []})
    assert response.status_code in (400, 422)


def test_launch_scan_validation():
    # Missing target_url and use_fixtures=False should return 422
    response = client.post("/api/scans/run", json={"scan_id": "test-invalid-run", "use_fixtures": False})
    assert response.status_code == 422


def test_get_scan_status_existing():
    response = client.get("/api/scans/status/demo")
    assert response.status_code == 200
    data = response.json()
    assert data["scan_id"] == "demo"
    assert data["status"] == "completed"
