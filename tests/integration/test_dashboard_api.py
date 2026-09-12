from fastapi.testclient import TestClient

from app.main import app
from api.events import broadcast_security_event


def test_cors_headers_allowed() -> None:
    client = TestClient(app)
    response = client.options(
        "/v1/health",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:3000"


def test_recent_events_endpoint() -> None:
    client = TestClient(app)
    broadcast_security_event({
        "event_id": "test-evt-001",
        "event_type": "prompt.scan",
        "decision": "ALLOW",
        "risk_score": 0,
        "reason_codes": ["PROMPT_CLEAN"],
    })
    response = client.get("/v1/security/events/recent")
    assert response.status_code == 200
    data = response.json()
    assert "events" in data
    assert any(e.get("event_id") == "test-evt-001" for e in data["events"])


def test_prompt_scan_broadcasts_event() -> None:
    client = TestClient(app)
    response = client.post(
        "/v1/security/prompt/scan",
        json={"prompt": "Summarize safe project milestones."},
    )
    assert response.status_code == 200
    event_id = response.json()["event_id"]

    # Check recent events contains the scanned event
    recent = client.get("/v1/security/events/recent")
    assert recent.status_code == 200
    assert any(e.get("event_id") == event_id for e in recent.json()["events"])


def test_dashboard_static_mount() -> None:
    client = TestClient(app)
    response = client.get("/dashboard/")
    assert response.status_code == 200
    assert "AI SECURITY" in response.text

