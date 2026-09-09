from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_output_scan_releases_clean_output() -> None:
    response = client.post("/v1/security/output/scan", json={"output": "Safe response."})

    assert response.status_code == 200
    body = response.json()
    assert body["decision"]["decision"] == "ALLOW"
    assert body["released_output"] == "Safe response."


def test_output_scan_redacts_pii() -> None:
    response = client.post(
        "/v1/security/output/scan",
        json={"output": "Email me at jane@example.com"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["decision"]["decision"] == "SANITIZE"
    assert "jane@example.com" not in body["released_output"]


def test_output_scan_blocks_secret_and_rejects_extra_fields() -> None:
    blocked = client.post(
        "/v1/security/output/scan",
        json={"output": "api_key=AbCDef0123456789xyzXYZ"},
    )
    invalid = client.post(
        "/v1/security/output/scan",
        json={"output": "safe", "trust_level": "trusted"},
    )

    assert blocked.status_code == 200
    assert blocked.json()["decision"]["decision"] == "DENY"
    assert blocked.json()["released_output"] is None
    assert invalid.status_code == 422
