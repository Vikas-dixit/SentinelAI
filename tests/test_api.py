from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_high_risk_event():
    response = client.post(
        "/analyze",
        json={
            "event_type": "login",
            "source_ip": "192.168.1.20",
            "username": "admin",
            "success": False,
            "failed_attempts": 12,
            "destination_port": 22,
            "process_name": "powershell.exe",
            "bytes_sent": 65000000,
            "destination_ip": "203.0.113.50",
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] == 100
    assert data["severity"] == "critical"
    assert "Possible brute-force login activity" in data["alerts"]


def test_clean_event():
    response = client.post(
        "/analyze",
        json={
            "event_type": "connection",
            "source_ip": "192.168.1.5",
            "destination_port": 443,
            "bytes_sent": 1024,
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] == 0
    assert data["severity"] == "informational"
