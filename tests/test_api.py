from pathlib import Path

from fastapi.testclient import TestClient

from certify.api import create_app
from certify.config import Settings
from certify.database import Database
from certify.security import hash_password


def app_client(tmp_path: Path) -> TestClient:
    settings = Settings(tmp_path, "test-secret-that-is-long-enough-123", 30, ("testserver",), False)
    app = create_app(settings)
    database = Database(tmp_path / "certify.db")
    database.initialize()
    with database.connect() as connection:
        connection.execute(
            "INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
            ("admin", hash_password("correct horse battery staple"), "admin"),
        )
    return TestClient(app)


def test_login_and_certificate_request(tmp_path: Path) -> None:
    with app_client(tmp_path) as client:
        response = client.post("/api/v1/auth/login", json={"username": "admin", "password": "correct horse battery staple"})
        assert response.status_code == 200
        headers = {"Authorization": f"Bearer {response.json()['access_token']}"}
        response = client.post(
            "/api/v1/certificates",
            headers=headers,
            json={
                "common_name": "example.test",
                "sans": ["www.example.test"],
                "acme_directory": "https://acme.example.test/directory",
                "challenge": "dns-01",
                "key_mode": "csr",
                "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----",
            },
        )
        assert response.status_code == 201
        assert response.json()["status"] == "pending"


def test_health_and_localized_page(tmp_path: Path) -> None:
    with app_client(tmp_path) as client:
        assert client.get("/health").json() == {"status": "ok"}
        assert "Zertifikatsverwaltung" in client.get("/", headers={"Accept-Language": "de"}).text
