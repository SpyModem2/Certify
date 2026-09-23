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


def test_certificate_can_be_assigned_to_multiple_targets(tmp_path: Path) -> None:
    with app_client(tmp_path) as client:
        login = client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "correct horse battery staple"},
        )
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        target_ids = []
        for name in ("web-one", "web-two"):
            response = client.post(
                "/api/v1/targets",
                headers=headers,
                json={"name": name, "adapter": "linux-ssh", "hostname": f"{name}.example.test"},
            )
            assert response.status_code == 201
            target_ids.append(response.json()["id"])

        response = client.post(
            "/api/v1/certificates",
            headers=headers,
            json={
                "common_name": "*.example.test",
                "sans": ["example.test"],
                "acme_directory": "https://acme.example.test/directory",
                "challenge": "dns-01",
                "target_ids": target_ids,
            },
        )
        assert response.status_code == 201
        certificate_id = response.json()["id"]
        certificates = client.get("/api/v1/certificates", headers=headers).json()
        assert [target["name"] for target in certificates[0]["targets"]] == ["web-one", "web-two"]

        response = client.put(
            f"/api/v1/certificates/{certificate_id}/targets",
            headers=headers,
            json={"target_ids": [target_ids[1]]},
        )
        assert response.json() == {"target_ids": [target_ids[1]]}


def test_certificate_rejects_unknown_target(tmp_path: Path) -> None:
    with app_client(tmp_path) as client:
        login = client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "correct horse battery staple"},
        )
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        response = client.post(
            "/api/v1/certificates",
            headers=headers,
            json={
                "common_name": "*.example.test",
                "acme_directory": "https://acme.example.test/directory",
                "challenge": "dns-01",
                "target_ids": [999],
            },
        )
        assert response.status_code == 422
