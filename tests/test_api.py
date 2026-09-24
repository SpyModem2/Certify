import base64
from pathlib import Path

from fastapi.testclient import TestClient

from certify.api import create_app
from certify.config import Settings
from certify.database import Database
from certify.security import hash_password
from certify.security import totp


def app_client(tmp_path: Path) -> TestClient:
    settings = Settings(tmp_path, "test-secret-that-is-long-enough-123", 30, ("testserver",), False)
    app = create_app(settings)
    database = Database(tmp_path / "certify.db")
    database.initialize()
    with database.connect() as connection:
        connection.execute(
            "INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
            ("admin", hash_password("Correct horse battery staple!7"), "admin"),
        )
    return TestClient(app)


def test_login_and_certificate_request(tmp_path: Path) -> None:
    with app_client(tmp_path) as client:
        response = client.post("/api/v1/auth/login", json={"username": "admin", "password": "Correct horse battery staple!7"})
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
        assert client.get("/health").json() == {"status": "ok", "version": "0.1.0"}
        page = client.get("/", headers={"Accept-Language": "de"})
        assert "Zertifikatsverwaltung" in page.text
        assert "default-src 'self'" in page.headers["content-security-policy"]
        assert client.get("/assets/app.css").status_code == 200
        assert client.get("/assets/app.js").status_code == 200
        assert '<dialog id="modal"><div class="modal-card">' in page.text


def test_frontend_supporting_inventory_endpoints(tmp_path: Path) -> None:
    with app_client(tmp_path) as client:
        login = client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "Correct horse battery staple!7"},
        )
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

        me = client.get("/api/v1/users/me", headers=headers)
        assert me.status_code == 200
        assert me.json()["username"] == "admin"
        assert me.json()["notify_level"] == "errors"

        users = client.get("/api/v1/users", headers=headers)
        assert users.status_code == 200
        assert users.json()[0]["role"] == "admin"

        created = client.post(
            "/api/v1/targets",
            headers=headers,
            json={
                "name": "frontend-target",
                "adapter": "linux-ssh",
                "hostname": "web.example.test",
                "config": {"path": "/etc/pki"},
                "credentials": {"username": "deploy"},
            },
        )
        assert created.status_code == 201
        targets = client.get("/api/v1/targets", headers=headers)
        assert targets.json()[0]["config"] == {"path": "/etc/pki"}
        assert "credentials" not in targets.json()[0]

        entries = client.get("/api/v1/audit", headers=headers)
        assert entries.status_code == 200
        assert entries.json()[0]["action"] == "target.create"
        assert isinstance(entries.json()[0]["details"], dict)


def test_certificate_can_be_assigned_to_multiple_targets(tmp_path: Path) -> None:
    with app_client(tmp_path) as client:
        login = client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "Correct horse battery staple!7"},
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
            json={"username": "admin", "password": "Correct horse battery staple!7"},
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


def test_password_change_enforces_history(tmp_path: Path) -> None:
    with app_client(tmp_path) as client:
        login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "Correct horse battery staple!7"})
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        changed = client.put("/api/v1/users/me/password", headers=headers, json={"current_password": "Correct horse battery staple!7", "new_password": "An even better Password!8"})
        assert changed.status_code == 204
        reused = client.put("/api/v1/users/me/password", headers=headers, json={"current_password": "An even better Password!8", "new_password": "Correct horse battery staple!7"})
        assert reused.status_code == 422
        assert "last 20" in reused.json()["detail"]


def test_api_key_inherits_role_and_can_be_read_only(tmp_path: Path) -> None:
    with app_client(tmp_path) as client:
        login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "Correct horse battery staple!7"})
        session_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        created = client.post("/api/v1/api-keys", headers=session_headers, json={"name": "reporting", "scope": "read"})
        assert created.status_code == 201
        api_headers = {"Authorization": f"Bearer {created.json()['key']}"}
        assert client.get("/api/v1/certificates", headers=api_headers).status_code == 200
        denied = client.post("/api/v1/targets", headers=api_headers, json={"name": "blocked", "adapter": "linux-ssh"})
        assert denied.status_code == 403
        key_id = created.json()["id"]
        assert client.delete(f"/api/v1/api-keys/{key_id}", headers=session_headers).status_code == 204
        assert client.get("/api/v1/certificates", headers=api_headers).status_code == 401


def test_user_identity_email_and_totp_lifecycle(tmp_path: Path) -> None:
    with app_client(tmp_path) as client:
        login = client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "Correct horse battery staple!7"},
        )
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

        incomplete = client.post(
            "/api/v1/users",
            headers=headers,
            json={"username": "missing", "password": "A sufficiently Strong!9", "role": "operator"},
        )
        assert incomplete.status_code == 422
        created = client.post(
            "/api/v1/users",
            headers=headers,
            json={
                "username": "alice",
                "first_name": "Alice",
                "last_name": "Example",
                "email": "alice@example.test",
                "password": "A sufficiently Strong!9",
                "role": "operator",
            },
        )
        assert created.status_code == 201
        assert created.json()["first_name"] == "Alice"

        renamed = client.put(
            "/api/v1/users/me/name",
            headers=headers,
            json={"first_name": "Ada", "last_name": "Admin"},
        )
        assert renamed.json() == {"first_name": "Ada", "last_name": "Admin"}
        assert client.get("/api/v1/users/me", headers=headers).json()["last_name"] == "Admin"

        updated = client.put(
            f"/api/v1/users/{created.json()['id']}",
            headers=headers,
            json={
                "first_name": "Alicia",
                "last_name": "Example-Smith",
                "email": "alicia@example.test",
                "role": "auditor",
                "active": False,
            },
        )
        assert updated.status_code == 200
        assert updated.json()["first_name"] == "Alicia"
        alice = next(user for user in client.get("/api/v1/users", headers=headers).json() if user["username"] == "alice")
        assert alice["role"] == "auditor"
        assert alice["active"] == 0

        changed = client.put(
            "/api/v1/users/me/email", headers=headers, json={"email": "admin@example.test"}
        )
        assert changed.json() == {"email": "admin@example.test"}
        assert client.get("/api/v1/users/me", headers=headers).json()["email"] == "admin@example.test"

        setup = client.post("/api/v1/users/me/totp/setup", headers=headers)
        assert setup.status_code == 200
        assert setup.json()["otpauth_uri"].startswith("otpauth://totp/Certify%3Aadmin?")
        assert setup.json()["qr_code"].startswith("data:image/svg+xml;base64,")
        assert b"<svg" in base64.b64decode(setup.json()["qr_code"].split(",", 1)[1])

        cancelled = client.delete("/api/v1/users/me/totp/setup", headers=headers)
        assert cancelled.status_code == 204
        cancelled_confirmation = client.post(
            "/api/v1/users/me/totp/confirm",
            headers=headers,
            json={"code": totp(setup.json()["secret"])},
        )
        assert cancelled_confirmation.status_code == 409

        setup = client.post("/api/v1/users/me/totp/setup", headers=headers)
        confirmation = client.post(
            "/api/v1/users/me/totp/confirm",
            headers=headers,
            json={"code": totp(setup.json()["secret"])},
        )
        assert confirmation.status_code == 204
        assert client.get("/api/v1/users/me", headers=headers).json()["totp_enabled"] == 1

        replacement = client.post(
            "/api/v1/users/me/totp/setup",
            headers=headers,
            json={"current_code": totp(setup.json()["secret"])},
        )
        assert replacement.status_code == 200
        assert replacement.json()["secret"] != setup.json()["secret"]
        assert client.post(
            "/api/v1/users/me/totp/confirm",
            headers=headers,
            json={"code": totp(replacement.json()["secret"])},
        ).status_code == 204

        without_code = client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "Correct horse battery staple!7"},
        )
        assert without_code.status_code == 401
        reset = client.delete("/api/v1/users/1/totp", headers=headers)
        assert reset.status_code == 204
        assert client.get("/api/v1/users/me", headers=headers).json()["totp_enabled"] == 0


def test_failed_login_audit_records_specific_reason(tmp_path: Path) -> None:
    with app_client(tmp_path) as client:
        assert client.post("/api/v1/auth/login", json={
            "username": "admin", "password": "wrong"
        }).status_code == 401
        with client.app.state.database.connect() as connection:
            details = connection.execute(
                "SELECT details FROM audit_log WHERE action='auth.login.failed' ORDER BY sequence DESC"
            ).fetchone()["details"]
        assert '"reason": "invalid_password"' in details


def test_expired_password_only_allows_password_change(tmp_path: Path) -> None:
    settings = Settings(tmp_path, "test-secret-that-is-long-enough-123", 30, ("testserver",), False,
                        password_max_age_days=30)
    app = create_app(settings)
    app.state.database.initialize()
    with app.state.database.connect() as connection:
        connection.execute(
            "INSERT INTO users(username,password_hash,role,password_changed_at) VALUES(?,?,?,'2020-01-01')",
            ("admin", hash_password("Correct horse battery staple!7"), "admin"),
        )
    with TestClient(app) as client:
        login = client.post("/api/v1/auth/login", json={
            "username": "admin", "password": "Correct horse battery staple!7"
        })
        assert login.json()["password_change_required"] is True
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        assert client.get("/api/v1/certificates", headers=headers).status_code == 403
        assert client.put("/api/v1/users/me/password", headers=headers, json={
            "current_password": "Correct horse battery staple!7",
            "new_password": "An even better Password!8",
        }).status_code == 204
        assert client.get("/api/v1/certificates", headers=headers).status_code == 200
