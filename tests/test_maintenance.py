import base64
import sqlite3
from pathlib import Path

import pytest

from certify.maintenance import BackupError, MAGIC, create_automatic_backup, create_backup, restore_backup
from test_api import app_client


def test_encrypted_backup_round_trip_and_wrong_password(tmp_path: Path) -> None:
    database = tmp_path / "certify.db"
    connection = sqlite3.connect(database)
    for table in ("users", "audit_log", "certificates"):
        connection.execute(f"CREATE TABLE {table}(id INTEGER)")
    connection.execute("INSERT INTO users VALUES(42)")
    connection.commit()
    connection.close()
    payload, encrypted = create_backup(database, "a sufficiently long password")
    assert encrypted is True and payload.startswith(MAGIC)
    with pytest.raises(BackupError, match="incorrect password"):
        restore_backup(database, payload, "the wrong password")
    with sqlite3.connect(database) as connection:
        connection.execute("DELETE FROM users")
        connection.commit()
    restore_backup(database, payload, "a sufficiently long password")
    with sqlite3.connect(database) as restored:
        assert restored.execute("SELECT id FROM users").fetchone() == (42,)


def test_automatic_backup_is_always_encrypted_and_retained(tmp_path: Path) -> None:
    database = tmp_path / "certify.db"
    connection = sqlite3.connect(database)
    for table in ("users", "audit_log", "certificates"):
        connection.execute(f"CREATE TABLE {table}(id INTEGER)")
    connection.close()
    with pytest.raises(BackupError, match="require a password"):
        create_automatic_backup(database, tmp_path / "backups", "")
    created = create_automatic_backup(database, tmp_path / "backups", "a sufficiently long password")
    assert created.read_bytes().startswith(MAGIC)
    assert created.stat().st_mode & 0o777 == 0o600


def test_admin_can_download_restore_and_request_update(tmp_path: Path) -> None:
    with app_client(tmp_path) as client:
        login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "Correct horse battery staple!7"})
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        backup = client.post("/api/v1/maintenance/backup", headers=headers, json={"password": "backup password!123"})
        assert backup.status_code == 200 and backup.content.startswith(MAGIC)
        restored = client.post("/api/v1/maintenance/restore", headers=headers, json={
            "password": "backup password!123", "data": base64.b64encode(backup.content).decode(),
        })
        assert restored.json() == {"status": "restored"}
        update = client.post("/api/v1/maintenance/update", headers=headers, json={})
        assert update.status_code == 202
        assert (tmp_path / "update.request").is_file()
        assert client.get("/api/v1/maintenance", headers=headers).json()["update_status"] == "queued"


def test_admin_can_configure_and_download_automatic_backup(tmp_path: Path) -> None:
    with app_client(tmp_path) as client:
        login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "Correct horse battery staple!7"})
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        rejected = client.put("/api/v1/maintenance/backup/automatic", headers=headers, json={"enabled": True})
        assert rejected.status_code == 422
        configured = client.put("/api/v1/maintenance/backup/automatic", headers=headers, json={
            "enabled": True, "interval_hours": 24, "retention": 3, "password": "automatic backup passphrase",
        })
        assert configured.status_code == 200
        status = client.get("/api/v1/maintenance", headers=headers).json()
        assert status["automatic_backup"] == {"enabled": True, "interval_hours": 24, "retention": 3}
        assert len(status["backups"]) == 1
        downloaded = client.get(f"/api/v1/maintenance/backups/{status['backups'][0]['name']}", headers=headers)
        assert downloaded.status_code == 200
        assert downloaded.content.startswith(MAGIC)
        config = (tmp_path / "automatic-backup.json").read_text()
        assert "automatic backup passphrase" not in config


def test_admin_can_request_and_read_update_check(tmp_path: Path) -> None:
    with app_client(tmp_path) as client:
        login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "Correct horse battery staple!7"})
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        response = client.post("/api/v1/maintenance/update/check", headers=headers, json={})
        assert response.status_code == 202
        assert (tmp_path / "update-check.request").is_file()
        assert client.get("/api/v1/maintenance", headers=headers).json()["check_status"] == "queued"

        (tmp_path / "update-check.request").unlink()
        (tmp_path / "update-check-status.json").write_text(
            '{"check_status":"success","update_available":false,'
            '"latest_version":"0.1.0","check_message":"Die installierte Version ist aktuell."}'
        )
        status_response = client.get("/api/v1/maintenance", headers=headers).json()
        assert status_response["check_status"] == "success"
        assert status_response["update_available"] is False
        assert "aktuell" in status_response["check_message"]


def test_maintenance_rejects_operator(tmp_path: Path) -> None:
    from certify.security import hash_password

    with app_client(tmp_path) as client:
        with client.app.state.database.connect() as connection:
            connection.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)", ("operator", hash_password("Correct horse battery staple!8"), "operator"))
        login = client.post("/api/v1/auth/login", json={"username": "operator", "password": "Correct horse battery staple!8"})
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        assert client.get("/api/v1/maintenance", headers=headers).status_code == 403
