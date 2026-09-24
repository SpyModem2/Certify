"""Create, encrypt and restore portable Certify database backups."""

from __future__ import annotations

import io
import json
import os
import re
import sqlite3
import tempfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"CERTIFY-BACKUP\x01"
MAX_BACKUP_SIZE = 100 * 1024 * 1024
BACKUP_FILENAME = re.compile(r"^certify-auto-\d{8}-\d{6}\.certify-backup$")


class BackupError(ValueError):
    """A backup is invalid or cannot be decrypted safely."""


def _key(password: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode())


def _snapshot(database_path: Path) -> bytes:
    with tempfile.TemporaryDirectory() as temporary:
        snapshot = Path(temporary) / "certify.db"
        source, destination = sqlite3.connect(database_path), sqlite3.connect(snapshot)
        try:
            source.backup(destination)
        finally:
            destination.close()
            source.close()
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("manifest.json", json.dumps({"format": 1, "created_at": datetime.now(UTC).isoformat(), "contents": ["certify.db"]}, separators=(",", ":")))
            archive.write(snapshot, "certify.db")
        return buffer.getvalue()


def create_backup(database_path: Path, password: str | None = None) -> tuple[bytes, bool]:
    payload = _snapshot(database_path)
    if not password:
        return payload, False
    salt, nonce = os.urandom(16), os.urandom(12)
    return MAGIC + salt + nonce + AESGCM(_key(password, salt)).encrypt(nonce, payload, MAGIC), True


def create_automatic_backup(database_path: Path, backup_dir: Path, password: str, *, keep: int = 14) -> Path:
    """Atomically store an encrypted snapshot and prune the oldest snapshots."""
    if not password:
        raise BackupError("automatic backups require a password")
    payload, _ = create_backup(database_path, password)
    backup_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    filename = f"certify-auto-{datetime.now(UTC):%Y%m%d-%H%M%S}.certify-backup"
    destination = backup_dir / filename
    with tempfile.NamedTemporaryFile(dir=backup_dir, prefix=".backup-", delete=False) as handle:
        temporary = Path(handle.name)
        os.chmod(temporary, 0o600)
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, destination)
    backups = sorted((item for item in backup_dir.iterdir() if item.is_file() and BACKUP_FILENAME.fullmatch(item.name)), reverse=True)
    for expired in backups[max(1, keep):]:
        expired.unlink()
    return destination


def _decrypt(payload: bytes, password: str | None) -> bytes:
    if not payload.startswith(MAGIC):
        return payload
    if not password:
        raise BackupError("backup password is required")
    offset = len(MAGIC)
    if len(payload) < offset + 44:
        raise BackupError("backup is truncated")
    salt, nonce = payload[offset:offset + 16], payload[offset + 16:offset + 28]
    try:
        return AESGCM(_key(password, salt)).decrypt(nonce, payload[offset + 28:], MAGIC)
    except InvalidTag as error:
        raise BackupError("incorrect password or damaged backup") from error


def restore_backup(database_path: Path, payload: bytes, password: str | None = None) -> None:
    if len(payload) > MAX_BACKUP_SIZE:
        raise BackupError("backup exceeds the 100 MiB limit")
    try:
        with zipfile.ZipFile(io.BytesIO(_decrypt(payload, password))) as archive:
            if set(archive.namelist()) != {"manifest.json", "certify.db"}:
                raise BackupError("backup has unexpected contents")
            manifest = json.loads(archive.read("manifest.json"))
            info = archive.getinfo("certify.db")
            if manifest.get("format") != 1 or info.file_size > MAX_BACKUP_SIZE:
                raise BackupError("unsupported or oversized backup")
            database_bytes = archive.read(info)
    except (zipfile.BadZipFile, KeyError, json.JSONDecodeError) as error:
        raise BackupError("invalid backup archive") from error

    with tempfile.NamedTemporaryFile(dir=database_path.parent, prefix="restore-", delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(database_bytes)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        connection = sqlite3.connect(f"file:{temporary}?mode=ro", uri=True)
        try:
            integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        finally:
            connection.close()
        if integrity != "ok" or not {"users", "audit_log", "certificates"}.issubset(tables):
            raise BackupError("backup database failed validation")
        if database_path.exists():
            safety = database_path.with_name(f"certify.pre-restore-{datetime.now(UTC):%Y%m%dT%H%M%SZ}.db")
            current, copy = sqlite3.connect(database_path), sqlite3.connect(safety)
            try:
                current.backup(copy)
            finally:
                copy.close()
                current.close()
        os.replace(temporary, database_path)
        database_path.with_name(database_path.name + "-wal").unlink(missing_ok=True)
        database_path.with_name(database_path.name + "-shm").unlink(missing_ok=True)
    finally:
        temporary.unlink(missing_ok=True)
