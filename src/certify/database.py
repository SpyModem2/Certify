from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','operator','auditor')),
 first_name TEXT, last_name TEXT, totp_secret TEXT, totp_pending_secret TEXT,
 email TEXT, notify_level TEXT NOT NULL DEFAULT 'errors'
 CHECK(notify_level IN ('none','errors','expiry','all')), active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 password_changed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS password_history (
 id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 password_hash TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_password_history_user ON password_history(user_id,id DESC);
CREATE TABLE IF NOT EXISTS api_keys (
 id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 name TEXT NOT NULL, key_hash TEXT NOT NULL UNIQUE,
 scope TEXT NOT NULL CHECK(scope IN ('read','read_write')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, last_used_at TEXT, revoked_at TEXT,
 UNIQUE(user_id,name)
);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
CREATE TABLE IF NOT EXISTS certificates (
 id INTEGER PRIMARY KEY, common_name TEXT NOT NULL, sans TEXT NOT NULL DEFAULT '[]',
 acme_directory TEXT NOT NULL, challenge TEXT NOT NULL CHECK(challenge IN ('http-01','dns-01')),
 key_mode TEXT NOT NULL CHECK(key_mode IN ('managed','csr')),
 status TEXT NOT NULL DEFAULT 'pending', certificate_pem TEXT, private_key_pem TEXT,
 csr_pem TEXT, not_after TEXT, created_by INTEGER REFERENCES users(id),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS targets (
 id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE,
 adapter TEXT NOT NULL CHECK(adapter IN ('linux-ssh','iis-ssh','fortigate-7.4')),
 hostname TEXT, ip_address TEXT, config TEXT NOT NULL DEFAULT '{}', secret_config TEXT,
 enabled INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS certificate_users (
 certificate_id INTEGER NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 assigned_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(certificate_id,user_id)
);
CREATE TABLE IF NOT EXISTS certificate_targets (
 certificate_id INTEGER NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
 target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
 assigned_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(certificate_id,target_id)
);
CREATE TABLE IF NOT EXISTS audit_log (
 sequence INTEGER PRIMARY KEY AUTOINCREMENT, occurred_at TEXT NOT NULL,
 actor TEXT NOT NULL, action TEXT NOT NULL, resource TEXT NOT NULL,
 details TEXT NOT NULL, previous_hash TEXT NOT NULL, entry_hash TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_audit_occurred ON audit_log(occurred_at);
"""


class Database:
    def __init__(self, path: Path):
        self.path = path

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        with self.connect() as connection:
            connection.executescript(SCHEMA)
            # Small, idempotent in-place migrations preserve installations
            # created by earlier releases.
            user_columns = {row["name"] for row in connection.execute("PRAGMA table_info(users)")}
            if "email" not in user_columns:
                connection.execute("ALTER TABLE users ADD COLUMN email TEXT")
            if "first_name" not in user_columns:
                connection.execute("ALTER TABLE users ADD COLUMN first_name TEXT")
            if "last_name" not in user_columns:
                connection.execute("ALTER TABLE users ADD COLUMN last_name TEXT")
            if "totp_pending_secret" not in user_columns:
                connection.execute("ALTER TABLE users ADD COLUMN totp_pending_secret TEXT")
            if "notify_level" not in user_columns:
                connection.execute("ALTER TABLE users ADD COLUMN notify_level TEXT NOT NULL DEFAULT 'errors'")
            if "password_changed_at" not in user_columns:
                connection.execute("ALTER TABLE users ADD COLUMN password_changed_at TEXT")
                connection.execute(
                    "UPDATE users SET password_changed_at=COALESCE(created_at,CURRENT_TIMESTAMP) "
                    "WHERE password_changed_at IS NULL"
                )
            target_columns = {row["name"] for row in connection.execute("PRAGMA table_info(targets)")}
            if "hostname" not in target_columns:
                connection.execute("ALTER TABLE targets ADD COLUMN hostname TEXT")
            if "ip_address" not in target_columns:
                connection.execute("ALTER TABLE targets ADD COLUMN ip_address TEXT")
            if "secret_config" not in target_columns:
                connection.execute("ALTER TABLE targets ADD COLUMN secret_config TEXT")

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
