from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime
from typing import Any

from .database import Database


GENESIS = "0" * 64


def _canonical(event: dict[str, Any]) -> bytes:
    return json.dumps(event, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()


class AuditLog:
    """Append-only, keyed hash chain.

    HMAC detects database manipulation provided the application secret is kept
    separately. Production backups should additionally be exported to WORM or
    a remote syslog/SIEM destination.
    """

    def __init__(self, database: Database, secret: str):
        self.database = database
        self.key = hashlib.sha256(("audit:" + secret).encode()).digest()

    def append(
        self, actor: str, action: str, resource: str, details: dict[str, Any] | None = None
    ) -> str:
        with self.database.connect() as connection:
            # Serialize writers so two events cannot select the same chain tip.
            connection.execute("BEGIN IMMEDIATE")
            last = connection.execute(
                "SELECT entry_hash FROM audit_log ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            previous = last["entry_hash"] if last else GENESIS
            event = {
                "occurred_at": datetime.now(UTC).isoformat(),
                "actor": actor,
                "action": action,
                "resource": resource,
                "details": details or {},
                "previous_hash": previous,
            }
            digest = hmac.new(self.key, _canonical(event), hashlib.sha256).hexdigest()
            connection.execute(
                "INSERT INTO audit_log(occurred_at,actor,action,resource,details,previous_hash,entry_hash) VALUES(?,?,?,?,?,?,?)",
                (
                    event["occurred_at"], actor, action, resource,
                    json.dumps(event["details"], ensure_ascii=False, sort_keys=True),
                    previous, digest,
                ),
            )
            return digest

    def verify(self) -> tuple[bool, int | None]:
        previous = GENESIS
        with self.database.connect() as connection:
            rows = connection.execute("SELECT * FROM audit_log ORDER BY sequence").fetchall()
        for row in rows:
            event = {
                "occurred_at": row["occurred_at"], "actor": row["actor"],
                "action": row["action"], "resource": row["resource"],
                "details": json.loads(row["details"]), "previous_hash": row["previous_hash"],
            }
            expected = hmac.new(self.key, _canonical(event), hashlib.sha256).hexdigest()
            if row["previous_hash"] != previous or not hmac.compare_digest(row["entry_hash"], expected):
                return False, row["sequence"]
            previous = row["entry_hash"]
        return True, None
