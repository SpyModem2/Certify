from pathlib import Path

from certify.audit import AuditLog
from certify.database import Database


def test_audit_chain_detects_tampering(tmp_path: Path) -> None:
    database = Database(tmp_path / "test.db")
    database.initialize()
    audit = AuditLog(database, "secret" * 8)
    audit.append("alice", "certificate.create", "certificate:1", {"name": "example.test"})
    audit.append("alice", "certificate.download", "certificate:1")
    assert audit.verify() == (True, None)

    with database.connect() as connection:
        connection.execute("UPDATE audit_log SET action='hidden' WHERE sequence=1")
    assert audit.verify() == (False, 1)
