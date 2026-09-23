from __future__ import annotations

import argparse
import getpass
import sys

from .audit import AuditLog
from .config import Settings
from .database import Database
from .security import PASSWORD_POLICY, hash_password, validate_password


def _database(settings: Settings) -> Database:
    database = Database(settings.data_dir / "certify.db")
    database.initialize()
    return database


def init_admin(username: str) -> int:
    settings = Settings.from_env()
    print(f"Create the password for the first Certify administrator. {PASSWORD_POLICY}")
    password = getpass.getpass("Administrator password: ")
    confirmation = getpass.getpass("Repeat administrator password: ")
    if password != confirmation:
        print("Passwords do not match", file=sys.stderr)
        return 2
    try:
        validate_password(password)
    except ValueError as error:
        print(error, file=sys.stderr)
        return 2
    database = _database(settings)
    try:
        with database.connect() as connection:
            cursor = connection.execute(
                "INSERT INTO users(username,password_hash,role) VALUES(?,?,'admin')",
                (username, hash_password(password)),
            )
            password_hash = connection.execute("SELECT password_hash FROM users WHERE id=?", (cursor.lastrowid,)).fetchone()["password_hash"]
            connection.execute("INSERT INTO password_history(user_id,password_hash) VALUES(?,?)", (cursor.lastrowid, password_hash))
    except Exception as error:
        print(f"Could not create administrator: {error}", file=sys.stderr)
        return 1
    AuditLog(database, settings.secret).append("system", "user.bootstrap", f"user:{username}")
    print(f"Administrator {username!r} created")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="certify")
    commands = parser.add_subparsers(dest="command", required=True)
    admin = commands.add_parser("init-admin", help="create the initial administrator")
    admin.add_argument("username")
    serve = commands.add_parser("serve", help="run the web service")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", default=8080, type=int)
    arguments = parser.parse_args()
    if arguments.command == "init-admin":
        return init_admin(arguments.username)
    if arguments.command == "serve":
        import uvicorn

        settings = Settings.from_env()
        uvicorn.run(
            "certify.api:create_app",
            factory=True,
            host=arguments.host,
            port=arguments.port,
            proxy_headers=False,
            log_level="debug" if settings.debug else "info",
        )
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
