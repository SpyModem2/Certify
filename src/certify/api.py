import base64
import asyncio
import hashlib
import hmac
import json
import secrets
import time
from contextlib import asynccontextmanager, suppress
from io import BytesIO
from urllib.parse import quote
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Literal

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
import qrcode
import qrcode.image.svg
from pydantic import BaseModel, Field, field_validator

from . import __version__
from .audit import AuditLog
from .config import Settings
from .database import Database
from .mailer import send_local_mail
from .maintenance import BACKUP_FILENAME, BackupError, MAX_BACKUP_SIZE, create_automatic_backup, create_backup, restore_backup
from .providers import test_acme_connection, validate_acme_directory
from .security import PASSWORD_POLICY, hash_password, new_totp_secret, sign_token, validate_password, verify_password, verify_token, verify_totp
from .secrets import SecretBox


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str
    totp_code: str | None = Field(default=None, pattern=r"^\d{6}$")


class UserCreate(BaseModel):
    username: str = Field(pattern=r"^[a-zA-Z0-9_.@-]{1,128}$")
    first_name: str = Field(min_length=1, max_length=128)
    last_name: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=14, max_length=1024, description=PASSWORD_POLICY)
    role: Literal["admin", "operator", "auditor"] = "operator"
    email: str = Field(min_length=3, max_length=320)

    @field_validator("password")
    @classmethod
    def complex_password(cls, password: str) -> str:
        validate_password(password)
        return password

    @field_validator("first_name", "last_name", "email")
    @classmethod
    def non_empty_fields(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("field must not be empty")
        return value

    @field_validator("email")
    @classmethod
    def valid_email(cls, value: str) -> str:
        if value.count("@") != 1 or any(character.isspace() for character in value):
            raise ValueError("invalid email address")
        local, domain = value.rsplit("@", 1)
        if not local or "." not in domain or domain.startswith(".") or domain.endswith("."):
            raise ValueError("invalid email address")
        return value


class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(min_length=14, max_length=1024, description=PASSWORD_POLICY)

    @field_validator("new_password")
    @classmethod
    def complex_password(cls, password: str) -> str:
        validate_password(password)
        return password


class EmailChange(BaseModel):
    email: str = Field(min_length=3, max_length=320)

    @field_validator("email")
    @classmethod
    def valid_email(cls, value: str) -> str:
        value = value.strip()
        if value.count("@") != 1 or any(character.isspace() for character in value):
            raise ValueError("invalid email address")
        local, domain = value.rsplit("@", 1)
        if not local or "." not in domain or domain.startswith(".") or domain.endswith("."):
            raise ValueError("invalid email address")
        return value


class NameChange(BaseModel):
    first_name: str = Field(min_length=1, max_length=128)
    last_name: str = Field(min_length=1, max_length=128)

    @field_validator("first_name", "last_name")
    @classmethod
    def non_empty_names(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("field must not be empty")
        return value


class UserUpdate(NameChange):
    email: str | None = Field(default=None, max_length=320)
    role: Literal["admin", "operator", "auditor"]
    active: bool

    @field_validator("email")
    @classmethod
    def valid_email(cls, value: str | None) -> str | None:
        return EmailChange(email=value).email if value is not None else None


class TotpConfirm(BaseModel):
    code: str = Field(pattern=r"^\d{6}$")


class TotpSetup(BaseModel):
    current_code: str | None = Field(default=None, pattern=r"^\d{6}$")


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_. -]+$")
    scope: Literal["read", "read_write"] = "read"


class CertificateCreate(BaseModel):
    common_name: str = Field(min_length=1, max_length=253)
    sans: list[str] = Field(default_factory=list, max_length=100)
    acme_directory: str | None = None
    challenge: Literal["http-01", "dns-01"]
    key_mode: Literal["managed", "csr"] = "managed"
    csr_pem: str | None = None
    target_ids: list[int] = Field(default_factory=list, max_length=100)
    ca_account_id: int | None = None


class CaAccountCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    provider: Literal["letsencrypt", "custom"]
    directory_url: str
    email: str = Field(min_length=3, max_length=320)
    terms_url: str | None = None
    terms_accepted: bool
    enabled: bool = True

    @field_validator("email")
    @classmethod
    def valid_email(cls, value: str) -> str:
        return EmailChange(email=value).email

    @field_validator("directory_url", "terms_url")
    @classmethod
    def valid_urls(cls, value: str | None) -> str | None:
        if value is not None:
            validate_acme_directory(value)
        return value


class CaAccountUpdate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    provider: Literal["letsencrypt", "custom"]
    directory_url: str
    email: str = Field(min_length=3, max_length=320)
    terms_url: str | None = None
    terms_accepted: bool

    @field_validator("email")
    @classmethod
    def valid_email(cls, value: str) -> str:
        return EmailChange(email=value).email

    @field_validator("directory_url", "terms_url")
    @classmethod
    def valid_urls(cls, value: str | None) -> str | None:
        if value is not None:
            validate_acme_directory(value)
        return value


class TargetAssignments(BaseModel):
    """The complete set of systems to which a certificate is deployed."""

    target_ids: list[int] = Field(max_length=100)


class TargetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    adapter: Literal["linux-ssh", "iis-ssh", "fortigate-7.4"]
    config: dict[str, object] = Field(default_factory=dict)
    hostname: str | None = Field(default=None, max_length=253)
    ip_address: str | None = Field(default=None, max_length=45)
    credentials: dict[str, str] = Field(default_factory=dict)


class CsrUpload(BaseModel):
    csr_pem: str = Field(min_length=32, max_length=131072)


class NotificationPreferences(BaseModel):
    email: str | None = Field(default=None, max_length=320)
    level: Literal["none", "errors", "expiry", "all"]


class Notification(BaseModel):
    category: Literal["errors", "expiry", "issued"]
    subject: str = Field(min_length=1, max_length=200)
    message: str = Field(min_length=1, max_length=10000)


class BackupRequest(BaseModel):
    password: str | None = Field(default=None, min_length=12, max_length=1024)


class AutomaticBackupSettings(BaseModel):
    enabled: bool
    interval_hours: int = Field(default=24, ge=1, le=24 * 31)
    retention: int = Field(default=14, ge=1, le=100)
    password: str | None = Field(default=None, min_length=12, max_length=1024)


class RestoreRequest(BackupRequest):
    data: str = Field(min_length=1)


class Principal(BaseModel):
    id: int
    username: str
    role: str
    api_key_id: int | None = None
    api_scope: Literal["read", "read_write"] | None = None
    password_change_required: bool = False


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    database = Database(settings.data_dir / "certify.db")
    audit = AuditLog(database, settings.secret)
    secret_box = SecretBox(settings.secret)

    automatic_config_file = settings.data_dir / "automatic-backup.json"
    automatic_backup_dir = settings.data_dir / "backups"

    def automatic_config() -> dict[str, object]:
        try:
            value = json.loads(automatic_config_file.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def run_automatic_backup_if_due() -> Path | None:
        config = automatic_config()
        if not config.get("enabled") or not config.get("password"):
            return None
        backups = sorted((p for p in automatic_backup_dir.glob("*.certify-backup") if BACKUP_FILENAME.fullmatch(p.name)), key=lambda p: p.stat().st_mtime, reverse=True)
        interval = int(config.get("interval_hours", 24)) * 3600
        if backups and time.time() - backups[0].stat().st_mtime < interval:
            return None
        password = secret_box.decrypt(str(config["password"]), context="automatic-backup").decode()
        return create_automatic_backup(database.path, automatic_backup_dir, password, keep=int(config.get("retention", 14)))

    async def automatic_backup_worker() -> None:
        while True:
            try:
                await asyncio.to_thread(run_automatic_backup_if_due)
            except Exception:
                # A failed backup must not terminate the web service or scheduler.
                pass
            await asyncio.sleep(60)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        database.initialize()
        worker = asyncio.create_task(automatic_backup_worker())
        try:
            yield
        finally:
            worker.cancel()
            with suppress(asyncio.CancelledError):
                await worker

    app = FastAPI(title="Certify", version=__version__, lifespan=lifespan)
    app.state.database = database
    app.state.audit = audit
    app.state.settings = settings
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(settings.trusted_hosts))
    web_dir = Path(__file__).with_name("web")
    app.mount("/assets", StaticFiles(directory=web_dir / "assets"), name="assets")

    def principal(request: Request, authorization: Annotated[str | None, Header()] = None) -> Principal:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication required")
        token = authorization[7:]
        if token.startswith("certify_"):
            try:
                prefix, key_id, key_secret = token.split("_", 2)
                if prefix != "certify" or not key_secret:
                    raise ValueError
                key_id_int = int(key_id)
            except (ValueError, AssertionError):
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid API key") from None
            key_hash = hmac.new(settings.secret.encode(), token.encode(), hashlib.sha256).hexdigest()
            with database.connect() as connection:
                row = connection.execute(
                    "SELECT k.id,k.key_hash,k.scope,u.id AS user_id,u.username,u.role "
                    "FROM api_keys k JOIN users u ON u.id=k.user_id "
                    "WHERE k.id=? AND k.revoked_at IS NULL AND u.active=1",
                    (key_id_int,),
                ).fetchone()
                if row and hmac.compare_digest(row["key_hash"], key_hash):
                    connection.execute("UPDATE api_keys SET last_used_at=CURRENT_TIMESTAMP WHERE id=?", (key_id_int,))
            if not row or not hmac.compare_digest(row["key_hash"], key_hash):
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid API key")
            if request.method not in ("GET", "HEAD", "OPTIONS") and row["scope"] != "read_write":
                raise HTTPException(status.HTTP_403_FORBIDDEN, "API key has read-only scope")
            return Principal(id=row["user_id"], username=row["username"], role=row["role"], api_key_id=row["id"], api_scope=row["scope"])
        payload = verify_token(token, settings.secret)
        if not payload:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or expired session")
        password_change_required = bool(payload.get("password_change_required", False))
        if password_change_required and settings.password_max_age_days is not None:
            with database.connect() as connection:
                password_row = connection.execute(
                    "SELECT password_changed_at,created_at FROM users WHERE id=?", (int(payload["sub"]),)
                ).fetchone()
            if password_row:
                changed_at = datetime.fromisoformat(password_row["password_changed_at"] or password_row["created_at"])
                if changed_at.tzinfo is None:
                    changed_at = changed_at.replace(tzinfo=UTC)
                password_change_required = changed_at + timedelta(days=settings.password_max_age_days) <= datetime.now(UTC)
        if password_change_required and not (
            request.url.path == "/api/v1/users/me"
            or (request.url.path == "/api/v1/users/me/password" and request.method == "PUT")
        ):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "password change required")
        return Principal(id=int(payload["sub"]), username=payload["username"], role=payload["role"],
                         password_change_required=password_change_required)

    def roles(*allowed: str):
        def dependency(user: Annotated[Principal, Depends(principal)]) -> Principal:
            if user.role not in allowed:
                raise HTTPException(status.HTTP_403_FORBIDDEN, "insufficient role")
            return user
        return dependency

    def session_admin(actor: Annotated[Principal, Depends(roles("admin"))]) -> Principal:
        if actor.api_key_id is not None:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "interactive administrator session required")
        return actor

    @app.get("/health")
    def health() -> dict[str, str]:
        # The updater uses this unauthenticated endpoint to verify the running
        # process, rather than merely checking that systemd managed to fork it.
        return {"status": "ok", "version": __version__}

    @app.get("/", response_class=FileResponse)
    def index() -> FileResponse:
        return FileResponse(
            web_dir / "index.html",
            headers={
                "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; "
                "img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
            },
        )

    @app.post("/api/v1/auth/login")
    def login(body: LoginRequest, request: Request) -> dict[str, object]:
        with database.connect() as connection:
            row = connection.execute("SELECT * FROM users WHERE username=? AND active=1", (body.username,)).fetchone()
        client = request.client.host if request.client else "unknown"
        if row is None:
            audit.append(body.username, "auth.login.failed", "session", {"client": client, "reason": "unknown_or_inactive_user"})
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
        if not verify_password(body.password, row["password_hash"]):
            audit.append(body.username, "auth.login.failed", "session", {"client": client, "reason": "invalid_password"})
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
        if row["totp_secret"] and body.totp_code is None:
            audit.append(body.username, "auth.login.failed", "session", {"client": client, "reason": "totp_required"})
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
        if row["totp_secret"] and not verify_totp(row["totp_secret"], body.totp_code):
            audit.append(body.username, "auth.login.failed", "session", {"client": client, "reason": "invalid_totp"})
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
        password_change_required = False
        if settings.password_max_age_days is not None:
            changed_at = datetime.fromisoformat(row["password_changed_at"] or row["created_at"])
            if changed_at.tzinfo is None:
                changed_at = changed_at.replace(tzinfo=UTC)
            password_change_required = changed_at + timedelta(days=settings.password_max_age_days) <= datetime.now(UTC)
        expires = datetime.now(UTC) + timedelta(minutes=settings.session_minutes)
        token = sign_token({"sub": row["id"], "username": row["username"], "role": row["role"], "password_change_required": password_change_required, "exp": int(expires.timestamp()), "nonce": time.time_ns()}, settings.secret)
        audit.append(row["username"], "auth.login", "session", {"client": client, "password_change_required": password_change_required})
        return {"access_token": token, "token_type": "bearer", "expires_at": expires.isoformat(), "password_change_required": password_change_required}

    @app.get("/api/v1/users/me")
    def current_user(actor: Annotated[Principal, Depends(principal)]) -> dict[str, object]:
        with database.connect() as connection:
            row = connection.execute(
                "SELECT id,username,first_name,last_name,role,email,notify_level,"
                "totp_secret IS NOT NULL AS totp_enabled,created_at,password_changed_at FROM users WHERE id=?",
                (actor.id,),
            ).fetchone()
        if not row:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
        result = dict(row)
        result["password_change_required"] = actor.password_change_required
        return result

    @app.get("/api/v1/users")
    def list_users(_: Annotated[Principal, Depends(roles("admin"))]) -> list[dict[str, object]]:
        with database.connect() as connection:
            rows = connection.execute(
                "SELECT id,username,first_name,last_name,role,email,notify_level,active,"
                "totp_secret IS NOT NULL AS totp_enabled,created_at FROM users ORDER BY username"
            ).fetchall()
        return [dict(row) for row in rows]

    @app.post("/api/v1/users", status_code=201)
    def create_user(body: UserCreate, actor: Annotated[Principal, Depends(roles("admin"))]) -> dict[str, object]:
        try:
            with database.connect() as connection:
                password_hash = hash_password(body.password)
                cursor = connection.execute(
                    "INSERT INTO users(username,first_name,last_name,password_hash,role,email) VALUES(?,?,?,?,?,?)",
                    (body.username, body.first_name, body.last_name, password_hash, body.role, body.email),
                )
                connection.execute("INSERT INTO password_history(user_id,password_hash) VALUES(?,?)", (cursor.lastrowid, password_hash))
        except Exception as error:
            if "UNIQUE constraint" in str(error):
                raise HTTPException(status.HTTP_409_CONFLICT, "username already exists") from error
            raise
        audit.append(actor.username, "user.create", f"user:{cursor.lastrowid}", {"username": body.username, "role": body.role})
        return {"id": cursor.lastrowid, "username": body.username, "first_name": body.first_name,
                "last_name": body.last_name, "email": body.email, "role": body.role}

    @app.put("/api/v1/users/me/email")
    def change_email(body: EmailChange, actor: Annotated[Principal, Depends(principal)]) -> dict[str, str]:
        with database.connect() as connection:
            connection.execute("UPDATE users SET email=? WHERE id=?", (body.email, actor.id))
        audit.append(actor.username, "user.email.change", f"user:{actor.id}")
        return {"email": body.email}

    @app.put("/api/v1/users/me/name")
    def change_name(body: NameChange, actor: Annotated[Principal, Depends(principal)]) -> dict[str, str]:
        with database.connect() as connection:
            connection.execute(
                "UPDATE users SET first_name=?,last_name=? WHERE id=?",
                (body.first_name, body.last_name, actor.id),
            )
        audit.append(actor.username, "user.name.change", f"user:{actor.id}")
        return {"first_name": body.first_name, "last_name": body.last_name}

    @app.put("/api/v1/users/{user_id}")
    def update_user(
        user_id: int, body: UserUpdate, actor: Annotated[Principal, Depends(roles("admin"))]
    ) -> dict[str, object]:
        with database.connect() as connection:
            result = connection.execute(
                "UPDATE users SET first_name=?,last_name=?,email=?,role=?,active=? WHERE id=?",
                (body.first_name, body.last_name, body.email, body.role, int(body.active), user_id),
            )
        if not result.rowcount:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
        audit.append(
            actor.username,
            "user.update",
            f"user:{user_id}",
            {"role": body.role, "active": body.active},
        )
        return {"id": user_id, **body.model_dump()}

    @app.post("/api/v1/users/me/totp/setup")
    def setup_totp(
        actor: Annotated[Principal, Depends(principal)], body: TotpSetup = TotpSetup()
    ) -> dict[str, str]:
        if actor.api_key_id is not None:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "TOTP setup requires a user session")
        with database.connect() as connection:
            user = connection.execute("SELECT totp_secret FROM users WHERE id=?", (actor.id,)).fetchone()
            if user and user["totp_secret"] and (
                body.current_code is None or not verify_totp(user["totp_secret"], body.current_code)
            ):
                audit.append(actor.username, "user.totp.setup.failed", f"user:{actor.id}", {"reason": "invalid_current_totp"})
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, "current TOTP code is incorrect")
            secret = new_totp_secret()
            connection.execute("UPDATE users SET totp_pending_secret=? WHERE id=?", (secret, actor.id))
        label = quote(f"Certify:{actor.username}", safe="")
        uri = f"otpauth://totp/{label}?secret={secret}&issuer=Certify&digits=6&period=30"
        qr_buffer = BytesIO()
        qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage).save(qr_buffer)
        qr_code = "data:image/svg+xml;base64," + base64.b64encode(qr_buffer.getvalue()).decode("ascii")
        audit.append(actor.username, "user.totp.setup.started", f"user:{actor.id}")
        return {"secret": secret, "otpauth_uri": uri, "qr_code": qr_code}

    @app.delete("/api/v1/users/me/totp/setup", status_code=204)
    def cancel_totp_setup(actor: Annotated[Principal, Depends(principal)]) -> Response:
        if actor.api_key_id is not None:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "TOTP setup requires a user session")
        with database.connect() as connection:
            result = connection.execute(
                "UPDATE users SET totp_pending_secret=NULL WHERE id=? AND totp_pending_secret IS NOT NULL",
                (actor.id,),
            )
        if result.rowcount:
            audit.append(actor.username, "user.totp.setup.cancelled", f"user:{actor.id}")
        return Response(status_code=204)

    @app.post("/api/v1/users/me/totp/confirm", status_code=204)
    def confirm_totp(body: TotpConfirm, actor: Annotated[Principal, Depends(principal)]) -> Response:
        with database.connect() as connection:
            user = connection.execute("SELECT totp_pending_secret FROM users WHERE id=?", (actor.id,)).fetchone()
            if not user or not user["totp_pending_secret"]:
                raise HTTPException(status.HTTP_409_CONFLICT, "no TOTP setup is pending")
            if not verify_totp(user["totp_pending_secret"], body.code):
                raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "invalid TOTP code")
            connection.execute(
                "UPDATE users SET totp_secret=totp_pending_secret,totp_pending_secret=NULL WHERE id=?", (actor.id,)
            )
        audit.append(actor.username, "user.totp.enabled", f"user:{actor.id}")
        return Response(status_code=204)

    @app.delete("/api/v1/users/{user_id}/totp", status_code=204)
    def reset_totp(user_id: int, actor: Annotated[Principal, Depends(roles("admin"))]) -> Response:
        with database.connect() as connection:
            result = connection.execute(
                "UPDATE users SET totp_secret=NULL,totp_pending_secret=NULL "
                "WHERE id=? AND (totp_secret IS NOT NULL OR totp_pending_secret IS NOT NULL)", (user_id,)
            )
        if not result.rowcount:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "user has no TOTP settings")
        audit.append(actor.username, "user.totp.reset", f"user:{user_id}")
        return Response(status_code=204)

    @app.put("/api/v1/users/me/password", status_code=204)
    def change_password(body: PasswordChange, actor: Annotated[Principal, Depends(principal)]) -> Response:
        with database.connect() as connection:
            user = connection.execute("SELECT password_hash FROM users WHERE id=?", (actor.id,)).fetchone()
            if not user or not verify_password(body.current_password, user["password_hash"]):
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, "current password is incorrect")
            history = connection.execute(
                "SELECT password_hash FROM password_history WHERE user_id=? ORDER BY id DESC LIMIT 20", (actor.id,)
            ).fetchall()
            hashes = [user["password_hash"], *(row["password_hash"] for row in history)]
            if any(verify_password(body.new_password, password_hash) for password_hash in dict.fromkeys(hashes)):
                raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "The last 20 passwords cannot be reused.")
            password_hash = hash_password(body.new_password)
            # Preserve the value that is about to be replaced.  Older databases
            # may not yet contain the current hash in password_history.
            connection.execute(
                "INSERT INTO password_history(user_id,password_hash) VALUES(?,?)",
                (actor.id, user["password_hash"]),
            )
            connection.execute(
                "UPDATE users SET password_hash=?,password_changed_at=CURRENT_TIMESTAMP WHERE id=?",
                (password_hash, actor.id),
            )
            connection.execute(
                "DELETE FROM password_history WHERE user_id=? AND id NOT IN "
                "(SELECT id FROM password_history WHERE user_id=? ORDER BY id DESC LIMIT 20)", (actor.id, actor.id)
            )
        audit.append(actor.username, "user.password.change", f"user:{actor.id}")
        return Response(status_code=204)

    @app.post("/api/v1/api-keys", status_code=201)
    def create_api_key(body: ApiKeyCreate, actor: Annotated[Principal, Depends(principal)]) -> dict[str, object]:
        if actor.api_key_id is not None:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "API keys cannot create other API keys")
        raw_secret = secrets.token_urlsafe(32)
        try:
            with database.connect() as connection:
                cursor = connection.execute("INSERT INTO api_keys(user_id,name,key_hash,scope) VALUES(?,?,?,?)", (actor.id, body.name, "pending", body.scope))
                token = f"certify_{cursor.lastrowid}_{raw_secret}"
                key_hash = hmac.new(settings.secret.encode(), token.encode(), hashlib.sha256).hexdigest()
                connection.execute("UPDATE api_keys SET key_hash=? WHERE id=?", (key_hash, cursor.lastrowid))
        except Exception as error:
            if "UNIQUE constraint" in str(error):
                raise HTTPException(status.HTTP_409_CONFLICT, "API key name already exists") from error
            raise
        audit.append(actor.username, "api_key.create", f"api_key:{cursor.lastrowid}", {"scope": body.scope})
        return {"id": cursor.lastrowid, "name": body.name, "scope": body.scope, "key": token, "warning": "Store this key now; it will not be shown again."}

    @app.get("/api/v1/api-keys")
    def list_api_keys(actor: Annotated[Principal, Depends(principal)]) -> list[dict[str, object]]:
        with database.connect() as connection:
            rows = connection.execute("SELECT id,name,scope,created_at,last_used_at,revoked_at FROM api_keys WHERE user_id=? ORDER BY id", (actor.id,)).fetchall()
        return [dict(row) for row in rows]

    @app.delete("/api/v1/api-keys/{key_id}", status_code=204)
    def revoke_api_key(key_id: int, actor: Annotated[Principal, Depends(principal)]) -> Response:
        with database.connect() as connection:
            result = connection.execute("UPDATE api_keys SET revoked_at=CURRENT_TIMESTAMP WHERE id=? AND user_id=? AND revoked_at IS NULL", (key_id, actor.id))
        if not result.rowcount:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "active API key not found")
        audit.append(actor.username, "api_key.revoke", f"api_key:{key_id}")
        return Response(status_code=204)

    @app.get("/api/v1/certificates")
    def certificates(actor: Annotated[Principal, Depends(principal)]) -> list[dict[str, object]]:
        with database.connect() as connection:
            if actor.role in ("admin", "auditor"):
                rows = connection.execute("SELECT c.id,c.common_name,c.sans,c.acme_directory,c.challenge,c.key_mode,c.status,c.status_detail,c.not_after,c.created_at,c.updated_at,c.ca_account_id,a.name AS ca_name FROM certificates c LEFT JOIN ca_accounts a ON a.id=c.ca_account_id ORDER BY c.id DESC").fetchall()
            else:
                rows = connection.execute("SELECT c.id,c.common_name,c.sans,c.acme_directory,c.challenge,c.key_mode,c.status,c.status_detail,c.not_after,c.created_at,c.updated_at,c.ca_account_id,a.name AS ca_name FROM certificates c JOIN certificate_users cu ON cu.certificate_id=c.id LEFT JOIN ca_accounts a ON a.id=c.ca_account_id WHERE cu.user_id=? ORDER BY c.id DESC", (actor.id,)).fetchall()
            certificate_ids = [row["id"] for row in rows]
            targets_by_certificate: dict[int, list[dict[str, object]]] = {item: [] for item in certificate_ids}
            if certificate_ids:
                placeholders = ",".join("?" for _ in certificate_ids)
                assigned_targets = connection.execute(
                    f"SELECT ct.certificate_id,t.id,t.name,t.adapter,t.hostname,t.ip_address "
                    f"FROM certificate_targets ct JOIN targets t ON t.id=ct.target_id "
                    f"WHERE ct.certificate_id IN ({placeholders}) ORDER BY t.name",
                    certificate_ids,
                ).fetchall()
                for target in assigned_targets:
                    targets_by_certificate[target["certificate_id"]].append(
                        {key: target[key] for key in ("id", "name", "adapter", "hostname", "ip_address")}
                    )
        return [
            {**dict(row), "sans": json.loads(row["sans"]), "targets": targets_by_certificate[row["id"]]}
            for row in rows
        ]

    @app.post("/api/v1/certificates", status_code=201)
    def create_certificate(body: CertificateCreate, actor: Annotated[Principal, Depends(roles("admin", "operator"))]) -> dict[str, object]:
        if body.ca_account_id is None:
            if not body.acme_directory:
                raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "acme_directory or ca_account_id is required")
            try:
                validate_acme_directory(body.acme_directory)
            except ValueError as error:
                raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(error)) from error
        if body.key_mode == "csr" and not body.csr_pem:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "csr_pem is required for CSR mode")
        with database.connect() as connection:
            directory = body.acme_directory
            if body.ca_account_id is not None:
                account = connection.execute(
                    "SELECT id,directory_url,enabled,terms_accepted_at FROM ca_accounts WHERE id=?",
                    (body.ca_account_id,),
                ).fetchone()
                if not account:
                    raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "certification authority account does not exist")
                if not account["enabled"]:
                    raise HTTPException(status.HTTP_409_CONFLICT, "certification authority account is disabled")
                if not account["terms_accepted_at"]:
                    raise HTTPException(status.HTTP_409_CONFLICT, "CA terms must be accepted first")
                directory = account["directory_url"]
            requested_targets = list(dict.fromkeys(body.target_ids))
            if requested_targets:
                placeholders = ",".join("?" for _ in requested_targets)
                existing = connection.execute(
                    f"SELECT id FROM targets WHERE id IN ({placeholders})", requested_targets
                ).fetchall()
                if len(existing) != len(requested_targets):
                    raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "one or more target systems do not exist")
            detail = "Auftrag angelegt; Schlüsselmaterial und Challenge werden vorbereitet."
            cursor = connection.execute("INSERT INTO certificates(common_name,sans,acme_directory,challenge,key_mode,csr_pem,created_by,ca_account_id,status_detail) VALUES(?,?,?,?,?,?,?,?,?)", (body.common_name, json.dumps(body.sans), directory, body.challenge, body.key_mode, body.csr_pem, actor.id, body.ca_account_id, detail))
            connection.execute("INSERT INTO certificate_users(certificate_id,user_id) VALUES(?,?)", (cursor.lastrowid, actor.id))
            connection.executemany(
                "INSERT INTO certificate_targets(certificate_id,target_id) VALUES(?,?)",
                ((cursor.lastrowid, target_id) for target_id in requested_targets),
            )
        audit.append(actor.username, "certificate.request", f"certificate:{cursor.lastrowid}", {"common_name": body.common_name, "challenge": body.challenge, "key_mode": body.key_mode, "target_ids": requested_targets})
        return {"id": cursor.lastrowid, "status": "pending"}

    @app.get("/api/v1/ca-accounts")
    def list_ca_accounts(_: Annotated[Principal, Depends(roles("admin", "operator", "auditor"))]) -> list[dict[str, object]]:
        with database.connect() as connection:
            rows = connection.execute(
                "SELECT id,name,provider,directory_url,email,terms_url,terms_accepted_at,enabled,created_at,updated_at FROM ca_accounts ORDER BY name"
            ).fetchall()
        return [dict(row) for row in rows]

    @app.post("/api/v1/ca-accounts", status_code=201)
    def create_ca_account(body: CaAccountCreate, actor: Annotated[Principal, Depends(roles("admin"))]) -> dict[str, object]:
        if not body.terms_accepted:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "the CA terms must be accepted")
        try:
            with database.connect() as connection:
                cursor = connection.execute(
                    "INSERT INTO ca_accounts(name,provider,directory_url,email,terms_url,terms_accepted_at,enabled) VALUES(?,?,?,?,?,CURRENT_TIMESTAMP,?)",
                    (body.name.strip(), body.provider, body.directory_url, body.email, body.terms_url, body.enabled),
                )
                row = connection.execute("SELECT id,name,provider,directory_url,email,terms_url,terms_accepted_at,enabled,created_at,updated_at FROM ca_accounts WHERE id=?", (cursor.lastrowid,)).fetchone()
        except Exception as error:
            if "UNIQUE constraint" in str(error):
                raise HTTPException(status.HTTP_409_CONFLICT, "CA account name already exists") from error
            raise
        audit.append(actor.username, "ca_account.create", f"ca_account:{cursor.lastrowid}", {"name": body.name, "provider": body.provider})
        return dict(row)

    @app.delete("/api/v1/ca-accounts/{account_id}", status_code=204)
    def disable_ca_account(account_id: int, actor: Annotated[Principal, Depends(roles("admin"))]) -> Response:
        with database.connect() as connection:
            result = connection.execute("UPDATE ca_accounts SET enabled=0,updated_at=CURRENT_TIMESTAMP WHERE id=? AND enabled=1", (account_id,))
        if not result.rowcount:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "active CA account not found")
        audit.append(actor.username, "ca_account.disable", f"ca_account:{account_id}")
        return Response(status_code=204)

    @app.put("/api/v1/ca-accounts/{account_id}")
    def update_ca_account(account_id: int, body: CaAccountUpdate, actor: Annotated[Principal, Depends(roles("admin"))]) -> dict[str, object]:
        if not body.terms_accepted:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "the CA terms must be accepted")
        try:
            with database.connect() as connection:
                result = connection.execute(
                    "UPDATE ca_accounts SET name=?,provider=?,directory_url=?,email=?,terms_url=?,"
                    "terms_accepted_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=?",
                    (body.name.strip(), body.provider, body.directory_url, body.email, body.terms_url, account_id),
                )
                row = connection.execute(
                    "SELECT id,name,provider,directory_url,email,terms_url,terms_accepted_at,enabled,created_at,updated_at FROM ca_accounts WHERE id=?",
                    (account_id,),
                ).fetchone()
        except Exception as error:
            if "UNIQUE constraint" in str(error):
                raise HTTPException(status.HTTP_409_CONFLICT, "CA account name already exists") from error
            raise
        if not result.rowcount:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "CA account not found")
        audit.append(actor.username, "ca_account.update", f"ca_account:{account_id}", {"name": body.name, "provider": body.provider})
        return dict(row)

    @app.post("/api/v1/ca-accounts/{account_id}/enable")
    def enable_ca_account(account_id: int, actor: Annotated[Principal, Depends(roles("admin"))]) -> dict[str, object]:
        with database.connect() as connection:
            result = connection.execute(
                "UPDATE ca_accounts SET enabled=1,updated_at=CURRENT_TIMESTAMP WHERE id=? AND enabled=0", (account_id,)
            )
            row = connection.execute(
                "SELECT id,name,provider,directory_url,email,terms_url,terms_accepted_at,enabled,created_at,updated_at FROM ca_accounts WHERE id=?",
                (account_id,),
            ).fetchone()
        if not row:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "CA account not found")
        if not result.rowcount:
            raise HTTPException(status.HTTP_409_CONFLICT, "CA account is already active")
        audit.append(actor.username, "ca_account.enable", f"ca_account:{account_id}")
        return dict(row)

    @app.post("/api/v1/ca-accounts/{account_id}/test")
    def test_ca_account(account_id: int, actor: Annotated[Principal, Depends(roles("admin"))]) -> dict[str, object]:
        with database.connect() as connection:
            row = connection.execute("SELECT directory_url FROM ca_accounts WHERE id=?", (account_id,)).fetchone()
        if not row:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "CA account not found")
        try:
            result = test_acme_connection(row["directory_url"])
        except Exception as error:
            audit.append(actor.username, "ca_account.test.failed", f"ca_account:{account_id}", {"error": str(error)[:500]})
            raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"CA connection test failed: {error}") from error
        audit.append(actor.username, "ca_account.test", f"ca_account:{account_id}")
        return result

    @app.get("/api/v1/certificates/{certificate_id}/download")
    def download_certificate(certificate_id: int, actor: Annotated[Principal, Depends(roles("admin", "operator"))], include_key: bool = False) -> Response:
        with database.connect() as connection:
            row = connection.execute("SELECT * FROM certificates WHERE id=?", (certificate_id,)).fetchone()
            assigned = actor.role == "admin" or connection.execute("SELECT 1 FROM certificate_users WHERE certificate_id=? AND user_id=?", (certificate_id, actor.id)).fetchone()
        if not assigned:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "certificate is not assigned to this user")
        if not row or not row["certificate_pem"]:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "issued certificate not found")
        content = row["certificate_pem"]
        if include_key:
            if not row["private_key_pem"]:
                raise HTTPException(status.HTTP_409_CONFLICT, "private key is not managed by Certify")
            key = row["private_key_pem"]
            if key.startswith("v1."):
                key = secret_box.decrypt(key, context=f"certificate:{certificate_id}").decode()
            content += "\n" + key
        audit.append(actor.username, "certificate.download", f"certificate:{certificate_id}", {"private_key": include_key})
        return Response(content, media_type="application/x-pem-file", headers={"Content-Disposition": f'attachment; filename="certificate-{certificate_id}.pem"', "Cache-Control": "no-store"})

    @app.post("/api/v1/targets", status_code=201)
    def create_target(body: TargetCreate, actor: Annotated[Principal, Depends(roles("admin"))]) -> dict[str, object]:
        with database.connect() as connection:
            encrypted = secret_box.encrypt(body.credentials, context=f"target:{body.name}") if body.credentials else None
            cursor = connection.execute("INSERT INTO targets(name,adapter,hostname,ip_address,config,secret_config) VALUES(?,?,?,?,?,?)", (body.name, body.adapter, body.hostname, body.ip_address, json.dumps(body.config), encrypted))
        audit.append(actor.username, "target.create", f"target:{cursor.lastrowid}", {"name": body.name, "adapter": body.adapter})
        return {"id": cursor.lastrowid, "name": body.name, "adapter": body.adapter}

    @app.get("/api/v1/targets")
    def list_targets(_: Annotated[Principal, Depends(roles("admin", "operator"))]) -> list[dict[str, object]]:
        with database.connect() as connection:
            rows = connection.execute(
                "SELECT id,name,adapter,hostname,ip_address,config,enabled,created_at FROM targets ORDER BY name"
            ).fetchall()
        return [
            {**dict(row), "config": json.loads(row["config"])}
            for row in rows
        ]

    def require_certificate_access(certificate_id: int, actor: Principal) -> None:
        if actor.role == "admin":
            return
        with database.connect() as connection:
            assigned = connection.execute("SELECT 1 FROM certificate_users WHERE certificate_id=? AND user_id=?", (certificate_id, actor.id)).fetchone()
        if not assigned:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "certificate is not assigned to this user")

    @app.put("/api/v1/certificates/{certificate_id}/users/{user_id}", status_code=204)
    def assign_user(certificate_id: int, user_id: int, actor: Annotated[Principal, Depends(roles("admin"))]) -> Response:
        try:
            with database.connect() as connection:
                connection.execute("INSERT OR IGNORE INTO certificate_users(certificate_id,user_id) VALUES(?,?)", (certificate_id, user_id))
        except Exception as error:
            if "FOREIGN KEY" in str(error):
                raise HTTPException(status.HTTP_404_NOT_FOUND, "certificate or user not found") from error
            raise
        audit.append(actor.username, "certificate.user.assign", f"certificate:{certificate_id}", {"user_id": user_id})
        return Response(status_code=204)

    @app.put("/api/v1/certificates/{certificate_id}/targets/{target_id}", status_code=204)
    def assign_target(certificate_id: int, target_id: int, actor: Annotated[Principal, Depends(roles("admin"))]) -> Response:
        try:
            with database.connect() as connection:
                connection.execute("INSERT OR IGNORE INTO certificate_targets(certificate_id,target_id) VALUES(?,?)", (certificate_id, target_id))
        except Exception as error:
            if "FOREIGN KEY" in str(error):
                raise HTTPException(status.HTTP_404_NOT_FOUND, "certificate or target not found") from error
            raise
        audit.append(actor.username, "certificate.target.assign", f"certificate:{certificate_id}", {"target_id": target_id})
        return Response(status_code=204)

    @app.put("/api/v1/certificates/{certificate_id}/targets")
    def assign_targets(certificate_id: int, body: TargetAssignments, actor: Annotated[Principal, Depends(roles("admin"))]) -> dict[str, list[int]]:
        """Replace all system assignments in one operation (useful for wildcard certificates)."""
        target_ids = list(dict.fromkeys(body.target_ids))
        with database.connect() as connection:
            if not connection.execute("SELECT 1 FROM certificates WHERE id=?", (certificate_id,)).fetchone():
                raise HTTPException(status.HTTP_404_NOT_FOUND, "certificate not found")
            if target_ids:
                placeholders = ",".join("?" for _ in target_ids)
                existing = connection.execute(
                    f"SELECT id FROM targets WHERE id IN ({placeholders})", target_ids
                ).fetchall()
                if len(existing) != len(target_ids):
                    raise HTTPException(status.HTTP_404_NOT_FOUND, "one or more target systems do not exist")
            connection.execute("DELETE FROM certificate_targets WHERE certificate_id=?", (certificate_id,))
            connection.executemany(
                "INSERT INTO certificate_targets(certificate_id,target_id) VALUES(?,?)",
                ((certificate_id, target_id) for target_id in target_ids),
            )
        audit.append(actor.username, "certificate.targets.replace", f"certificate:{certificate_id}", {"target_ids": target_ids})
        return {"target_ids": target_ids}

    @app.put("/api/v1/certificates/{certificate_id}/csr", status_code=204)
    def upload_csr(certificate_id: int, body: CsrUpload, actor: Annotated[Principal, Depends(roles("admin", "operator"))]) -> Response:
        require_certificate_access(certificate_id, actor)
        try:
            x509.load_pem_x509_csr(body.csr_pem.encode())
        except ValueError as error:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "invalid PEM CSR") from error
        with database.connect() as connection:
            result = connection.execute("UPDATE certificates SET csr_pem=?,key_mode='csr',private_key_pem=NULL,status='pending',updated_at=CURRENT_TIMESTAMP WHERE id=?", (body.csr_pem, certificate_id))
        if not result.rowcount:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "certificate not found")
        audit.append(actor.username, "certificate.csr.upload", f"certificate:{certificate_id}")
        return Response(status_code=204)

    @app.post("/api/v1/certificates/{certificate_id}/generate-key")
    def generate_key(certificate_id: int, actor: Annotated[Principal, Depends(roles("admin", "operator"))]) -> dict[str, str]:
        require_certificate_access(certificate_id, actor)
        with database.connect() as connection:
            row = connection.execute("SELECT common_name,sans FROM certificates WHERE id=?", (certificate_id,)).fetchone()
        if not row:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "certificate not found")
        key = ec.generate_private_key(ec.SECP384R1())
        names = [row["common_name"], *json.loads(row["sans"])]
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, row["common_name"])])).add_extension(x509.SubjectAlternativeName([x509.DNSName(name) for name in names]), critical=False).sign(key, hashes.SHA384())
        private_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
        encrypted = secret_box.encrypt(private_pem, context=f"certificate:{certificate_id}")
        with database.connect() as connection:
            connection.execute("UPDATE certificates SET key_mode='managed',private_key_pem=?,csr_pem=?,status='pending',updated_at=CURRENT_TIMESTAMP WHERE id=?", (encrypted, csr_pem, certificate_id))
        audit.append(actor.username, "certificate.key.generate", f"certificate:{certificate_id}")
        return {"csr_pem": csr_pem}

    @app.put("/api/v1/users/me/notifications")
    def notification_preferences(body: NotificationPreferences, actor: Annotated[Principal, Depends(principal)]) -> dict[str, object]:
        if body.level != "none" and not body.email:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "email is required when notifications are enabled")
        with database.connect() as connection:
            connection.execute("UPDATE users SET email=?,notify_level=? WHERE id=?", (body.email, body.level, actor.id))
        audit.append(actor.username, "user.notifications.update", f"user:{actor.id}", {"level": body.level})
        return {"email": body.email, "level": body.level}

    @app.post("/api/v1/notifications/send")
    def send_notification(body: Notification, actor: Annotated[Principal, Depends(roles("admin"))]) -> dict[str, int]:
        accepted = {
            "errors": ("errors", "expiry", "all"),
            "expiry": ("expiry", "all"),
            "issued": ("all",),
        }[body.category]
        placeholders = ",".join("?" for _ in accepted)
        with database.connect() as connection:
            recipients = connection.execute(
                f"SELECT email FROM users WHERE active=1 AND email IS NOT NULL AND notify_level IN ({placeholders})",
                accepted,
            ).fetchall()
        for recipient in recipients:
            send_local_mail(settings.smtp_host, settings.smtp_port, settings.mail_from, recipient["email"], body.subject, body.message)
        audit.append(actor.username, "notification.send", "users", {"category": body.category, "recipients": len(recipients)})
        return {"recipients": len(recipients)}

    @app.get("/api/v1/audit/verify")
    def verify_audit(_: Annotated[Principal, Depends(roles("admin", "auditor"))]) -> dict[str, object]:
        valid, broken_at = audit.verify()
        return {"valid": valid, "broken_at": broken_at}

    @app.get("/api/v1/audit")
    def audit_entries(
        _: Annotated[Principal, Depends(roles("admin", "auditor"))],
        limit: int = 100,
    ) -> list[dict[str, object]]:
        limit = max(1, min(limit, 500))
        with database.connect() as connection:
            rows = connection.execute(
                "SELECT sequence,occurred_at,actor,action,resource,details FROM audit_log "
                "ORDER BY sequence DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [{**dict(row), "details": json.loads(row["details"])} for row in rows]

    @app.get("/api/v1/maintenance")
    def maintenance_status(_: Annotated[Principal, Depends(session_admin)]) -> dict[str, object]:
        result: dict[str, object] = {"version": __version__, "update_status": "idle"}
        status_file = settings.data_dir / "update-status.json"
        if status_file.exists():
            try:
                value = json.loads(status_file.read_text(encoding="utf-8"))
                if isinstance(value, dict):
                    result.update(value)
            except (OSError, json.JSONDecodeError):
                result["update_status"] = "unknown"
        if (settings.data_dir / "update.request").exists():
            result["update_status"] = "queued"
        check_file = settings.data_dir / "update-check-status.json"
        if check_file.exists():
            try:
                value = json.loads(check_file.read_text(encoding="utf-8"))
                if isinstance(value, dict):
                    result.update(value)
            except (OSError, json.JSONDecodeError):
                result["check_status"] = "unknown"
        if (settings.data_dir / "update-check.request").exists():
            result["check_status"] = "queued"
        config = automatic_config()
        backups = sorted((p for p in automatic_backup_dir.glob("*.certify-backup") if BACKUP_FILENAME.fullmatch(p.name)), key=lambda p: p.stat().st_mtime, reverse=True)
        result["automatic_backup"] = {
            "enabled": bool(config.get("enabled", False)),
            "interval_hours": int(config.get("interval_hours", 24)),
            "retention": int(config.get("retention", 14)),
        }
        result["backups"] = [{"name": p.name, "size": p.stat().st_size, "created_at": datetime.fromtimestamp(p.stat().st_mtime, UTC).isoformat()} for p in backups]
        return result

    @app.put("/api/v1/maintenance/backup/automatic")
    def configure_automatic_backup(body: AutomaticBackupSettings, actor: Annotated[Principal, Depends(session_admin)]) -> dict[str, object]:
        current = automatic_config()
        if body.enabled and not body.password and not current.get("password"):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "a password is required for automatic backups")
        value: dict[str, object] = {"enabled": body.enabled, "interval_hours": body.interval_hours, "retention": body.retention}
        if body.password:
            value["password"] = secret_box.encrypt(body.password, context="automatic-backup")
        elif current.get("password"):
            value["password"] = current["password"]
        settings.data_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
        temporary = automatic_config_file.with_suffix(".tmp")
        temporary.write_text(json.dumps(value), encoding="utf-8")
        temporary.chmod(0o600)
        temporary.replace(automatic_config_file)
        created = run_automatic_backup_if_due()
        audit.append(actor.username, "maintenance.backup.automatic.configure", "system", {"enabled": body.enabled, "interval_hours": body.interval_hours, "retention": body.retention})
        return {"status": "configured", "backup_created": created.name if created else None}

    @app.get("/api/v1/maintenance/backups/{filename}")
    def download_automatic_backup(filename: str, actor: Annotated[Principal, Depends(session_admin)]) -> FileResponse:
        if not BACKUP_FILENAME.fullmatch(filename):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "backup not found")
        path = automatic_backup_dir / filename
        if not path.is_file():
            raise HTTPException(status.HTTP_404_NOT_FOUND, "backup not found")
        audit.append(actor.username, "maintenance.backup.download", f"backup:{filename}")
        return FileResponse(path, media_type="application/octet-stream", filename=filename, headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})

    @app.post("/api/v1/maintenance/update/check", status_code=202)
    def request_update_check(actor: Annotated[Principal, Depends(session_admin)]) -> dict[str, str]:
        request_file = settings.data_dir / "update-check.request"
        if request_file.exists():
            raise HTTPException(status.HTTP_409_CONFLICT, "an update check is already queued")
        audit.append(actor.username, "maintenance.update.check", "system")
        temporary = request_file.with_suffix(".tmp")
        temporary.write_text(json.dumps({"requested_at": datetime.now(UTC).isoformat(), "actor": actor.username}), encoding="utf-8")
        temporary.chmod(0o600)
        temporary.replace(request_file)
        return {"status": "queued"}

    @app.post("/api/v1/maintenance/backup")
    def download_backup(body: BackupRequest, actor: Annotated[Principal, Depends(session_admin)]) -> Response:
        payload, encrypted = create_backup(database.path, body.password)
        audit.append(actor.username, "maintenance.backup.create", "system", {"encrypted": encrypted})
        stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        suffix = "certify-backup" if encrypted else "zip"
        return Response(payload, media_type="application/octet-stream", headers={
            "Content-Disposition": f'attachment; filename="certify-{stamp}.{suffix}"',
            "X-Content-Type-Options": "nosniff",
        })

    @app.post("/api/v1/maintenance/restore")
    def upload_backup(body: RestoreRequest, actor: Annotated[Principal, Depends(session_admin)]) -> dict[str, str]:
        try:
            payload = base64.b64decode(body.data, validate=True)
            if len(payload) > MAX_BACKUP_SIZE:
                raise BackupError("backup exceeds the 100 MiB limit")
            restore_backup(database.path, payload, body.password)
            database.initialize()
        except (ValueError, BackupError) as error:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(error)) from error
        audit.append(actor.username, "maintenance.backup.restore", "system")
        return {"status": "restored"}

    @app.post("/api/v1/maintenance/update", status_code=202)
    def request_update(actor: Annotated[Principal, Depends(session_admin)]) -> dict[str, str]:
        request_file = settings.data_dir / "update.request"
        if request_file.exists():
            raise HTTPException(status.HTTP_409_CONFLICT, "an update is already queued")
        audit.append(actor.username, "maintenance.update.request", "system")
        temporary = request_file.with_suffix(".tmp")
        temporary.write_text(json.dumps({"requested_at": datetime.now(UTC).isoformat(), "actor": actor.username}), encoding="utf-8")
        temporary.chmod(0o600)
        temporary.replace(request_file)
        return {"status": "queued"}

    return app
