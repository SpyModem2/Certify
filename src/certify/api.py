from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel, Field, field_validator

from .audit import AuditLog
from .config import Settings
from .database import Database
from .mailer import send_local_mail
from .providers import validate_acme_directory
from .security import PASSWORD_POLICY, hash_password, sign_token, validate_password, verify_password, verify_token, verify_totp
from .secrets import SecretBox


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str
    totp_code: str | None = Field(default=None, pattern=r"^\d{6}$")


class UserCreate(BaseModel):
    username: str = Field(pattern=r"^[a-zA-Z0-9_.@-]{1,128}$")
    password: str = Field(min_length=14, max_length=1024, description=PASSWORD_POLICY)
    role: Literal["admin", "operator", "auditor"] = "operator"
    email: str | None = Field(default=None, max_length=320)

    @field_validator("password")
    @classmethod
    def complex_password(cls, password: str) -> str:
        validate_password(password)
        return password


class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(min_length=14, max_length=1024, description=PASSWORD_POLICY)

    @field_validator("new_password")
    @classmethod
    def complex_password(cls, password: str) -> str:
        validate_password(password)
        return password


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_. -]+$")
    scope: Literal["read", "read_write"] = "read"


class CertificateCreate(BaseModel):
    common_name: str = Field(min_length=1, max_length=253)
    sans: list[str] = Field(default_factory=list, max_length=100)
    acme_directory: str
    challenge: Literal["http-01", "dns-01"]
    key_mode: Literal["managed", "csr"] = "managed"
    csr_pem: str | None = None
    target_ids: list[int] = Field(default_factory=list, max_length=100)


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


class Principal(BaseModel):
    id: int
    username: str
    role: str
    api_key_id: int | None = None
    api_scope: Literal["read", "read_write"] | None = None


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    database = Database(settings.data_dir / "certify.db")
    audit = AuditLog(database, settings.secret)
    secret_box = SecretBox(settings.secret)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        database.initialize()
        yield

    app = FastAPI(title="Certify", version="0.1.0", lifespan=lifespan)
    app.state.database = database
    app.state.audit = audit
    app.state.settings = settings
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(settings.trusted_hosts))

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
        return Principal(id=int(payload["sub"]), username=payload["username"], role=payload["role"])

    def roles(*allowed: str):
        def dependency(user: Annotated[Principal, Depends(principal)]) -> Principal:
            if user.role not in allowed:
                raise HTTPException(status.HTTP_403_FORBIDDEN, "insufficient role")
            return user
        return dependency

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/", response_class=Response)
    def index(request: Request) -> Response:
        language = request.headers.get("accept-language", "en").lower()
        title = "Zertifikatsverwaltung" if language.startswith("de") else "Certificate management"
        body = f"""<!doctype html><html lang=\"{'de' if language.startswith('de') else 'en'}\"><meta charset=\"utf-8\"><title>Certify</title><style>body{{font:16px system-ui;max-width:60rem;margin:4rem auto;padding:0 1rem}}code{{background:#eee;padding:.2rem}}</style><h1>Certify</h1><p>{title}</p><p>API: <a href=\"/docs\"><code>/docs</code></a></p></html>"""
        return Response(body, media_type="text/html", headers={"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"})

    @app.post("/api/v1/auth/login")
    def login(body: LoginRequest, request: Request) -> dict[str, str]:
        with database.connect() as connection:
            row = connection.execute("SELECT * FROM users WHERE username=? AND active=1", (body.username,)).fetchone()
        valid = row is not None and verify_password(body.password, row["password_hash"])
        valid = valid and (not row["totp_secret"] or (body.totp_code is not None and verify_totp(row["totp_secret"], body.totp_code)))
        if not valid:
            audit.append(body.username, "auth.login.failed", "session", {"client": request.client.host if request.client else "unknown"})
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
        expires = datetime.now(UTC) + timedelta(minutes=settings.session_minutes)
        token = sign_token({"sub": row["id"], "username": row["username"], "role": row["role"], "exp": int(expires.timestamp()), "nonce": time.time_ns()}, settings.secret)
        audit.append(row["username"], "auth.login", "session")
        return {"access_token": token, "token_type": "bearer", "expires_at": expires.isoformat()}

    @app.post("/api/v1/users", status_code=201)
    def create_user(body: UserCreate, actor: Annotated[Principal, Depends(roles("admin"))]) -> dict[str, object]:
        try:
            with database.connect() as connection:
                password_hash = hash_password(body.password)
                cursor = connection.execute("INSERT INTO users(username,password_hash,role,email) VALUES(?,?,?,?)", (body.username, password_hash, body.role, body.email))
                connection.execute("INSERT INTO password_history(user_id,password_hash) VALUES(?,?)", (cursor.lastrowid, password_hash))
        except Exception as error:
            if "UNIQUE constraint" in str(error):
                raise HTTPException(status.HTTP_409_CONFLICT, "username already exists") from error
            raise
        audit.append(actor.username, "user.create", f"user:{cursor.lastrowid}", {"username": body.username, "role": body.role})
        return {"id": cursor.lastrowid, "username": body.username, "role": body.role}

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
            connection.execute("UPDATE users SET password_hash=? WHERE id=?", (password_hash, actor.id))
            connection.execute("INSERT INTO password_history(user_id,password_hash) VALUES(?,?)", (actor.id, password_hash))
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
                rows = connection.execute("SELECT id,common_name,sans,challenge,key_mode,status,not_after,created_at FROM certificates ORDER BY id DESC").fetchall()
            else:
                rows = connection.execute("SELECT c.id,c.common_name,c.sans,c.challenge,c.key_mode,c.status,c.not_after,c.created_at FROM certificates c JOIN certificate_users cu ON cu.certificate_id=c.id WHERE cu.user_id=? ORDER BY c.id DESC", (actor.id,)).fetchall()
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
        try:
            validate_acme_directory(body.acme_directory)
        except ValueError as error:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(error)) from error
        if body.key_mode == "csr" and not body.csr_pem:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "csr_pem is required for CSR mode")
        with database.connect() as connection:
            requested_targets = list(dict.fromkeys(body.target_ids))
            if requested_targets:
                placeholders = ",".join("?" for _ in requested_targets)
                existing = connection.execute(
                    f"SELECT id FROM targets WHERE id IN ({placeholders})", requested_targets
                ).fetchall()
                if len(existing) != len(requested_targets):
                    raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "one or more target systems do not exist")
            cursor = connection.execute("INSERT INTO certificates(common_name,sans,acme_directory,challenge,key_mode,csr_pem,created_by) VALUES(?,?,?,?,?,?,?)", (body.common_name, json.dumps(body.sans), body.acme_directory, body.challenge, body.key_mode, body.csr_pem, actor.id))
            connection.execute("INSERT INTO certificate_users(certificate_id,user_id) VALUES(?,?)", (cursor.lastrowid, actor.id))
            connection.executemany(
                "INSERT INTO certificate_targets(certificate_id,target_id) VALUES(?,?)",
                ((cursor.lastrowid, target_id) for target_id in requested_targets),
            )
        audit.append(actor.username, "certificate.request", f"certificate:{cursor.lastrowid}", {"common_name": body.common_name, "challenge": body.challenge, "key_mode": body.key_mode, "target_ids": requested_targets})
        return {"id": cursor.lastrowid, "status": "pending"}

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

    return app
