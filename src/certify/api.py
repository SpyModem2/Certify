from __future__ import annotations

import json
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel, Field

from .audit import AuditLog
from .config import Settings
from .database import Database
from .providers import validate_acme_directory
from .security import hash_password, sign_token, verify_password, verify_token, verify_totp


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str
    totp_code: str | None = Field(default=None, pattern=r"^\d{6}$")


class UserCreate(BaseModel):
    username: str = Field(pattern=r"^[a-zA-Z0-9_.@-]{1,128}$")
    password: str = Field(min_length=12, max_length=1024)
    role: Literal["admin", "operator", "auditor"] = "operator"


class CertificateCreate(BaseModel):
    common_name: str = Field(min_length=1, max_length=253)
    sans: list[str] = Field(default_factory=list, max_length=100)
    acme_directory: str
    challenge: Literal["http-01", "dns-01"]
    key_mode: Literal["managed", "csr"] = "managed"
    csr_pem: str | None = None


class TargetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    adapter: Literal["linux-ssh", "iis-ssh", "fortigate-7.4"]
    config: dict[str, object] = Field(default_factory=dict)


class Principal(BaseModel):
    id: int
    username: str
    role: str


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    database = Database(settings.data_dir / "certify.db")
    audit = AuditLog(database, settings.secret)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        database.initialize()
        yield

    app = FastAPI(title="Certify", version="0.1.0", lifespan=lifespan)
    app.state.database = database
    app.state.audit = audit
    app.state.settings = settings
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(settings.trusted_hosts))

    def principal(authorization: Annotated[str | None, Header()] = None) -> Principal:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication required")
        payload = verify_token(authorization[7:], settings.secret)
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
                cursor = connection.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)", (body.username, hash_password(body.password), body.role))
        except Exception as error:
            if "UNIQUE constraint" in str(error):
                raise HTTPException(status.HTTP_409_CONFLICT, "username already exists") from error
            raise
        audit.append(actor.username, "user.create", f"user:{cursor.lastrowid}", {"username": body.username, "role": body.role})
        return {"id": cursor.lastrowid, "username": body.username, "role": body.role}

    @app.get("/api/v1/certificates")
    def certificates(_: Annotated[Principal, Depends(principal)]) -> list[dict[str, object]]:
        with database.connect() as connection:
            rows = connection.execute("SELECT id,common_name,sans,challenge,key_mode,status,not_after,created_at FROM certificates ORDER BY id DESC").fetchall()
        return [{**dict(row), "sans": json.loads(row["sans"])} for row in rows]

    @app.post("/api/v1/certificates", status_code=201)
    def create_certificate(body: CertificateCreate, actor: Annotated[Principal, Depends(roles("admin", "operator"))]) -> dict[str, object]:
        try:
            validate_acme_directory(body.acme_directory)
        except ValueError as error:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(error)) from error
        if body.key_mode == "csr" and not body.csr_pem:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "csr_pem is required for CSR mode")
        with database.connect() as connection:
            cursor = connection.execute("INSERT INTO certificates(common_name,sans,acme_directory,challenge,key_mode,csr_pem,created_by) VALUES(?,?,?,?,?,?,?)", (body.common_name, json.dumps(body.sans), body.acme_directory, body.challenge, body.key_mode, body.csr_pem, actor.id))
        audit.append(actor.username, "certificate.request", f"certificate:{cursor.lastrowid}", {"common_name": body.common_name, "challenge": body.challenge, "key_mode": body.key_mode})
        return {"id": cursor.lastrowid, "status": "pending"}

    @app.get("/api/v1/certificates/{certificate_id}/download")
    def download_certificate(certificate_id: int, actor: Annotated[Principal, Depends(roles("admin", "operator"))], include_key: bool = False) -> Response:
        with database.connect() as connection:
            row = connection.execute("SELECT * FROM certificates WHERE id=?", (certificate_id,)).fetchone()
        if not row or not row["certificate_pem"]:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "issued certificate not found")
        content = row["certificate_pem"]
        if include_key:
            if not row["private_key_pem"]:
                raise HTTPException(status.HTTP_409_CONFLICT, "private key is not managed by Certify")
            content += "\n" + row["private_key_pem"]
        audit.append(actor.username, "certificate.download", f"certificate:{certificate_id}", {"private_key": include_key})
        return Response(content, media_type="application/x-pem-file", headers={"Content-Disposition": f'attachment; filename="certificate-{certificate_id}.pem"', "Cache-Control": "no-store"})

    @app.post("/api/v1/targets", status_code=201)
    def create_target(body: TargetCreate, actor: Annotated[Principal, Depends(roles("admin"))]) -> dict[str, object]:
        with database.connect() as connection:
            cursor = connection.execute("INSERT INTO targets(name,adapter,config) VALUES(?,?,?)", (body.name, body.adapter, json.dumps(body.config)))
        audit.append(actor.username, "target.create", f"target:{cursor.lastrowid}", {"name": body.name, "adapter": body.adapter})
        return {"id": cursor.lastrowid, "name": body.name, "adapter": body.adapter}

    @app.get("/api/v1/audit/verify")
    def verify_audit(_: Annotated[Principal, Depends(roles("admin", "auditor"))]) -> dict[str, object]:
        valid, broken_at = audit.verify()
        return {"valid": valid, "broken_at": broken_at}

    return app
