from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _boolean(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True, slots=True)
class Settings:
    data_dir: Path
    secret: str
    session_minutes: int
    trusted_hosts: tuple[str, ...]
    debug: bool
    smtp_host: str = "localhost"
    smtp_port: int = 25
    mail_from: str = "certify@localhost"
    # None disables password expiry entirely.
    password_max_age_days: int | None = None

    @classmethod
    def from_env(cls, *, require_secret: bool = True) -> "Settings":
        secret = os.getenv("CERTIFY_SECRET", "")
        if require_secret and len(secret) < 32:
            raise RuntimeError("CERTIFY_SECRET must contain at least 32 characters")
        max_age = os.getenv("CERTIFY_PASSWORD_MAX_AGE_DAYS", "").strip()
        password_max_age_days = int(max_age) if max_age else None
        if password_max_age_days is not None and password_max_age_days < 1:
            raise RuntimeError("CERTIFY_PASSWORD_MAX_AGE_DAYS must be a positive integer")
        return cls(
            data_dir=Path(os.getenv("CERTIFY_DATA_DIR", "/var/lib/certify")),
            secret=secret,
            session_minutes=int(os.getenv("CERTIFY_SESSION_MINUTES", "30")),
            trusted_hosts=tuple(
                item.strip()
                for item in os.getenv(
                    "CERTIFY_TRUSTED_HOSTS", "localhost,127.0.0.1"
                ).split(",")
                if item.strip()
            ),
            debug=_boolean("CERTIFY_DEBUG"),
            smtp_host=os.getenv("CERTIFY_SMTP_HOST", "localhost"),
            smtp_port=int(os.getenv("CERTIFY_SMTP_PORT", "25")),
            mail_from=os.getenv("CERTIFY_MAIL_FROM", "certify@localhost"),
            password_max_age_days=password_max_age_days,
        )
