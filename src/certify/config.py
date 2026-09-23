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

    @classmethod
    def from_env(cls, *, require_secret: bool = True) -> "Settings":
        secret = os.getenv("CERTIFY_SECRET", "")
        if require_secret and len(secret) < 32:
            raise RuntimeError("CERTIFY_SECRET must contain at least 32 characters")
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
        )
