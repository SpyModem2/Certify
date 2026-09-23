"""Authenticated encryption for credentials and managed private keys."""

from __future__ import annotations

import base64
import json
import os
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class SecretBox:
    """Derive a purpose-specific AEAD key from the externally stored master secret."""

    def __init__(self, master_secret: str):
        self._key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None, info=b"certify-storage-v1"
        ).derive(master_secret.encode())

    def encrypt(self, value: dict[str, Any] | str, *, context: str) -> str:
        raw = value.encode() if isinstance(value, str) else json.dumps(value).encode()
        nonce = os.urandom(12)
        sealed = AESGCM(self._key).encrypt(nonce, raw, context.encode())
        return "v1." + base64.urlsafe_b64encode(nonce + sealed).decode()

    def decrypt(self, value: str, *, context: str) -> bytes:
        if not value.startswith("v1."):
            raise ValueError("unsupported encrypted secret format")
        raw = base64.urlsafe_b64decode(value[3:])
        return AESGCM(self._key).decrypt(raw[:12], raw[12:], context.encode())
