"""Encryption at rest for sensitive fields (credentials, secrets).

Uses Fernet (AES-128-CBC + HMAC) from the `cryptography` package. The key is
derived from ENCRYPTION_KEY. Never log ciphertext or plaintext secrets.
"""
from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from ..config import settings

_fernet: Fernet | None = None


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        key = base64.urlsafe_b64encode(
            hashlib.sha256(settings.ENCRYPTION_KEY.encode()).digest()
        )
        _fernet = Fernet(key)
    return _fernet


def encrypt_str(plaintext: str) -> str:
    if not plaintext:
        return plaintext
    return _get_fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_str(ciphertext: str) -> str:
    if not ciphertext:
        return ciphertext
    try:
        return _get_fernet().decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError):
        return "<unable-to-decrypt>"
