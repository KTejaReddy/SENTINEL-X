"""Authentication.

- Passwords hashed with scrypt (stdlib, memory-hard).
- JWT access tokens (short-lived) + DB-backed refresh tokens (revocable).
- MFA-ready: the user model carries mfa_enabled; token claims include mfa_verified.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from ..config import settings
from ..db import get_db
from ..models import RefreshToken, User

_bearer = HTTPBearer(auto_error=False)

SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    derived = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P
    )
    return "$scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(derived).decode()


def verify_password(password: str, stored: str) -> bool:
    try:
        _, _, salt_b64, hash_b64 = stored.split("$")
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
    except (ValueError, TypeError):
        return False
    derived = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P
    )
    return hmac.compare_digest(derived, expected)


def create_access_token(user: User) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user.id,
        "org_id": user.org_id,
        "role": user.role,
        "mfa_verified": not user.mfa_enabled,
        "type": "access",
        "iat": now,
        "exp": now + timedelta(minutes=settings.JWT_ACCESS_TTL_MINUTES),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm="HS256")


def decode_token(token: str) -> dict:
    return jwt.decode(token, settings.JWT_SECRET, algorithms=["HS256"])


def create_refresh_token(db: Session, user: User, ip: str | None, user_agent: str | None) -> str:
    raw = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(raw.encode()).hexdigest()
    db.add(
        RefreshToken(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=datetime.now(timezone.utc) + timedelta(days=settings.JWT_REFRESH_TTL_DAYS),
            ip=ip,
            user_agent=(user_agent or "")[:255] or None,
        )
    )
    db.commit()
    return raw


def _get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    try:
        payload = decode_token(credentials.credentials)
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    if payload.get("type") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
    user = db.get(User, payload.get("sub"))
    if user is None or user.status != "ACTIVE":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Account unavailable")
    return user


get_current_user = _get_current_user


def require_permission(permission: str):
    """Dependency factory enforcing a permission for the current user's role."""

    def dependency(user: User = Depends(get_current_user)) -> User:
        from .rbac import has_permission

        if not has_permission(user.role, permission):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Missing permission: {permission}")
        return user

    return dependency


def _as_aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def rotate_refresh_token(db: Session, refresh_token: str, ip: str | None, user_agent: str | None) -> tuple[str, str]:
    """Validate a refresh token, revoke it, and issue a new pair."""
    token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    row = (
        db.query(RefreshToken)
        .filter(RefreshToken.token_hash == token_hash)
        .first()
    )
    now = datetime.now(timezone.utc)
    if row is None or row.revoked_at is not None or _as_aware(row.expires_at) < now:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
    user = db.get(User, row.user_id)
    if user is None or user.status != "ACTIVE":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Account unavailable")
    row.revoked_at = now
    db.commit()
    access = create_access_token(user)
    refresh = create_refresh_token(db, user, ip, user_agent)
    return access, refresh


def revoke_all_user_tokens(db: Session, user_id: str) -> int:
    rows = db.query(RefreshToken).filter(
        RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None)
    ).all()
    now = datetime.now(timezone.utc)
    for row in rows:
        row.revoked_at = now
    db.commit()
    return len(rows)
