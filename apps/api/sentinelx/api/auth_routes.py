"""/auth, /organizations, /users routes."""
from __future__ import annotations

from datetime import datetime, timezone

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from ..config import settings
from ..db import get_db
from ..models import Organization, User
from ..schemas import (
    LoginRequest,
    LoginResponse,
    OrganizationCreate,
    OrganizationOut,
    RefreshRequest,
    UserCreate,
    UserOut,
)
from ..security import (
    create_access_token,
    create_refresh_token,
    hash_password,
    revoke_all_user_tokens,
    rotate_refresh_token,
    verify_password,
)
from ..security.lockout import account_lock_status, lock_status_for_user, record_login_attempt
from ..security.audit import AuditService
from ..security.rbac import ROLES
from .deps import (
    RequestContext,
    check_permission,
    ctx_audit,
    get_request_context,
    require_org,
)

router = APIRouter(tags=["auth"])


def _login_response(db: Session, user: User, ip: str | None, ua: str | None, request_id: str) -> LoginResponse:
    access = create_access_token(user)
    refresh = create_refresh_token(db, user, ip, ua)
    user.last_login_at = datetime.now(timezone.utc)
    db.commit()
    return LoginResponse(access_token=access, refresh_token=refresh, user=UserOut.model_validate(user))


@router.post("/auth/login", response_model=LoginResponse)
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent")

    # --- Login hardening: lockout + rate limiting (pre-auth, DB-backed) ---
    lock = account_lock_status(db, body.email, ip)
    if lock["account_locked"]:
        AuditService(db).log("auth.login.locked", user_id=None, detail={"email": body.email, "retry_after": lock["retry_after_seconds"]}, ip=ip, user_agent=ua, outcome="denied")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"message": "Account temporarily locked due to too many failed attempts", "retry_after_seconds": lock["retry_after_seconds"]},
            headers={"Retry-After": str(max(lock["retry_after_seconds"], 1))},
        )
    if lock["ip_blocked"]:
        AuditService(db).log("auth.login.rate_limited", user_id=None, detail={"email": body.email, "ip": ip}, ip=ip, user_agent=ua, outcome="denied")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"message": "Too many login attempts from this address", "retry_after_seconds": lock["ip_retry_after_seconds"]},
            headers={"Retry-After": str(max(lock["ip_retry_after_seconds"], 1))},
        )

    user = db.query(User).filter(User.email == body.email.lower()).first()
    if user is None or not verify_password(body.password, user.password_hash):
        record_login_attempt(db, body.email, ip, success=False, user_id=user.id if user else None)
        AuditService(db).log("auth.login", user_id=user.id if user else None, detail={"email": body.email}, ip=ip, user_agent=ua, outcome="denied")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if user.status != "ACTIVE":
        AuditService(db).log("auth.login", org_id=user.org_id, user_id=user.id, detail={"reason": "inactive"}, outcome="denied")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is not active")

    record_login_attempt(db, body.email, ip, success=True, user_id=user.id)
    AuditService(db).log("auth.login", org_id=user.org_id, user_id=user.id, detail={"email": body.email}, ip=ip, user_agent=ua, outcome="success")
    return _login_response(db, user, ip, ua, "")


@router.post("/auth/refresh", response_model=LoginResponse)
def refresh(body: RefreshRequest, request: Request, db: Session = Depends(get_db)):
    access, refresh = rotate_refresh_token(db, body.refresh_token, request.client.host if request.client else None, request.headers.get("user-agent"))
    payload = jwt.decode(access, settings.JWT_SECRET, algorithms=["HS256"])
    user = db.get(User, payload["sub"])
    return LoginResponse(access_token=access, refresh_token=refresh, user=UserOut.model_validate(user))


@router.post("/auth/logout")
def logout(ctx: RequestContext = Depends(get_request_context), db: Session = Depends(get_db)):
    revoked = revoke_all_user_tokens(db, ctx.user.id)
    ctx_audit(ctx, "auth.logout", detail={"revoked": revoked})
    return {"ok": True, "revoked": revoked}


@router.get("/auth/me", response_model=UserOut)
def me(ctx: RequestContext = Depends(get_request_context)):
    return ctx.user


# ---------- Organizations ----------

@router.post("/organizations", response_model=OrganizationOut)
def create_organization(body: OrganizationCreate, ctx: RequestContext = Depends(get_request_context), db: Session = Depends(get_db)):
    check_permission(ctx.user, "org:manage")
    if db.query(Organization).filter(Organization.slug == body.slug).first():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Slug already in use")
    org = Organization(name=body.name, slug=body.slug, plan=body.plan)
    db.add(org)
    db.commit()
    db.refresh(org)
    ctx_audit(ctx, "org.create", resource_type="organization", resource_id=org.id, detail={"name": org.name, "slug": org.slug})
    return org


@router.get("/organizations", response_model=list[OrganizationOut])
def list_organizations(ctx: RequestContext = Depends(get_request_context), db: Session = Depends(get_db)):
    if ctx.user.role == "SUPER_ADMIN":
        return db.query(Organization).all()
    if ctx.org:
        return [ctx.org]
    return []


# ---------- Users ----------

@router.post("/users", response_model=UserOut)
def create_user(body: UserCreate, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "users:write")
    if body.role not in ROLES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid role: {body.role}")
    org_id = ctx.org.id
    if db.query(User).filter(User.email == body.email.lower()).first():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")
    user = User(
        org_id=org_id,
        email=body.email.lower(),
        name=body.name,
        password_hash=hash_password(body.password),
        role=body.role,
        status="ACTIVE",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    ctx_audit(ctx, "user.create", resource_type="user", resource_id=user.id, detail={"email": user.email, "role": user.role})
    return user


@router.get("/users", response_model=list[UserOut])
def list_users(ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "users:read")
    return db.query(User).filter(User.org_id == ctx.org.id).all()


@router.patch("/users/{user_id}", response_model=UserOut)
def update_user(user_id: str, body: dict, ctx: RequestContext = Depends(require_org), db: Session = Depends(get_db)):
    check_permission(ctx.user, "users:write")
    user = db.query(User).filter(User.id == user_id, User.org_id == ctx.org.id).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if "role" in body and body["role"] in ROLES:
        user.role = body["role"]
    if "status" in body and body["status"] in {"ACTIVE", "DISABLED"}:
        user.status = body["status"]
        if body["status"] == "DISABLED":
            revoke_all_user_tokens(db, user.id)
    db.commit()
    db.refresh(user)
    ctx_audit(ctx, "user.update", resource_type="user", resource_id=user.id, detail=body)
    return user
