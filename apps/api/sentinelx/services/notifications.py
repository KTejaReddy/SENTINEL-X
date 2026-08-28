"""Notification service — persisted + realtime."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from ..models import Notification
from ..realtime import hub


def notify(
    db: Session,
    *,
    org_id: str,
    kind: str,
    title: str,
    body: str = "",
    link: Optional[str] = None,
    user_id: Optional[str] = None,
) -> Notification:
    n = Notification(
        org_id=org_id,
        user_id=user_id,
        kind=kind,
        title=title,
        body=body,
        link=link,
        created_at=datetime.now(timezone.utc),
    )
    db.add(n)
    db.commit()
    db.refresh(n)
    hub.publish_sync(org_id, "notification", {"id": n.id, "kind": kind, "title": title, "body": body, "link": link})
    return n


def mark_read(db: Session, notification: Notification) -> Notification:
    notification.read = True
    db.commit()
    return notification
