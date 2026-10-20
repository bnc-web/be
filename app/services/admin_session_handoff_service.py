import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import delete, or_, update
from sqlalchemy.orm import Session

from app.models.admin_session_handoff import AdminSessionHandoff

HANDOFF_TTL = timedelta(seconds=60)


class AdminSessionHandoffService:
    @staticmethod
    def _digest(ticket: str) -> str:
        return hashlib.sha256(ticket.encode("ascii")).hexdigest()

    def issue(self, db: Session, user_id: UUID) -> tuple[str, datetime]:
        current_time = datetime.now(UTC)
        expires_at = current_time + HANDOFF_TTL
        ticket = secrets.token_urlsafe(32)
        db.execute(
            delete(AdminSessionHandoff).where(
                or_(
                    AdminSessionHandoff.expires_at <= current_time,
                    AdminSessionHandoff.consumed_at.is_not(None),
                )
            )
        )
        db.add(
            AdminSessionHandoff(
                ticket_digest=self._digest(ticket),
                user_id=user_id,
                expires_at=expires_at,
            )
        )
        db.commit()
        return ticket, expires_at

    def consume(self, db: Session, ticket: str) -> UUID | None:
        current_time = datetime.now(UTC)
        row = db.execute(
            update(AdminSessionHandoff)
            .where(
                AdminSessionHandoff.ticket_digest == self._digest(ticket),
                AdminSessionHandoff.consumed_at.is_(None),
                AdminSessionHandoff.expires_at > current_time,
            )
            .values(consumed_at=current_time)
            .returning(AdminSessionHandoff.user_id)
        ).one_or_none()
        db.commit()
        return row.user_id if row is not None else None
