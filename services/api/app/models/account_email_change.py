"""Pending email changes; the email on User remains authoritative until verification."""

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class AccountEmailChangeRequest(Base):
    __tablename__ = "account_email_change_requests"
    __table_args__ = (
        CheckConstraint("expires_at > created_at", name="email_change_expiry_after_creation"),
        CheckConstraint(
            "consumed_at IS NULL OR cancelled_at IS NULL",
            name="email_change_terminal_exclusive",
        ),
        Index(
            "ix_email_change_user_pending",
            "tenant_id",
            "user_id",
            "expires_at",
            postgresql_where=text("consumed_at IS NULL AND cancelled_at IS NULL"),
        ),
        Index(
            "ux_email_change_one_pending_per_user",
            "user_id",
            unique=True,
            postgresql_where=text("consumed_at IS NULL AND cancelled_at IS NULL"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    previous_email: Mapped[str] = mapped_column(String(255), nullable=False)
    proposed_email: Mapped[str] = mapped_column(String(255), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("NOW()"), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cancelled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
