
from datetime import datetime

from sqlalchemy import (
    DateTime,
    Boolean,
    ForeignKey,
    String,
    UniqueConstraint,
    CheckConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(
        String(50), unique=True, nullable=False
    )
    email: Mapped[str] = mapped_column(
        String(255), unique=True, nullable=False
    )
    password_hash: Mapped[str] = mapped_column(
        String(255), nullable=False
    )
    role: Mapped[str] = mapped_column(
        String(20), nullable=False, default="viewer"
    )


class Document(Base):
    __tablename__ = "documents"

    id: Mapped[int] = mapped_column(primary_key=True)
    filename: Mapped[str] = mapped_column(
        String(255), nullable=False
    )
    category: Mapped[str] = mapped_column(
        String(100), nullable=False, default="uncategorized"
    )
    storage_path: Mapped[str] = mapped_column(
        String(500), unique=True, nullable=False
    )
    owner_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    is_deleted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")

class DocumentPermission(Base):
    __tablename__ = "document_permissions"

    __table_args__ = (
        UniqueConstraint(
            "document_id",
            "user_id",
            name="uq_document_permission_user",
        ),
        CheckConstraint(
            "permission IN ('READ', 'EDIT')",
            name="ck_document_permission_valid",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    document_id: Mapped[int] = mapped_column(
        ForeignKey("documents.id"), nullable=False
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"), nullable=False
    )
    permission: Mapped[str] = mapped_column(
        String(10), nullable=False
    )
class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    document_id: Mapped[int | None] = mapped_column(
        ForeignKey("documents.id"), nullable=True
    )
    action: Mapped[str] = mapped_column(
        String(50), nullable=False
    )
    outcome: Mapped[str] = mapped_column(
        String(20), nullable=False
    )
    details: Mapped[str] = mapped_column(
        String(500), nullable=False, default=""
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    previous_hash: Mapped[str] = mapped_column(
        String(64),nullable=False,default="0" * 64,)
    entry_hash: Mapped[str] = mapped_column(String(64),nullable=False,default="0" * 64,)