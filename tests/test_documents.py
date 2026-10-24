from app.models import AuditLog
from datetime import datetime, timezone
from sqlalchemy import select
from app.models import AuditLog
from app.database import get_db
from app.main import app, STORAGE_DIR, verify_audit_chain
from app.models import Document, DocumentPermission, User
from app.security import create_access_token, hash_password


def create_test_user(db, username, email):
    user = User(
        username=username,
        email=email,
        password_hash=hash_password("SecurePass123!"),
        role="viewer",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def create_test_document(db, owner_id, filename, storage_path):
    document = Document(
        filename=filename,
        category="Reports",
        storage_path=str(storage_path),
        owner_id=owner_id,
        created_at=datetime.now(timezone.utc),
    )
    db.add(document)
    db.commit()
    db.refresh(document)
    return document


def test_other_user_cannot_download_private_document(client, tmp_path):
    file_path = tmp_path / "private.txt"
    file_path.write_text("This is confidential.")

    db = next(app.dependency_overrides[get_db]())
    try:
        owner = create_test_user(
            db, "owner01", "owner01@example.com"
        )
        other_user = create_test_user(
            db, "other01", "other01@example.com"
        )
        document = create_test_document(
            db, owner.id, "private.txt", file_path.resolve()
        )

        other_user_id = other_user.id
        document_id = document.id
    finally:
        db.close()

    token = create_access_token(other_user_id)

    response = client.get(
        f"/documents/{document_id}/download",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403


def test_owner_can_download_private_document(client):
    file_path = STORAGE_DIR / "owner-file.txt"
    file_path.write_text("Owner's private document.")

    db = next(app.dependency_overrides[get_db]())
    try:
        owner = create_test_user(
            db, "owner02", "owner02@example.com"
        )
        document = create_test_document(
            db, owner.id, "owner-file.txt", file_path.resolve()
        )

        owner_id = owner.id
        document_id = document.id
    finally:
        db.close()

    try:
        token = create_access_token(owner_id)

        response = client.get(
            f"/documents/{document_id}/download",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200
        assert response.content == b"Owner's private document."
    finally:
        if file_path.exists():
            file_path.unlink()


def test_owner_can_grant_read_permission(client):
    db = next(app.dependency_overrides[get_db]())
    try:
        owner = create_test_user(
            db, "owner_grant", "owner_grant@example.com"
        )
        recipient = create_test_user(
            db, "recipient_grant", "recipient_grant@example.com"
        )

        document = create_test_document(
            db,
            owner.id,
            "grant-test.txt",
            STORAGE_DIR / "grant-test.txt",
        )

        owner_id = owner.id
        recipient_id = recipient.id
        document_id = document.id
    finally:
        db.close()

    owner_token = create_access_token(owner_id)

    response = client.post(
        f"/documents/{document_id}/permissions",
        json={
            "user_id": recipient_id,
            "permission": "READ",
        },
        headers={"Authorization": f"Bearer {owner_token}"},
    )

    assert response.status_code == 201
    assert response.json()["document_id"] == document_id
    assert response.json()["user_id"] == recipient_id
    assert response.json()["permission"] == "READ"


def test_recipient_can_download_after_read_permission(client):
    file_path = STORAGE_DIR / "shared-test.txt"
    file_path.write_text("Shared document content.")

    db = next(app.dependency_overrides[get_db]())
    try:
        owner = create_test_user(
            db, "owner_share", "owner_share@example.com"
        )
        recipient = create_test_user(
            db, "recipient_share", "recipient_share@example.com"
        )
        document = create_test_document(
            db, owner.id, "shared-test.txt", file_path.resolve()
        )

        db.add(
            DocumentPermission(
                document_id=document.id,
                user_id=recipient.id,
                permission="READ",
            )
        )
        db.commit()

        recipient_id = recipient.id
        document_id = document.id
    finally:
        db.close()

    try:
        token = create_access_token(recipient_id)

        response = client.get(
            f"/documents/{document_id}/download",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200
        assert response.content == b"Shared document content."
    finally:
        if file_path.exists():
            file_path.unlink()


def test_recipient_cannot_download_after_permission_revoked(client):
    file_path = STORAGE_DIR / "revoked-test.txt"
    file_path.write_text("Previously shared content.")

    db = next(app.dependency_overrides[get_db]())
    try:
        owner = create_test_user(
            db, "owner_revoke", "owner_revoke@example.com"
        )
        recipient = create_test_user(
            db, "recipient_revoke", "recipient_revoke@example.com"
        )
        document = create_test_document(
            db, owner.id, "revoked-test.txt", file_path.resolve()
        )

        permission = DocumentPermission(
            document_id=document.id,
            user_id=recipient.id,
            permission="READ",
        )
        db.add(permission)
        db.commit()

        # Simulate revocation by removing the permission.
        db.delete(permission)
        db.commit()

        recipient_id = recipient.id
        document_id = document.id
    finally:
        db.close()

    try:
        token = create_access_token(recipient_id)

        response = client.get(
            f"/documents/{document_id}/download",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 403
    finally:
        if file_path.exists():
            file_path.unlink()


def test_non_owner_cannot_grant_permission(client):
    db = next(app.dependency_overrides[get_db]())
    try:
        owner = create_test_user(
            db, "owner_denied", "owner_denied@example.com"
        )
        other_user = create_test_user(
            db, "other_denied", "other_denied@example.com"
        )
        recipient = create_test_user(
            db, "recipient_denied", "recipient_denied@example.com"
        )
        document = create_test_document(
            db,
            owner.id,
            "denied-test.txt",
            STORAGE_DIR / "denied-test.txt",
        )

        other_user_id = other_user.id
        recipient_id = recipient.id
        document_id = document.id
    finally:
        db.close()

    token = create_access_token(other_user_id)

    response = client.post(
        f"/documents/{document_id}/permissions",
        json={
            "user_id": recipient_id,
            "permission": "READ",
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == (
        "Only the document owner can grant permissions"
    )

def test_owner_can_revoke_read_permission(client):
    db = next(app.dependency_overrides[get_db]())
    try:
        owner = create_test_user(
            db, "owner_revoke_api", "owner_revoke_api@example.com"
        )
        recipient = create_test_user(
            db, "recipient_revoke_api", "recipient_revoke_api@example.com"
        )
        document = create_test_document(
            db,
            owner.id,
            "revoke-api-test.txt",
            STORAGE_DIR / "revoke-api-test.txt",
        )

        permission = DocumentPermission(
            document_id=document.id,
            user_id=recipient.id,
            permission="READ",
        )
        db.add(permission)
        db.commit()

        owner_id = owner.id
        recipient_id = recipient.id
        document_id = document.id
    finally:
        db.close()

    owner_token = create_access_token(owner_id)

    response = client.delete(
        f"/documents/{document_id}/permissions/{recipient_id}",
        headers={"Authorization": f"Bearer {owner_token}"},
    )

    assert response.status_code == 200
    assert response.json()["message"] == "Permission revoked successfully"

    # Confirm the recipient can no longer download the document.
    recipient_token = create_access_token(recipient_id)
    download_response = client.get(
        f"/documents/{document_id}/download",
        headers={"Authorization": f"Bearer {recipient_token}"},
    )

    assert download_response.status_code == 403

def test_successful_upload_creates_audit_log(client):
    # Register a user.
    registration = client.post(
        "/auth/register",
        json={
            "username": "audit_uploader",
            "email": "audit_uploader@example.com",
            "password": "SecurePass123!",
        },
    )
    assert registration.status_code == 201

    # Log in to obtain an access token.
    login = client.post(
        "/auth/login",
        data={
            "username": "audit_uploader",
            "password": "SecurePass123!",
        },
    )
    assert login.status_code == 200
    token = login.json()["access_token"]

    # Upload a small text file.
    response = client.post(
        "/documents/upload",
        data={"category": "Tests"},
        files={
            "file": (
                "audit-test.txt",
                b"Audit trail test content",
                "text/plain",
            )
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 201
    document_id = response.json()["id"]

    # Check the isolated test database for the audit record.
    db = next(app.dependency_overrides[get_db]())
    try:
        audit = (
            db.query(AuditLog)
            .filter(
                AuditLog.document_id == document_id,
                AuditLog.action == "UPLOAD",
                AuditLog.outcome == "SUCCESS",
            )
            .first()
        )

        assert audit is not None
        assert audit.user_id == registration.json()["id"]
    finally:
        db.close()

    # Clean up the uploaded file.
    from pathlib import Path

    stored_path = Path(response.json().get("storage_path", ""))
    if stored_path.is_file():
        stored_path.unlink()
def test_granting_permission_creates_audit_log(client):
    from app.database import get_db
    from app.main import app
    from app.models import Base
    from app.security import create_access_token

    # Get the test database session from the existing fixture.
    db_generator = app.dependency_overrides[get_db]()
    db = next(db_generator)

    try:
        owner = create_test_user(
            db, "audit_owner", "audit_owner@example.com"
        )
        recipient = create_test_user(
            db, "audit_recipient", "audit_recipient@example.com"
        )

        document = create_test_document(
            db,
            owner.id,
            "audit-report.txt",
            STORAGE_DIR / "audit-report.txt",
        )

        token = create_access_token(owner.id)

        response = client.post(
            f"/documents/{document.id}/permissions",
            json={
                "user_id": recipient.id,
                "permission": "READ",
            },
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 201

        audit_entry = db.scalar(
            select(AuditLog).where(
                AuditLog.document_id == document.id,
                AuditLog.user_id == owner.id,
                AuditLog.action == "PERMISSION_GRANTED",
                AuditLog.outcome == "SUCCESS",
            )
        )

        assert audit_entry is not None
        assert str(recipient.id) in audit_entry.details

    finally:
        db_generator.close()

def test_revoking_permission_creates_audit_log(client):
    from sqlalchemy import select
    from app.models import AuditLog
    from app.security import create_access_token

    db_generator = app.dependency_overrides[get_db]()
    db = next(db_generator)

    try:
        owner = create_test_user(
            db, "revoke_audit_owner", "revoke_audit_owner@example.com"
        )
        recipient = create_test_user(
            db, "revoke_audit_recipient", "revoke_audit_recipient@example.com"
        )

        document = create_test_document(
            db,
            owner.id,
            "revoke-audit-report.txt",
            STORAGE_DIR / "revoke-audit-report.txt",
        )

        permission = DocumentPermission(
            document_id=document.id,
            user_id=recipient.id,
            permission="READ",
        )
        db.add(permission)
        db.commit()

        token = create_access_token(owner.id)

        response = client.delete(
            f"/documents/{document.id}/permissions/{recipient.id}",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200

        audit_entry = db.scalar(
            select(AuditLog).where(
                AuditLog.document_id == document.id,
                AuditLog.user_id == owner.id,
                AuditLog.action == "PERMISSION_REVOKED",
                AuditLog.outcome == "SUCCESS",
            )
        )

        assert audit_entry is not None
        assert str(recipient.id) in audit_entry.details

    finally:
        db_generator.close()


def test_empty_audit_chain_is_valid():
    from app.models import Base
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(bind=engine)

    TestSession = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
    )
    db = TestSession()

    try:
        assert verify_audit_chain(db) is True
    finally:
        db.close()
        engine.dispose()

def test_audit_chain_detects_tampering():
    from app.models import Base
    from app.main import record_audit
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(bind=engine)
    TestSession = sessionmaker(bind=engine)
    db = TestSession()

    try:
        record_audit(
            db=db,
            user_id=None,
            document_id=None,
            action="TEST",
            outcome="SUCCESS",
            details="Original event",
        )

        assert verify_audit_chain(db) is True

        entry = db.query(AuditLog).first()
        entry.details = "Modified event"
        db.commit()

        assert verify_audit_chain(db) is False
    finally:
        db.close()
        engine.dispose()
def test_audit_chain_with_multiple_records():
    from app.models import Base
    from app.main import record_audit
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    TestSession = sessionmaker(bind=engine)
    db = TestSession()

    try:
        record_audit(
            db, None, None, "UPLOAD", "SUCCESS", "First event"
        )
        record_audit(
            db, None, None, "DOWNLOAD", "SUCCESS", "Second event"
        )

        assert verify_audit_chain(db) is True

        entries = db.query(AuditLog).order_by(AuditLog.id).all()
        assert len(entries) == 2
        assert entries[1].previous_hash == entries[0].entry_hash
    finally:
        db.close()
        engine.dispose()
def test_invalid_permission_value_is_rejected():
    import pytest
    from sqlalchemy import create_engine
    from sqlalchemy.exc import IntegrityError
    from sqlalchemy.orm import sessionmaker
    from app.models import Base, User, Document, DocumentPermission
    from datetime import datetime, timezone
    from pathlib import Path
    import tempfile

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    TestSession = sessionmaker(bind=engine)
    db = TestSession()

    try:
        user = User(
            username="owner",
            email="owner@example.com",
            password_hash="test-hash",
            role="viewer",
        )
        db.add(user)
        db.commit()

        document = Document(
            filename="report.txt",
            category="Reports",
            storage_path="test-report.txt",
            owner_id=user.id,
            created_at=datetime.now(timezone.utc),
        )
        db.add(document)
        db.commit()

        permission = DocumentPermission(
            document_id=document.id,
            user_id=user.id,
            permission="INVALID",
        )
        db.add(permission)

        with pytest.raises(IntegrityError):
            db.commit()
    finally:
        db.close()
        engine.dispose()
def test_duplicate_document_permission_is_rejected():
    import pytest
    from sqlalchemy import create_engine
    from sqlalchemy.exc import IntegrityError
    from sqlalchemy.orm import sessionmaker
    from datetime import datetime, timezone
    from app.models import Base, User, Document, DocumentPermission

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    TestSession = sessionmaker(bind=engine)
    db = TestSession()

    try:
        owner = User(
            username="owner",
            email="owner@example.com",
            password_hash="test-hash",
            role="viewer",
        )
        viewer = User(
            username="viewer",
            email="viewer@example.com",
            password_hash="test-hash",
            role="viewer",
        )
        db.add_all([owner, viewer])
        db.commit()

        document = Document(
            filename="report.txt",
            category="Reports",
            storage_path="report.txt",
            owner_id=owner.id,
            created_at=datetime.now(timezone.utc),
        )
        db.add(document)
        db.commit()

        first = DocumentPermission(
            document_id=document.id,
            user_id=viewer.id,
            permission="READ",
        )
        db.add(first)
        db.commit()

        duplicate = DocumentPermission(
            document_id=document.id,
            user_id=viewer.id,
            permission="EDIT",
        )
        db.add(duplicate)

        with pytest.raises(IntegrityError):
            db.commit()

    finally:
        db.close()
        engine.dispose()

def test_denied_download_creates_audit_log(client):
    db = next(app.dependency_overrides[get_db]())

    try:
        owner = create_test_user(
            db, "denied_owner", "denied_owner@example.com"
        )
        recipient = create_test_user(
            db, "denied_recipient", "denied_recipient@example.com"
        )
        document = create_test_document(
            db,
            owner.id,
            "private-report.txt",
            STORAGE_DIR / "private-report.txt",
        )

        recipient_id = recipient.id
        document_id = document.id
    finally:
        db.close()

    token = create_access_token(recipient_id)

    response = client.get(
        f"/documents/{document_id}/download",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403

    db = next(app.dependency_overrides[get_db]())
    try:
        audit = (
            db.query(AuditLog)
            .filter(
                AuditLog.user_id == recipient_id,
                AuditLog.document_id == document_id,
                AuditLog.action == "DOWNLOAD",
                AuditLog.outcome == "DENIED",
            )
            .first()
        )

        assert audit is not None
    finally:
        db.close()

def test_non_admin_cannot_access_admin_route(client):
    db = next(app.dependency_overrides[get_db]())

    try:
        user = create_test_user(
            db, "normal_user", "normal_user@example.com"
        )
        user_id = user.id
    finally:
        db.close()

    token = create_access_token(user_id)

    response = client.get(
        "/admin/audit-logs",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403

def test_admin_can_access_audit_logs(client):
    db = next(app.dependency_overrides[get_db]())

    try:
        admin = create_test_user(
            db, "test_admin", "test_admin@example.com"
        )
        admin.role = "admin"
        db.commit()
        admin_id = admin.id
    finally:
        db.close()

    token = create_access_token(admin_id)

    response = client.get(
        "/admin/audit-logs",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert isinstance(response.json(), list)
def test_edit_permission_allows_metadata_update(client):
    from app.database import get_db
    from app.main import app
    from app.models import DocumentPermission
    from app.security import create_access_token

    db_generator = app.dependency_overrides[get_db]()
    db = next(db_generator)

    try:
        owner = create_test_user(
            db, "metadata_owner", "metadata_owner@example.com"
        )
        editor = create_test_user(
            db, "metadata_editor", "metadata_editor@example.com"
        )
        document = create_test_document(
            db,
            owner.id,
            "original.txt",
            STORAGE_DIR / "metadata-original.txt",
        )

        db.add(
            DocumentPermission(
                document_id=document.id,
                user_id=editor.id,
                permission="EDIT",
            )
        )
        db.commit()

        document_id = document.id
        editor_id = editor.id
    finally:
        db_generator.close()

    response = client.patch(
        f"/documents/{document_id}/metadata",
        json={"filename": "renamed.txt", "category": "Reports"},
        headers={
            "Authorization": f"Bearer {create_access_token(editor_id)}"
        },
    )

    assert response.status_code == 200
    assert response.json()["filename"] == "renamed.txt"
    assert response.json()["category"] == "Reports"


def test_read_permission_cannot_update_metadata(client):
    from app.database import get_db
    from app.main import app
    from app.models import DocumentPermission
    from app.security import create_access_token

    db_generator = app.dependency_overrides[get_db]()
    db = next(db_generator)

    try:
        owner = create_test_user(
            db, "metadata_read_owner", "metadata_read_owner@example.com"
        )
        reader = create_test_user(
            db, "metadata_reader", "metadata_reader@example.com"
        )
        document = create_test_document(
            db,
            owner.id,
            "private-name.txt",
            STORAGE_DIR / "metadata-private.txt",
        )

        db.add(
            DocumentPermission(
                document_id=document.id,
                user_id=reader.id,
                permission="READ",
            )
        )
        db.commit()

        document_id = document.id
        reader_id = reader.id
        original_filename = document.filename
    finally:
        db_generator.close()

    response = client.patch(
        f"/documents/{document_id}/metadata",
        json={"filename": "changed.txt"},
        headers={
            "Authorization": f"Bearer {create_access_token(reader_id)}"
        },
    )

    assert response.status_code == 403

    # Confirm the denied request did not change the filename.
    db_generator = app.dependency_overrides[get_db]()
    db = next(db_generator)
    try:
        document = db.get(Document, document_id)
        assert document.filename == original_filename
    finally:
        db_generator.close()



def test_unshared_user_cannot_update_metadata(client):
    db_generator = app.dependency_overrides[get_db]()
    db = next(db_generator)

    try:
        owner = create_test_user(
            db,
            "metadata_unshared_owner",
            "metadata_unshared_owner@example.com",
        )
        other_user = create_test_user(
            db,
            "metadata_unshared_other",
            "metadata_unshared_other@example.com",
        )
        document = create_test_document(
            db,
            owner.id,
            "unshared.txt",
            STORAGE_DIR / "metadata-unshared.txt",
        )

        document_id = document.id
        other_user_id = other_user.id
    finally:
        db_generator.close()

    token = create_access_token(other_user_id)

    response = client.patch(
        f"/documents/{document_id}/metadata",
        json={"category": "Changed"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403
