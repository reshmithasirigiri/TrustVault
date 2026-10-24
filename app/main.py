
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import uuid

import jwt
from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import AuditLog, Document, DocumentPermission, User
from app.schemas import UserCreate, UserResponse
from app.security import (
    create_access_token,
    hash_password,
    verify_access_token,
    verify_password,
)


app = FastAPI(
    title="TrustVault API",
    description="Secure document sharing with an auditable access trail",
    version="0.1.0",
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

STORAGE_DIR = Path("storage").resolve()
STORAGE_DIR.mkdir(parents=True, exist_ok=True)
STATIC_DIR = Path(__file__).resolve().parent.parent / "frontend"
if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
ALLOWED_EXTENSIONS = {".pdf", ".txt", ".png", ".jpg", ".jpeg"}


class PermissionRequest(BaseModel):
    user_id: int
    permission: str
class MetadataUpdateRequest(BaseModel):
    filename: str | None = None
    category: str | None = None


def record_audit(
    db: Session,
    user_id: int | None,
    document_id: int | None,
    action: str,
    outcome: str,
    details: str = "",
):
    """Record an audit event linked to the previous event's hash."""

    previous_entry = db.scalar(
        select(AuditLog).order_by(AuditLog.id.desc()).limit(1)
    )

    previous_hash = (
        previous_entry.entry_hash
        if previous_entry
        else "0" * 64
    )

    created_at = datetime.now(timezone.utc)
    safe_details = details[:500]

    # Create a consistent representation of the audit event.
    payload = {
        "user_id": user_id,
        "document_id": document_id,
        "action": action,
        "outcome": outcome,
        "details": safe_details,
        "created_at": created_at.isoformat(),
        "previous_hash": previous_hash,
    }

    canonical_payload = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    )

    entry_hash = hashlib.sha256(
        canonical_payload.encode("utf-8")
    ).hexdigest()

    audit_entry = AuditLog(
        user_id=user_id,
        document_id=document_id,
        action=action,
        outcome=outcome,
        details=safe_details,
        created_at=created_at,
        previous_hash=previous_hash,
        entry_hash=entry_hash,
    )

    db.add(audit_entry)
    db.commit()


def get_authenticated_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:

    """Validate a JWT and return the corresponding user."""
    try:
        user_id = verify_access_token(token)
    except (jwt.InvalidTokenError, ValueError, KeyError, TypeError):
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.get(User, user_id)

    if not user:
        raise HTTPException(
            status_code=401,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user

def require_admin(
    current_user: User = Depends(get_authenticated_user),
) -> User:
    """Allow access only to administrator accounts."""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=403,
            detail="Administrator access required",
        )

    return current_user



@app.get("/", response_class=HTMLResponse)
def home():
    index_file = STATIC_DIR / "index.html"
    if index_file.is_file():
        return index_file.read_text(encoding="utf-8")
    return "<h1>TrustVault API</h1><p>Open <a href='/docs'>API documentation</a>.</p>"


@app.get("/health")
def health_check():
    return {"status": "healthy"}


# -------------------- AUTHENTICATION --------------------


@app.post("/auth/register", response_model=UserResponse, status_code=201)
def register_user(
    user_data: UserCreate,
    db: Session = Depends(get_db),
):
    existing_user = db.scalar(
        select(User).where(
            (User.username == user_data.username)
            | (User.email == str(user_data.email))
        )
    )

    if existing_user:
        raise HTTPException(
            status_code=409,
            detail="Username or email is already registered",
        )

    user = User(
        username=user_data.username,
        email=str(user_data.email),
        password_hash=hash_password(user_data.password),
        role="viewer",
    )

    db.add(user)

    try:
        db.commit()
        db.refresh(user)
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="Username or email is already registered",
        )

    return user


@app.post("/auth/login")
def login_user(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    user = db.scalar(
        select(User).where(User.username == form_data.username)
    )

    if not user or not verify_password(
        form_data.password,
        user.password_hash,
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(user.id)

    return {
        "access_token": token,
        "token_type": "bearer",
    }


@app.get("/auth/me")
def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
):
    user = get_authenticated_user(token, db)

    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
    }


# -------------------- DOCUMENT UPLOAD --------------------


@app.post("/documents/upload", status_code=201)
def upload_document(
    file: UploadFile = File(...),
    category: str = "uncategorized",
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
):
    user = get_authenticated_user(token, db)

    stored_path = None

    try:
        original_name = Path(file.filename or "").name
        extension = Path(original_name).suffix.lower()

        if not original_name or extension not in ALLOWED_EXTENSIONS:
            raise HTTPException(
                status_code=400,
                detail="Unsupported file type",
            )

        if not category.strip() or len(category.strip()) > 100:
            raise HTTPException(
                status_code=400,
                detail="Category must be between 1 and 100 characters",
            )

        # Read at most one byte beyond the limit.
        content = file.file.read(MAX_FILE_SIZE + 1)

        if not content:
            raise HTTPException(
                status_code=400,
                detail="File is empty",
            )

        if len(content) > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=413,
                detail="File exceeds 5 MB limit",
            )

        # Use a random storage name instead of the uploaded filename.
        stored_name = f"{uuid.uuid4().hex}{extension}"
        stored_path = STORAGE_DIR / stored_name

        with stored_path.open("xb") as stored_file:
            stored_file.write(content)

        document = Document(
            filename=original_name,
            category=category.strip(),
            storage_path=str(stored_path),
            owner_id=user.id,
            created_at=datetime.now(timezone.utc),
        )

        db.add(document)
        db.commit()
        db.refresh(document)

    except HTTPException:
        if stored_path is not None and stored_path.exists():
            stored_path.unlink(missing_ok=True)
        raise

    except Exception:
        db.rollback()

        if stored_path is not None and stored_path.exists():
            stored_path.unlink(missing_ok=True)

        raise HTTPException(
            status_code=500,
            detail="Could not save document",
        )

    finally:
        file.file.close()

    record_audit(
        db=db,
        user_id=user.id,
        document_id=document.id,
        action="UPLOAD",
        outcome="SUCCESS",
        details=f"Uploaded document: {document.filename}",
    )

    return {
        "id": document.id,
        "filename": document.filename,
        "category": document.category,
        "owner_id": document.owner_id,
        "created_at": document.created_at,
    }


# -------------------- LIST MY DOCUMENTS --------------------


@app.get("/documents")
def list_my_documents(
    search: str | None = None,
    category: str | None = None,
    owner_id: int | None = None,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
):
    """List documents owned by or explicitly shared with the signed-in user."""
    user = get_authenticated_user(token, db)
    shared_ids = select(DocumentPermission.document_id).where(
        DocumentPermission.user_id == user.id
    )
    query = select(Document).where(
        Document.is_deleted.is_(False),
        (Document.owner_id == user.id) | (Document.id.in_(shared_ids)),
    )
    if search:
        query = query.where(Document.filename.ilike(f"%{search.strip()}%"))
    if category:
        query = query.where(Document.category.ilike(f"%{category.strip()}%"))
    if owner_id is not None:
        query = query.where(Document.owner_id == owner_id)
    documents = db.scalars(query.order_by(Document.id.desc())).all()
    permissions = {
        row.document_id: row.permission
        for row in db.scalars(
            select(DocumentPermission).where(DocumentPermission.user_id == user.id)
        ).all()
    }
    return [
        {
            "id": document.id,
            "filename": document.filename,
            "category": document.category,
            "owner_id": document.owner_id,
            "created_at": document.created_at,
            "access": "OWNER" if document.owner_id == user.id else permissions.get(document.id, "READ"),
        }
        for document in documents
    ]


# -------------------- DOWNLOAD DOCUMENT --------------------


@app.get("/documents/{document_id}/download")
def download_document(
    document_id: int,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
):
    user = get_authenticated_user(token, db)

    document = db.get(Document, document_id)

    if not document or document.is_deleted:
        raise HTTPException(
            status_code=404,
            detail="Document not found",
        )

    # The owner always has access to their own document.
    allowed = document.owner_id == user.id

    # Other users require explicit READ or EDIT permission.
    if not allowed:
        permission = db.scalar(
            select(DocumentPermission).where(
                DocumentPermission.document_id == document_id,
                DocumentPermission.user_id == user.id,
            )
        )

        allowed = (
            permission is not None
            and permission.permission in {"READ", "EDIT"}
        )

    # IMPORTANT: Only reject the request when access is denied.
    if not allowed:
        record_audit(
            db=db,
            user_id=user.id,
            document_id=document_id,
            action="DOWNLOAD",
            outcome="DENIED",
            details="Download denied: insufficient permission",
        )

        raise HTTPException(
            status_code=403,
            detail="You do not have permission to download this document",
        )

    # Verify that the stored path is inside the private storage directory.
    stored_path = Path(document.storage_path).resolve()

    if not stored_path.is_relative_to(STORAGE_DIR):
        raise HTTPException(
            status_code=500,
            detail="Invalid storage path",
        )

    if not stored_path.is_file():
        raise HTTPException(
            status_code=404,
            detail="Stored file not found",
        )

    record_audit(
        db=db,
        user_id=user.id,
        document_id=document.id,
        action="DOWNLOAD",
        outcome="SUCCESS",
        details=f"Downloaded document: {document.filename}",
    )

    return FileResponse(
        path=stored_path,
        filename=document.filename,
        media_type="application/octet-stream",
    )
    
@app.patch("/documents/{document_id}/metadata")
def update_document_metadata(
    document_id: int,
    request: MetadataUpdateRequest,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
):
    user = get_authenticated_user(token, db)

    document = db.get(Document, document_id)

    if not document or document.is_deleted:
        raise HTTPException(
            status_code=404,
            detail="Document not found",
        )

    # Only the owner or a user with EDIT permission may edit metadata.
    permission = None

    if document.owner_id != user.id:
        permission = db.scalar(
            select(DocumentPermission).where(
                DocumentPermission.document_id == document_id,
                DocumentPermission.user_id == user.id,
            )
        )

    allowed = (
        document.owner_id == user.id
        or (
            permission is not None
            and permission.permission == "EDIT"
        )
    )

    if not allowed:
        record_audit(
            db=db,
            user_id=user.id,
            document_id=document_id,
            action="METADATA_UPDATE",
            outcome="DENIED",
            details="Metadata update denied: insufficient permission",
        )

        raise HTTPException(
            status_code=403,
            detail="You do not have permission to edit this document's metadata",
        )

    # Require at least one field to be updated.
    updates = request.model_dump(exclude_unset=True)

    if not updates:
        raise HTTPException(
            status_code=400,
            detail="Provide a filename or category to update",
        )

    
    # Validate all supplied fields before changing anything.
    filename = updates.get("filename")
    category = updates.get("category")

    if "filename" in updates:
        if filename is None or not filename.strip():
            raise HTTPException(
                status_code=400,
                detail="Filename cannot be empty",
            )

        filename = filename.strip()

        if len(filename) > 255:
            raise HTTPException(
                status_code=400,
                detail="Filename cannot exceed 255 characters",
            )

        if "/" in filename or "\\" in filename:
            raise HTTPException(
                status_code=400,
                detail="Filename cannot contain path separators",
            )

    if "category" in updates:
        if category is None or not category.strip():
            raise HTTPException(
                status_code=400,
                detail="Category cannot be empty",
            )

        category = category.strip()

        if len(category) > 100:
            raise HTTPException(
                status_code=400,
                detail="Category cannot exceed 100 characters",
            )

    old_filename = document.filename
    old_category = document.category

    if "filename" in updates:
        document.filename = filename

    if "category" in updates:
        document.category = category

    db.commit()
    db.refresh(document)

    record_audit(
        db=db,
        user_id=user.id,
        document_id=document.id,
        action="METADATA_UPDATE",
        outcome="SUCCESS",
        details=(
            f"Filename: {old_filename!r} -> {document.filename!r}; "
            f"Category: {old_category!r} -> {document.category!r}"
        ),
    )

    return {
        "message": "Document metadata updated successfully",
        "id": document.id,
        "filename": document.filename,
        "category": document.category,
        "owner_id": document.owner_id,
    }
def verify_audit_chain(db: Session) -> bool:
    """Check whether audit records form a valid hash chain."""

    entries = db.scalars(
        select(AuditLog).order_by(AuditLog.id.asc())
    ).all()

    expected_previous_hash = "0" * 64

    for entry in entries:
        if entry.previous_hash != expected_previous_hash:
            return False

        payload = {
            "user_id": entry.user_id,
            "document_id": entry.document_id,
            "action": entry.action,
            "outcome": entry.outcome,
            "details": entry.details,
           "created_at": (
    entry.created_at.replace(tzinfo=timezone.utc)
    if entry.created_at.tzinfo is None
    else entry.created_at.astimezone(timezone.utc)
).isoformat(),
            "previous_hash": entry.previous_hash,
        }

        canonical_payload = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        )

        expected_hash = hashlib.sha256(
            canonical_payload.encode("utf-8")
        ).hexdigest()

        if entry.entry_hash != expected_hash:
            return False

        expected_previous_hash = entry.entry_hash

    return True




# -------------------- GRANT OR UPDATE PERMISSION --------------------


@app.post("/documents/{document_id}/permissions", status_code=201)
def grant_document_permission(
    document_id: int,
    request: PermissionRequest,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
):
    owner = get_authenticated_user(token, db)

    document = db.get(Document, document_id)

    if not document or document.is_deleted:
        raise HTTPException(
            status_code=404,
            detail="Document not found",
        )

    if document.owner_id != owner.id:
        raise HTTPException(
            status_code=403,
            detail="Only the document owner can grant permissions",
        )

    permission_value = request.permission.strip().upper()

    if permission_value not in {"READ", "EDIT"}:
        raise HTTPException(
            status_code=400,
            detail="Permission must be READ or EDIT",
        )

    target_user = db.get(User, request.user_id)

    if not target_user:
        raise HTTPException(
            status_code=404,
            detail="Target user not found",
        )

    if target_user.id == owner.id:
        raise HTTPException(
            status_code=400,
            detail="The owner already has access",
        )

    existing_permission = db.scalar(
        select(DocumentPermission).where(
            DocumentPermission.document_id == document_id,
            DocumentPermission.user_id == request.user_id,
        )
    )

    if existing_permission:
        existing_permission.permission = permission_value
        message = "Permission updated successfully"
        audit_action = "PERMISSION_UPDATED"
    else:
        new_permission = DocumentPermission(
            document_id=document_id,
            user_id=request.user_id,
            permission=permission_value,
        )
        db.add(new_permission)
        message = "Permission granted successfully"
        audit_action = "PERMISSION_GRANTED"

    db.commit()

    record_audit(
        db=db,
        user_id=owner.id,
        document_id=document_id,
        action=audit_action,
        outcome="SUCCESS",
        details=(
            f"{permission_value} permission for user "
            f"{request.user_id}"
        ),
    )

    return {
        "message": message,
        "document_id": document_id,
        "user_id": request.user_id,
        "permission": permission_value,
    }


# -------------------- REVOKE PERMISSION --------------------


@app.delete("/documents/{document_id}/permissions/{user_id}")
def revoke_document_permission(
    document_id: int,
    user_id: int,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
):
    owner = get_authenticated_user(token, db)

    document = db.get(Document, document_id)

    if not document or document.is_deleted:
        raise HTTPException(
            status_code=404,
            detail="Document not found",
        )

    if document.owner_id != owner.id:
        raise HTTPException(
            status_code=403,
            detail="Only the document owner can revoke permissions",
        )

    permission = db.scalar(
        select(DocumentPermission).where(
            DocumentPermission.document_id == document_id,
            DocumentPermission.user_id == user_id,
        )
    )

    if not permission:
        raise HTTPException(
            status_code=404,
            detail="Permission not found",
        )

    db.delete(permission)
    db.commit()

    record_audit(
        db=db,
        user_id=owner.id,
        document_id=document_id,
        action="PERMISSION_REVOKED",
        outcome="SUCCESS",
        details=f"Permission revoked for user {user_id}",
    )

    return {
        "message": "Permission revoked successfully",
        "document_id": document_id,
        "user_id": user_id,
    }

@app.get("/documents/{document_id}/permissions")
def list_document_permissions(
    document_id: int,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
):
    user = get_authenticated_user(token, db)
    document = db.get(Document, document_id)
    if not document or document.is_deleted:
        raise HTTPException(status_code=404, detail="Document not found")
    if document.owner_id != user.id:
        raise HTTPException(status_code=403, detail="Only the document owner can view permissions")
    rows = db.scalars(
        select(DocumentPermission).where(DocumentPermission.document_id == document_id)
    ).all()
    return [
        {"user_id": row.user_id, "username": db.get(User, row.user_id).username, "permission": row.permission}
        for row in rows
    ]


@app.delete("/documents/{document_id}")
def delete_document(
    document_id: int,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
):
    user = get_authenticated_user(token, db)
    document = db.get(Document, document_id)
    if not document or document.is_deleted:
        raise HTTPException(status_code=404, detail="Document not found")
    if document.owner_id != user.id:
        record_audit(db, user.id, document_id, "DELETE", "DENIED", "Document deletion denied: owner only")
        raise HTTPException(status_code=403, detail="Only the document owner can delete this document")
    path = Path(document.storage_path).resolve()
    if not path.is_relative_to(STORAGE_DIR):
        raise HTTPException(status_code=500, detail="Invalid storage path")
    # Soft-delete the database row so past audit records keep their document reference.
    db.query(DocumentPermission).filter(DocumentPermission.document_id == document_id).delete(synchronize_session=False)
    document.is_deleted = True
    db.commit()
    if path.is_file():
        path.unlink(missing_ok=True)
    record_audit(db, user.id, document_id, "DELETE", "SUCCESS", f"Deleted document {document_id}: {document.filename}")
    return {"message": "Document deleted", "document_id": document_id}


@app.get("/admin/users")
def list_users_for_admin(
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    return [{"id": u.id, "username": u.username, "email": u.email, "role": u.role} for u in db.scalars(select(User).order_by(User.username)).all()]


@app.get("/admin/audit-logs")
def get_admin_audit_logs(
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Return audit logs to administrators only."""
    logs = db.scalars(
        select(AuditLog).order_by(AuditLog.id.desc())
    ).all()

    return [
        {
            "id": log.id,
            "user_id": log.user_id,
            "document_id": log.document_id,
            "action": log.action,
            "outcome": log.outcome,
            "details": log.details,
            "created_at": log.created_at,
            "entry_hash": log.entry_hash,
        }
        for log in logs
    ]
@app.get("/admin/audit-logs/verify")
def verify_admin_audit_logs(
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Verify the integrity of the audit log hash chain."""
    is_valid = verify_audit_chain(db)

    return {
        "valid": is_valid,
        "message": (
            "Audit chain is valid"
            if is_valid
            else "Audit chain integrity check failed"
        ),
    }

