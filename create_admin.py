"""Create or promote an admin account from a trusted local shell.

Usage: python create_admin.py
Set ADMIN_USERNAME, ADMIN_EMAIL and ADMIN_PASSWORD in the environment first.
Do not expose this script as a public HTTP endpoint.
"""
import os
from sqlalchemy import select
from app.database import SessionLocal
from app.models import User
from app.security import hash_password

username = os.getenv("ADMIN_USERNAME", "").strip()
email = os.getenv("ADMIN_EMAIL", "").strip()
password = os.getenv("ADMIN_PASSWORD", "")
if not username or not email or len(password) < 12:
    raise SystemExit("Set ADMIN_USERNAME, ADMIN_EMAIL, and ADMIN_PASSWORD (at least 12 characters).")

with SessionLocal() as db:
    user = db.scalar(select(User).where((User.username == username) | (User.email == email)))
    if user:
        user.role = "admin"
        if user.username != username or user.email != email:
            raise SystemExit("Existing username/email mismatch; refusing to modify a different account.")
        user.password_hash = hash_password(password)
    else:
        user = User(username=username, email=email, password_hash=hash_password(password), role="admin")
        db.add(user)
    db.commit()
print(f"Admin account ready: {username}. Sign in through the app; never share the password.")
