"""Dashboard login: one password, kept only as a PBKDF2-SHA256 hash, and
30-day sessions, kept only as hashes of their tokens. The design and why a
password (not a tailnet identity check) is in the vault's NekoCTI Login note.

The password is set only with `main.py set-password`, inside the container.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from pathlib import Path

import db

# A bare filename like the other data files: in the container the entrypoint
# symlinks it into the data volume, so it survives rebuilds.
AUTH_FILE = Path(__file__).resolve().parent / "auth.json"
ITERATIONS = 600_000
MIN_PASSWORD_LENGTH = 12
SESSION_SECONDS = 30 * 24 * 60 * 60
MAX_FAILURES = 5
LOCKOUT_SECONDS = 15 * 60

_failures: list[float] = []
_failures_lock = threading.Lock()


def _hash_password(password: str, salt: bytes, iterations: int) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations).hex()


def _password_record() -> dict | None:
    """The stored hash, or None when no password has been set (the
    container starts with an empty file)."""
    try:
        record = json.loads(AUTH_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(record, dict) or not {"salt", "hash", "iterations"} <= record.keys():
        return None
    return record


def password_is_set() -> bool:
    return _password_record() is not None


def set_password(password: str) -> None:
    """Replace the password and end every session."""
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"the password must be at least {MIN_PASSWORD_LENGTH} characters")
    salt = secrets.token_bytes(16)
    record = {"salt": salt.hex(), "hash": _hash_password(password, salt, ITERATIONS), "iterations": ITERATIONS}
    target = AUTH_FILE.resolve()  # write through the container's symlink, not over it
    tmp = target.with_name(target.name + ".tmp")
    tmp.write_text(json.dumps(record), encoding="utf-8")
    os.replace(tmp, target)
    try:
        os.chmod(target, 0o600)
    except OSError:
        pass  # Windows Dev: permissions work differently
    end_all_sessions()


def locked_out() -> bool:
    """True after MAX_FAILURES wrong passwords within LOCKOUT_SECONDS."""
    now = time.time()
    with _failures_lock:
        _failures[:] = [t for t in _failures if now - t < LOCKOUT_SECONDS]
        return len(_failures) >= MAX_FAILURES


def check_password(password: str) -> bool:
    record = _password_record()
    if record is None:
        return False
    candidate = _hash_password(password, bytes.fromhex(record["salt"]), int(record["iterations"]))
    ok = hmac.compare_digest(candidate, record["hash"])
    with _failures_lock:
        if ok:
            _failures.clear()
        else:
            _failures.append(time.time())
    return ok


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session() -> str:
    token = secrets.token_urlsafe(32)
    now = time.time()
    conn = db.connect()
    try:
        conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
        conn.execute("INSERT INTO sessions (token_hash, expires_at) VALUES (?, ?)",
                     (_token_hash(token), now + SESSION_SECONDS))
        conn.commit()
    finally:
        conn.close()
    return token


def session_valid(token: str | None) -> bool:
    if not token:
        return False
    conn = db.connect()
    try:
        row = conn.execute("SELECT expires_at FROM sessions WHERE token_hash = ?",
                           (_token_hash(token),)).fetchone()
    finally:
        conn.close()
    return row is not None and row["expires_at"] > time.time()


def end_session(token: str | None) -> None:
    if not token:
        return
    conn = db.connect()
    try:
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (_token_hash(token),))
        conn.commit()
    finally:
        conn.close()


def end_all_sessions() -> None:
    conn = db.connect()
    try:
        conn.execute("DELETE FROM sessions")
        conn.commit()
    finally:
        conn.close()
