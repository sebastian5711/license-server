from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone
import sqlite3
import secrets
import os

APP_ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "change_me_now")

DB_PATH = os.getenv("DB_PATH", "license.db")

app = FastAPI(title="License Server", version="1.0.0")
templates = Jinja2Templates(directory="templates")

# ---------- DB ----------
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS license_keys (
        license_key TEXT PRIMARY KEY,
        key_type TEXT NOT NULL,           -- lifetime | timed
        days INTEGER NOT NULL DEFAULT 0,  -- for timed keys
        created_at TEXT NOT NULL,
        first_used_at TEXT,
        expires_at TEXT,
        hwid TEXT,
        revoked INTEGER NOT NULL DEFAULT 0,
        note TEXT NOT NULL DEFAULT ''
    )
    """)
    conn.commit()
    conn.close()

init_db()

# ---------- Helpers ----------
def require_admin(token: str):
    if not token or token != APP_ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid admin token")

def now_utc():
    return datetime.now(timezone.utc)

# ---------- Models ----------
class AdminCreateKeys(BaseModel):
    token: str
    key_type: str   # "lifetime" or "timed"
    count: int = 1
    days: int = 0

class ActivateRequest(BaseModel):
    license_key: str
    hwid: str

class ResetHWIDRequest(BaseModel):
    token: str
    license_key: str

# ---------- Public: Activate ----------
@app.post("/activate")
def activate(req: ActivateRequest):
    conn = db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM license_keys WHERE license_key = ?", (req.license_key,))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, detail="Key not found")

    if row["revoked"] == 1:
        conn.close()
        raise HTTPException(403, detail="Key revoked")

    # If HWID not set yet, bind on first activation
    if not row["hwid"]:
        first_used = now_utc()
        expires_at = None

        if row["key_type"] == "timed":
            if row["days"] < 1:
                conn.close()
                raise HTTPException(400, detail="Timed key misconfigured (days < 1)")
            expires_at = first_used + timedelta(days=int(row["days"]))

        cur.execute("""
            UPDATE license_keys
            SET hwid = ?, first_used_at = ?, expires_at = ?
            WHERE license_key = ?
        """, (
            req.hwid,
            first_used.isoformat(),
            expires_at.isoformat() if expires_at else None,
            req.license_key
        ))
        conn.commit()
        conn.close()
        return {"ok": True, "status": "BOUND", "expires_at": expires_at.isoformat() if expires_at else None}

    # HWID already bound, must match
    if row["hwid"] != req.hwid:
        conn.close()
        raise HTTPException(403, detail="HWID mismatch")

    # Check expiration for timed keys
    if row["key_type"] == "timed" and row["expires_at"]:
        exp = datetime.fromisoformat(row["expires_at"])
        if now_utc() > exp:
            conn.close()
            raise HTTPException(403, detail="Key expired")

    conn.close()
    return {"ok": True, "status": "OK", "expires_at": row["expires_at"]}

# ---------- Admin: Page ----------
@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request):
    # your admin.html will read token from URL (?token=...)
    return templates.TemplateResponse("admin.html", {"request": request})

# ---------- Admin: Create keys (JSON) ----------
@app.post("/admin/create_keys")
def admin_create_keys(req: AdminCreateKeys):
    require_admin(req.token)

    if req.count < 1 or req.count > 500:
        raise HTTPException(400, detail="count must be 1..500")

    if req.key_type not in ("lifetime", "timed"):
        raise HTTPException(400, detail="key_type must be lifetime|timed")

    if req.key_type == "timed" and req.days < 1:
        raise HTTPException(400, detail="timed keys need days >= 1")

    if req.key_type == "lifetime":
        req.days = 0

    conn = db()
    cur = conn.cursor()
    created = []

    for _ in range(req.count):
        # generate a unique key
        k = "NM-" + secrets.token_urlsafe(18).replace("_", "").replace("-", "")
        created.append(k)
        cur.execute("""
            INSERT INTO license_keys (license_key, key_type, days, created_at)
            VALUES (?, ?, ?, ?)
        """, (k, req.key_type, int(req.days), now_utc().isoformat()))

    conn.commit()
    conn.close()
    return {"ok": True, "keys": created}

# ---------- Admin: List keys ----------
@app.get("/admin/keys")
def admin_list_keys(token: str):
    require_admin(token)
    conn = db()
    cur = conn.cursor()
    cur.execute("""
        SELECT license_key, key_type, days, created_at, first_used_at, expires_at, hwid, revoked, note
        FROM license_keys
        ORDER BY created_at DESC
        LIMIT 2000
    """)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {"ok": True, "keys": rows}

# ---------- Admin: Revoke key ----------
@app.post("/admin/revoke/{license_key}")
def admin_revoke(license_key: str, token: str):
    require_admin(token)
    conn = db()
    cur = conn.cursor()
    cur.execute("UPDATE license_keys SET revoked = 1 WHERE license_key = ?", (license_key,))
    if cur.rowcount == 0:
        conn.close()
        raise HTTPException(404, detail="Key not found")
    conn.commit()
    conn.close()
    return {"ok": True}

# ---------- Admin: Reset HWID ----------
@app.post("/admin/reset_hwid")
def admin_reset_hwid(req: ResetHWIDRequest):
    require_admin(req.token)
    conn = db()
    cur = conn.cursor()
    cur.execute("""
        UPDATE license_keys
        SET hwid = NULL, first_used_at = NULL, expires_at = NULL
        WHERE license_key = ?
    """, (req.license_key,))
    if cur.rowcount == 0:
        conn.close()
        raise HTTPException(404, detail="Key not found")
    conn.commit()
    conn.close()
    return {"ok": True}
