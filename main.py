from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Literal
import sqlite3, secrets, datetime

from fastapi import Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

app = FastAPI()
templates = Jinja2Templates(directory="templates")

ADMIN_TOKEN = "CHANGE_ME_ADMIN_TOKEN"
DB_PATH = "licenses.db"

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
        key_type TEXT NOT NULL,        -- lifetime|timed
        days INTEGER NOT NULL,         -- 0 for lifetime
        created_at TEXT NOT NULL,
        activated_at TEXT,
        expires_at TEXT,               -- null for lifetime until activated if timed
        hwid TEXT,
        note TEXT,
        revoked INTEGER NOT NULL DEFAULT 0
    )
    """)
    conn.commit()
    conn.close()

init_db()

def require_admin(token: str):
    if token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Bad admin token")

def now_iso():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def add_days_iso(days: int):
    dt = datetime.datetime.utcnow() + datetime.timedelta(days=days)
    return dt.replace(microsecond=0).isoformat() + "Z"

class AdminCreateKeys(BaseModel):
    token: str
    key_type: Literal["lifetime", "timed"]
    count: int = 1
    days: int = 0

class AdminNote(BaseModel):
    token: str
    note: str = ""

class ActivateReq(BaseModel):
    license_key: str
    hwid: str

@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request, token: str | None = None):
    if not token or token != ADMIN_TOKEN:
        return HTMLResponse("<h3>Unauthorized</h3><p>Use /admin?token=YOUR_ADMIN_TOKEN</p>", status_code=401)
    return templates.TemplateResponse("admin.html", {"request": request, "token": token})

@app.post("/admin/create_keys")
def admin_create_keys(req: AdminCreateKeys):
    require_admin(req.token)

    if req.count < 1 or req.count > 500:
        raise HTTPException(400, detail="count must be 1..500")
    if req.key_type == "timed" and req.days < 1:
        raise HTTPException(400, detail="timed keys need days >= 1")
    if req.key_type == "lifetime":
        req.days = 0

    conn = db()
    cur = conn.cursor()
    keys = []
    for _ in range(req.count):
        k = "NM-" + secrets.token_urlsafe(18).replace("_", "").replace("-", "")
        cur.execute("""
            INSERT INTO license_keys (license_key, key_type, days, created_at, note, revoked)
            VALUES (?, ?, ?, ?, ?, 0)
        """, (k, req.key_type, req.days, now_iso(), "",))
        keys.append(k)
    conn.commit()
    conn.close()
    return {"ok": True, "keys": keys}

@app.get("/admin/keys")
def admin_list_keys(token: str):
    require_admin(token)
    conn = db()
    rows = conn.execute("""
        SELECT license_key, key_type, days, created_at, activated_at, expires_at, hwid, note, revoked
        FROM license_keys
        ORDER BY created_at DESC
        LIMIT 5000
    """).fetchall()
    conn.close()

    keys = []
    for r in rows:
        keys.append({
            "license_key": r["license_key"],
            "type": r["key_type"],
            "days": r["days"],
            "created_at": r["created_at"],
            "activated_at": r["activated_at"],
            "expires_at": r["expires_at"] or ("NEVER" if r["key_type"] == "lifetime" else None),
            "hwid": r["hwid"] or "",
            "note": r["note"] or "",
            "revoked": bool(r["revoked"]),
        })
    return {"ok": True, "keys": keys}

@app.post("/admin/reset_hwid/{license_key}")
def admin_reset_hwid(license_key: str, token: str):
    require_admin(token)
    conn = db()
    cur = conn.cursor()
    cur.execute("UPDATE license_keys SET hwid = NULL, activated_at=NULL, expires_at=NULL WHERE license_key = ?", (license_key,))
    if cur.rowcount == 0:
        conn.close()
        raise HTTPException(404, detail="Key not found")
    conn.commit()
    conn.close()
    return {"ok": True}

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

@app.post("/admin/note/{license_key}")
def admin_set_note(license_key: str, req: AdminNote):
    require_admin(req.token)
    conn = db()
    cur = conn.cursor()
    cur.execute("UPDATE license_keys SET note = ? WHERE license_key = ?", (req.note, license_key))
    if cur.rowcount == 0:
        conn.close()
        raise HTTPException(404, detail="Key not found")
    conn.commit()
    conn.close()
    return {"ok": True}

@app.post("/activate")
def activate(req: ActivateReq):
    conn = db()
    row = conn.execute("""
        SELECT license_key, key_type, days, activated_at, expires_at, hwid, revoked
        FROM license_keys
        WHERE license_key = ?
    """, (req.license_key,)).fetchone()

    if not row:
        conn.close()
        raise HTTPException(401, detail="Invalid key")

    if row["revoked"]:
        conn.close()
        raise HTTPException(401, detail="Key revoked")

    if row["key_type"] == "timed" and row["expires_at"]:
        if now_iso() > row["expires_at"]:
            conn.close()
            raise HTTPException(401, detail="Key expired")

    # First activation: bind HWID
    if not row["hwid"]:
        expires_at = None
        activated_at = now_iso()
        if row["key_type"] == "timed":
            expires_at = add_days_iso(int(row["days"]))
        conn.execute("""
            UPDATE license_keys
            SET hwid = ?, activated_at = ?, expires_at = ?
            WHERE license_key = ?
        """, (req.hwid, activated_at, expires_at, req.license_key))
        conn.commit()
        conn.close()
        return {"ok": True, "status": "BOUND", "expires_at": expires_at or "NEVER"}

    # Already bound: must match
    if row["hwid"] != req.hwid:
        conn.close()
        raise HTTPException(401, detail="HWID mismatch")

    conn.close()
    return {"ok": True, "status": "OK", "expires_at": row["expires_at"] or "NEVER"}
