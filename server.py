from __future__ import annotations

import os
import sqlite3
import secrets
from datetime import datetime, timedelta, timezone
from typing import Literal, Optional, List

from fastapi import FastAPI, HTTPException, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

# ========= CONFIG =========
DB_PATH = os.getenv("DB_PATH", "licenses.sqlite3")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "CHANGE_ME_ADMIN_TOKEN")  # set on Render!

UTC = timezone.utc

# ========= APP =========
app = FastAPI(title="NovaMacro License Server", version="1.0.0")
templates = Jinja2Templates(directory="templates")

# ========= DB =========
def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db() -> None:
    conn = db()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS license_keys (
        license_key TEXT PRIMARY KEY,
        key_type TEXT NOT NULL,              -- 'lifetime' | 'timed'
        days INTEGER NOT NULL DEFAULT 0,      -- only for timed
        created_at TEXT NOT NULL,
        activated_at TEXT NULL,              -- when first activated (timed)
        expires_at TEXT NULL,                -- computed on first activation (timed)
        hwid TEXT NULL,                      -- bound hwid after first activate
        note TEXT NULL,
        revoked INTEGER NOT NULL DEFAULT 0
    )
    """)
    conn.commit()
    conn.close()

init_db()

# ========= HELPERS =========
def now_iso() -> str:
    return datetime.now(UTC).isoformat()

def require_admin(token: str) -> None:
    if not token or token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid admin token")

def gen_key() -> str:
    # looks like XXXX-XXXX-XXXX-XXXX but cryptographically random
    raw = secrets.token_hex(16).upper()  # 32 hex chars
    return f"{raw[0:4]}-{raw[4:8]}-{raw[8:12]}-{raw[12:16]}-{raw[16:20]}-{raw[20:24]}-{raw[24:28]}-{raw[28:32]}"

def row_to_public(r: sqlite3.Row) -> dict:
    return {
        "license_key": r["license_key"],
        "type": r["key_type"],
        "days": r["days"],
        "created_at": r["created_at"],
        "activated_at": r["activated_at"],
        "expires_at": r["expires_at"],
        "hwid": r["hwid"] or "",
        "note": r["note"] or "",
        "revoked": bool(r["revoked"]),
    }

# ========= MODELS =========
class ActivateReq(BaseModel):
    license_key: str = Field(..., min_length=6)
    hwid: str = Field(..., min_length=3)

class ActivateResp(BaseModel):
    ok: bool
    key_type: Literal["lifetime", "timed"]
    expires_at: Optional[str] = None
    hwid: str

class AdminCreateReq(BaseModel):
    token: str
    key_type: Literal["lifetime", "timed"]
    count: int = Field(ge=1, le=200)
    days: int = Field(ge=0, le=3650)  # up to 10 years

class AdminSimpleResp(BaseModel):
    ok: bool
    detail: Optional[str] = None

# ========= PUBLIC ENDPOINT (macro calls this) =========
@app.post("/activate", response_model=ActivateResp)
def activate(req: ActivateReq):
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM license_keys WHERE license_key = ?", (req.license_key,))
    r = cur.fetchone()
    if not r:
        conn.close()
        raise HTTPException(status_code=404, detail="Key not found")
    if r["revoked"]:
        conn.close()
        raise HTTPException(status_code=403, detail="Key revoked")

    key_type = r["key_type"]
    days = int(r["days"] or 0)

    # If already bound, must match
    bound_hwid = r["hwid"]
    if bound_hwid and bound_hwid != req.hwid:
        conn.close()
        raise HTTPException(status_code=403, detail="HWID mismatch (key already bound)")

    activated_at = r["activated_at"]
    expires_at = r["expires_at"]

    # First activation: bind HWID, and if timed set activated/expires
    if not bound_hwid:
        activated_at = now_iso()
        if key_type == "timed":
            exp = datetime.now(UTC) + timedelta(days=days)
            expires_at = exp.isoformat()
        else:
            expires_at = None

        cur.execute("""
            UPDATE license_keys
            SET hwid = ?, activated_at = ?, expires_at = ?
            WHERE license_key = ?
        """, (req.hwid, activated_at, expires_at, req.license_key))
        conn.commit()

    # If timed, check expiry
    if key_type == "timed" and expires_at:
        try:
            exp_dt = datetime.fromisoformat(expires_at)
        except Exception:
            exp_dt = None
        if exp_dt and datetime.now(UTC) > exp_dt:
            conn.close()
            raise HTTPException(status_code=403, detail="Key expired")

    conn.close()
    return ActivateResp(ok=True, key_type=key_type, expires_at=expires_at, hwid=req.hwid)

# ========= ADMIN UI PAGE =========
@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request):
    # token is in query (?token=...)
    return templates.TemplateResponse("admin.html", {"request": request})

# ========= ADMIN API (JSON) =========
@app.post("/admin/create_keys")
def admin_create_keys(req: AdminCreateReq):
    require_admin(req.token)

    conn = db()
    cur = conn.cursor()

    created: List[str] = []
    for _ in range(req.count):
        # ensure unique
        for _try in range(10):
            k = gen_key()
            try:
                cur.execute("""
                    INSERT INTO license_keys (license_key, key_type, days, created_at)
                    VALUES (?, ?, ?, ?)
                """, (k, req.key_type, int(req.days if req.key_type == "timed" else 0), now_iso()))
                created.append(k)
                break
            except sqlite3.IntegrityError:
                continue

    conn.commit()
    conn.close()
    return {"ok": True, "keys": created}

@app.post("/admin/revoke/{license_key}", response_model=AdminSimpleResp)
def admin_revoke(license_key: str, token: str = Form(...)):
    require_admin(token)
    conn = db()
    cur = conn.cursor()
    cur.execute("UPDATE license_keys SET revoked = 1 WHERE license_key = ?", (license_key,))
    conn.commit()
    conn.close()
    return AdminSimpleResp(ok=True)

@app.post("/admin/reset_hwid/{license_key}", response_model=AdminSimpleResp)
def admin_reset_hwid(license_key: str, token: str = Form(...)):
    require_admin(token)
    conn = db()
    cur = conn.cursor()
    cur.execute("""
        UPDATE license_keys
        SET hwid = NULL, activated_at = NULL, expires_at = NULL
        WHERE license_key = ?
    """, (license_key,))
    conn.commit()
    conn.close()
    return AdminSimpleResp(ok=True)

@app.get("/admin/keys")
def admin_list_keys(token: str):
    require_admin(token)
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM license_keys ORDER BY created_at DESC")
    rows = cur.fetchall()
    conn.close()
    return {"ok": True, "keys": [row_to_public(r) for r in rows]}

@app.post("/admin/note", response_model=AdminSimpleResp)
def admin_set_note(token: str = Form(...), license_key: str = Form(...), note: str = Form("")):
    require_admin(token)
    conn = db()
    cur = conn.cursor()
    cur.execute("UPDATE license_keys SET note = ? WHERE license_key = ?", (note, license_key))
    conn.commit()
    conn.close()
    return AdminSimpleResp(ok=True)

# ========= ADMIN API (FormData) for your HTML panel =========
@app.post("/admin/web/create")
def admin_web_create(
    token: str = Form(...),
    key_type: Literal["lifetime", "timed"] = Form(...),
    count: int = Form(...),
    days: int = Form(0),
):
    # Just map to JSON handler
    return admin_create_keys(AdminCreateReq(token=token, key_type=key_type, count=count, days=days))

@app.get("/admin/web/keys")
def admin_web_keys(token: str):
    return admin_list_keys(token)

@app.post("/admin/web/revoke")
def admin_web_revoke(token: str = Form(...), license_key: str = Form(...)):
    require_admin(token)
    # Use the /admin/revoke/{license_key} route logic
    return admin_revoke(license_key=license_key, token=token).model_dump()

@app.post("/admin/web/reset-hwid")
def admin_web_reset(token: str = Form(...), license_key: str = Form(...)):
    require_admin(token)
    return admin_reset_hwid(license_key=license_key, token=token).model_dump()

@app.post("/admin/web/note")
def admin_web_note(token: str = Form(...), license_key: str = Form(...), note: str = Form("")):
    require_admin(token)
    return admin_set_note(token=token, license_key=license_key, note=note).model_dump()
