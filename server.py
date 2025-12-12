from fastapi import FastAPI, Header, HTTPException, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import sqlite3
from datetime import datetime, timedelta
import secrets
import os

app = FastAPI()
templates = Jinja2Templates(directory="templates")

DB = "licenses.db"
ADMIN_TOKEN = "my_secret_token"

def utcnow():
    return datetime.utcnow()

def init_db():
    con = sqlite3.connect(DB)
    cur = con.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS license_keys (
        key TEXT PRIMARY KEY,
        duration_days INTEGER,          -- NULL = lifetime
        activated_hwid TEXT,
        created_at TEXT NOT NULL,
        activated_at TEXT,
        expires_at TEXT,
        is_revoked INTEGER NOT NULL DEFAULT 0
    )
    """)
    con.commit()
    con.close()

init_db()

def gen_key():
    raw = secrets.token_hex(8).upper()
    return "NOVA-" + "-".join(raw[i:i+4] for i in range(0, 16, 4))

def require_admin(x_admin_token: str | None):
    if not ADMIN_TOKEN:
        raise HTTPException(status_code=500, detail="ADMIN_TOKEN not set")
    if not x_admin_token or x_admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")

class ActivateReq(BaseModel):
    key: str
    hwid: str

class CreateKeyReq(BaseModel):
    duration_days: int | None = None
    count: int = 1

@app.post("/activate")
def activate(req: ActivateReq):
    key = req.key.strip()
    hwid = req.hwid.strip()

    con = sqlite3.connect(DB)
    cur = con.cursor()
    cur.execute("SELECT duration_days, activated_hwid, expires_at, is_revoked FROM license_keys WHERE key=?", (key,))
    row = cur.fetchone()

    if not row:
        con.close()
        return {"ok": False, "reason": "INVALID_KEY"}

    duration_days, activated_hwid, expires_at, is_revoked = row

    if is_revoked:
        con.close()
        return {"ok": False, "reason": "REVOKED"}

    if expires_at and utcnow() > datetime.fromisoformat(expires_at):
        con.close()
        return {"ok": False, "reason": "EXPIRED"}

    if activated_hwid is None:
        now = utcnow()
        exp = None
        if duration_days is not None:
            exp = (now + timedelta(days=int(duration_days))).isoformat()

        cur.execute("""
            UPDATE license_keys
            SET activated_hwid=?, activated_at=?, expires_at=?
            WHERE key=?
        """, (hwid, now.isoformat(), exp, key))
        con.commit()
        con.close()
        return {"ok": True, "status": "ACTIVATED", "expires_at": exp}

    con.close()

    if activated_hwid == hwid:
        return {"ok": True, "status": "OK", "expires_at": expires_at}

    return {"ok": False, "reason": "KEY_ALREADY_USED"}

@app.post("/admin/create_keys")
def admin_create_keys(req: CreateKeyReq, x_admin_token: str | None = Header(default=None)):
    require_admin(x_admin_token)

    if req.count < 1 or req.count > 5000:
        raise HTTPException(status_code=400, detail="count must be 1..5000")

    con = sqlite3.connect(DB)
    cur = con.cursor()

    keys = []
    for _ in range(int(req.count)):
        k = gen_key()
        cur.execute("""
            INSERT INTO license_keys(key, duration_days, activated_hwid, created_at, activated_at, expires_at, is_revoked)
            VALUES(?, ?, NULL, ?, NULL, NULL, 0)
        """, (k, req.duration_days, utcnow().isoformat()))
        keys.append(k)

    con.commit()
    con.close()
    return {"ok": True, "duration_days": req.duration_days, "keys": keys}

@app.post("/admin/revoke/{license_key}")
def admin_revoke(license_key: str, x_admin_token: str | None = Header(default=None)):
    require_admin(x_admin_token)
    lk = license_key.strip()

    con = sqlite3.connect(DB)
    cur = con.cursor()
    cur.execute("UPDATE license_keys SET is_revoked=1 WHERE key=?", (lk,))
    con.commit()
    con.close()
    return {"ok": True, "revoked": lk}

@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request, token: str | None = None):
    if not token or token != ADMIN_TOKEN:
        return HTMLResponse("<h3>Unauthorized</h3><p>Use /admin?token=YOUR_ADMIN_TOKEN</p>", status_code=401)
    return templates.TemplateResponse("admin.html", {"request": request, "token": token})

@app.post("/admin/web/create", response_class=HTMLResponse)
def admin_web_create(
    request: Request,
    token: str = Form(...),
    key_type: str = Form(...),
    days: int = Form(30),
    count: int = Form(1),
):
    if token != ADMIN_TOKEN:
        return HTMLResponse("Unauthorized", status_code=401)

    duration_days = None if key_type == "lifetime" else int(days)
    count = max(1, min(int(count), 5000))

    con = sqlite3.connect(DB)
    cur = con.cursor()
    keys = []

    for _ in range(count):
        k = gen_key()
        cur.execute("""
            INSERT INTO license_keys(key, duration_days, activated_hwid, created_at, activated_at, expires_at, is_revoked)
            VALUES(?, ?, NULL, ?, NULL, NULL, 0)
        """, (k, duration_days, utcnow().isoformat()))
        keys.append(k)

    con.commit()
    con.close()

    return templates.TemplateResponse("admin.html", {
        "request": request,
        "token": token,
        "created_keys": keys,
        "message": f"Created {len(keys)} key(s)."
    })

@app.post("/admin/web/revoke", response_class=HTMLResponse)
def admin_web_revoke(
    request: Request,
    token: str = Form(...),
    license_key: str = Form(...),
):
    if token != ADMIN_TOKEN:
        return HTMLResponse("Unauthorized", status_code=401)

    lk = license_key.strip()

    con = sqlite3.connect(DB)
    cur = con.cursor()
    cur.execute("UPDATE license_keys SET is_revoked=1 WHERE key=?", (lk,))
    con.commit()
    con.close()

    return templates.TemplateResponse("admin.html", {
        "request": request,
        "token": token,
        "message": f"Revoked: {lk}"
    })
