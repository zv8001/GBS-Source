import asyncio
import os
import re
import json
import base64
import httpx
import secrets
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest
from starlette.responses import Response as StarletteResponse
from pydantic import BaseModel
from jose import JWTError, jwt
from passlib.context import CryptContext
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent.resolve()

SECRET_KEY        = os.environ.get("GBS_SECRET_KEY", "admin")
ALGORITHM         = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 30

GITHUB_TOKEN      = os.environ.get("GITHUB_TOKEN", "admin")
GITHUB_OWNER      = "zv8001"

# ── Owner account — cannot be demoted, deleted, or reset by other admins ─────
OWNER_EMAIL = os.environ.get("GBS_OWNER_EMAIL", "denverv1000@gmail.com")
GITHUB_REPO       = "GBS-DATABASE"
GITHUB_FILE_PATH  = "api/BannedUsers.txt"
GITHUB_JSON_PATH  = "api/BannedUsersAPI.json"
GITHUB_GROUP_PATH = "api/BannedGroups.json"
GITHUB_BRANCH     = "main"

RESEND_API_KEY    = os.environ.get("RESEND_API_KEY", "")
RESEND_FROM       = os.environ.get("RESEND_FROM", "noreply@unknown-technologies.us")
SITE_URL          = os.environ.get("SITE_URL", "https://gbs.unknown-technologies.us")

App = FastAPI(title="GBS API", docs_url=None, redoc_url=None, openapi_url=None, root_path="/gbs")
TURNSTILE_SECRET = os.environ.get("TURNSTILE_SECRET_KEY", "")

App.add_middleware(
    CORSMiddleware,
    allow_origins=["https://gbs.unknown-technologies.us"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

GBS_API_KEY    = os.environ.get("GBS_API_KEY", "")
UT_UTI_API_KEY = os.environ.get("UT_UTI_API_KEY", "")

PUBLIC_READONLY_PATHS = {
    "/health",
    "/debug/bans",
    "/gbs/debug/bans",
    "/users/lookup",
    "/gbs/users/lookup",
    "/bans",       "/bans/stats",
    "/groups",     "/groups/stats",
    "/BannedUsers.json",
    "/BannedGroups.json",
    "/gbs/health",
    "/gbs/bans",   "/gbs/bans/stats",
    "/gbs/groups", "/gbs/groups/stats",
    "/gbs/BannedUsers.json",
    "/gbs/BannedGroups.json",
    "/auth/forgot-password",
    "/auth/reset-password",
    "/auth/verify",
    "/auth/verify-otp",
    "/auth/resend-otp",
    "/gbs/auth/forgot-password",
    "/gbs/auth/reset-password",
    "/gbs/auth/verify",
    "/gbs/auth/verify-otp",
    "/gbs/auth/resend-otp",
}

class APIKeyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: StarletteRequest, call_next):
        if request.method == "OPTIONS":
            return await call_next(request)
        path = request.url.path
        if request.method == "GET" and (
            path in PUBLIC_READONLY_PATHS
            or path.startswith("/auth/verify/")
            or path.startswith("/gbs/auth/verify/")
        ):
            return await call_next(request)
        if request.method == "POST" and path in PUBLIC_READONLY_PATHS:
            return await call_next(request)
        if path in ("/AddUser", "/gbs/AddUser"):
            return await call_next(request)
        if not GBS_API_KEY:
            return await call_next(request)
        if request.headers.get("X-GBS-Key") != GBS_API_KEY:
            return StarletteResponse(
                content='{"detail":"Forbidden"}',
                status_code=403,
                media_type="application/json",
            )
        return await call_next(request)

App.add_middleware(APIKeyMiddleware)

RATE_LIMIT_ATTEMPTS = 5
RATE_LIMIT_WINDOW   = timedelta(minutes=15)
_login_attempts: dict = defaultdict(list)

def check_login_rate_limit(request: Request):
    ip  = request.client.host if request.client else "unknown"
    now = datetime.utcnow()
    cutoff = now - RATE_LIMIT_WINDOW
    _login_attempts[ip] = [t for t in _login_attempts[ip] if t > cutoff]
    if len(_login_attempts[ip]) >= RATE_LIMIT_ATTEMPTS:
        oldest = _login_attempts[ip][0]
        retry_after = int((oldest + RATE_LIMIT_WINDOW - now).total_seconds()) + 1
        raise HTTPException(
            status_code=429,
            detail=f"Too many login attempts. Try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)},
        )
    _login_attempts[ip].append(now)

pwd_context   = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

USERS_FILE = SCRIPT_DIR / "users.json"
_users_lock = asyncio.Lock()

def load_users() -> dict:
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE) as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            # Attempt recovery by reading backup
            backup = USERS_FILE.with_suffix(".bak")
            if os.path.exists(backup):
                print("[GBS] users.json corrupted — restoring from backup")
                with open(backup) as bf:
                    return json.load(bf)
            return {}

def save_users(users: dict):
    # Write to temp file first, then rename — atomic on most OSes
    tmp = USERS_FILE.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(users, f, indent=2)
    if os.path.exists(USERS_FILE):
        import shutil
        shutil.copy2(USERS_FILE, USERS_FILE.with_suffix(".bak"))
    os.replace(tmp, USERS_FILE)

LOG_FILE = "audit_log.json"

def load_log() -> list:
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE) as f:
        try:
            return json.load(f)
        except Exception:
            return []

def write_log(entry: dict):
    logs = load_log()
    logs.append(entry)
    tmp = LOG_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(logs, f, indent=2)
    os.replace(tmp, LOG_FILE)

def audit(action: str, actor: str, target: str = None, detail: str = None):
    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "action":    action,
        "actor":     actor,
    }
    if target: entry["target"] = target
    if detail: entry["detail"] = detail
    write_log(entry)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode["exp"] = expire
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    cred_exc = HTTPException(status_code=401, detail="Invalid credentials")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise cred_exc
    except JWTError:
        raise cred_exc
    if is_token_revoked(token):
        raise cred_exc
    users = load_users()
    user = users.get(email)
    if not user:
        raise cred_exc
    user["_raw_token"] = token
    return user

REVOKED_TOKENS_FILE = SCRIPT_DIR / "revoked_tokens.json"

def load_revoked() -> dict:
    if not os.path.exists(REVOKED_TOKENS_FILE):
        return {}
    with open(REVOKED_TOKENS_FILE) as f:
        try:
            return json.load(f)
        except Exception:
            return {}

def save_revoked(revoked: dict):
    with open(REVOKED_TOKENS_FILE, "w") as f:
        json.dump(revoked, f, indent=2)

def revoke_token(raw_token: str, expires_at: str):
    revoked = load_revoked()
    revoked[raw_token] = expires_at
    now = datetime.utcnow()
    revoked = {t: exp for t, exp in revoked.items()
               if datetime.fromisoformat(exp) > now}
    save_revoked(revoked)

def is_token_revoked(raw_token: str) -> bool:
    revoked = load_revoked()
    if raw_token not in revoked:
        return False
    exp = datetime.fromisoformat(revoked[raw_token])
    if datetime.utcnow() > exp:
        del revoked[raw_token]
        save_revoked(revoked)
        return False
    return True

def require_approved(user=Depends(get_current_user)):
    if user["status"] != "approved":
        raise HTTPException(status_code=403, detail="Account pending approval")
    return user

def require_admin(user=Depends(get_current_user)):
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin only")
    return user

GH_HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json",
}
GH_URL        = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/contents/{GITHUB_FILE_PATH}"
GH_JSON_URL   = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/contents/{GITHUB_JSON_PATH}"
GH_GROUP_URL  = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/contents/{GITHUB_GROUP_PATH}"

NETLIFY_TXT_URL   = "https://database.unknown-technologies.us/api/BannedUsers.txt"
NETLIFY_JSON_URL  = "https://database.unknown-technologies.us/api/BannedUsersAPI.json"
NETLIFY_GROUP_URL = "https://database.unknown-technologies.us/api/BannedGroups.json"

async def gh_get_file():
    async with httpx.AsyncClient() as client:
        r = await client.get(NETLIFY_TXT_URL)
    if r.status_code == 404:
        return "", None
    r.raise_for_status()
    return r.text, None

async def gh_get_json():
    async with httpx.AsyncClient() as client:
        r = await client.get(NETLIFY_JSON_URL)
    if r.status_code == 404:
        return [], None
    r.raise_for_status()
    return r.json(), None

_gh_write_lock = asyncio.Lock()

async def gh_write_file(content: str, sha: Optional[str], commit_msg: str):
    async with _gh_write_lock:
        async with httpx.AsyncClient() as client:
            r = await client.get(GH_URL, headers=GH_HEADERS, params={"ref": GITHUB_BRANCH})
        sha = r.json().get("sha") if r.status_code == 200 else None
        encoded = base64.b64encode(content.encode("utf-8")).decode("utf-8")
        payload = {"message": commit_msg, "content": encoded, "branch": GITHUB_BRANCH}
        if sha:
            payload["sha"] = sha
        async with httpx.AsyncClient() as client:
            r = await client.put(GH_URL, headers=GH_HEADERS, json=payload)
        r.raise_for_status()
        return r.json()

async def gh_write_json(records: list[dict], sha, commit_msg: str):
    async with _gh_write_lock:
        async with httpx.AsyncClient() as client:
            r = await client.get(GH_JSON_URL, headers=GH_HEADERS, params={"ref": GITHUB_BRANCH})
        sha = r.json().get("sha") if r.status_code == 200 else None
        encoded = base64.b64encode(json.dumps(records, indent=2).encode("utf-8")).decode("utf-8")
        payload = {"message": commit_msg, "content": encoded, "branch": GITHUB_BRANCH}
        if sha:
            payload["sha"] = sha
        async with httpx.AsyncClient() as client:
            r = await client.put(GH_JSON_URL, headers=GH_HEADERS, json=payload)
        r.raise_for_status()
        return r.json()

def sanitize_user_id(uid: str) -> str:
    """User IDs must be numeric only — reject anything else."""
    uid = uid.strip()
    if not uid.isdigit():
        raise HTTPException(400, f"Invalid user ID: {uid!r} — must be numeric")
    return uid

def parse_bans(raw: str) -> list[dict]:
    entries = [e.strip() for e in raw.split(",") if e.strip()]
    result = []
    for entry in entries:
        uid = re.search(r"USERID:\s*(\d+)", entry)
        msg = re.search(r"MESSAGE:\s*(.+)", entry)
        if uid:
            result.append({
                "userId":  uid.group(1),
                "message": msg.group(1).strip() if msg else "No reason provided",
            })
    return result

def serialize_bans(bans: list[dict]) -> str:
    return ",".join(f"USERID: {b['userId']} MESSAGE: {b['message']}" for b in bans)

async def sync_json(bans_txt: list[dict], extra: dict, sha_json, commit_msg: str):
    json_records, _ = await gh_get_json()
    json_lookup = {r["userId"]: r for r in json_records}
    merged = []
    for b in bans_txt:
        uid = b["userId"]
        info = extra.get(uid, {})
        if uid in json_lookup:
            rec = dict(json_lookup[uid])
            rec["message"] = b["message"]
            if info.get("_modifier") and rec.get("bannedBy", "unknown") in ("unknown", "", None):
                rec["bannedBy"] = f"Moderator (modified): {info['_modifier']}"
                rec["date"]     = info.get("_modified_date", datetime.utcnow().strftime("%Y-%m-%d"))
        else:
            rec = {
                "userId":   uid,
                "message":  b["message"],
                "date":     info.get("date", datetime.utcnow().strftime("%Y-%m-%d")),
                "bannedBy": info.get("bannedBy", "unknown"),
            }
        merged.append(rec)
    async with httpx.AsyncClient() as client:
        r = await client.get(GH_JSON_URL, headers=GH_HEADERS, params={"ref": GITHUB_BRANCH})
    sha = r.json().get("sha") if r.status_code == 200 else None
    await gh_write_json(merged, sha, commit_msg)
    return merged

_used_turnstile_tokens: dict = {}
_TURNSTILE_TOKEN_TTL = timedelta(minutes=10)

def _prune_used_tokens():
    now = datetime.utcnow()
    expired = [t for t, exp in _used_turnstile_tokens.items() if exp < now]
    for t in expired:
        del _used_turnstile_tokens[t]

async def verify_turnstile(token: str):
    if not TURNSTILE_SECRET:
        return
    if not token:
        raise HTTPException(400, "Turnstile verification required")
    _prune_used_tokens()
    if token in _used_turnstile_tokens:
        raise HTTPException(400, "Turnstile token already used")
    async with httpx.AsyncClient() as client:
        r = await client.post("https://challenges.cloudflare.com/turnstile/v0/siteverify", data={
            "secret": TURNSTILE_SECRET,
            "response": token,
        })
    if not r.json().get("success"):
        raise HTTPException(400, "Turnstile verification failed")
    _used_turnstile_tokens[token] = datetime.utcnow() + _TURNSTILE_TOKEN_TTL

RESET_RATE_LIMIT_ATTEMPTS = 2
RESET_RATE_LIMIT_WINDOW   = timedelta(minutes=30)
_reset_attempts: dict = defaultdict(list)

def check_reset_rate_limit(request: Request):
    ip     = request.client.host if request.client else "unknown"
    now    = datetime.utcnow()
    cutoff = now - RESET_RATE_LIMIT_WINDOW
    _reset_attempts[ip] = [t for t in _reset_attempts[ip] if t > cutoff]
    if len(_reset_attempts[ip]) >= RESET_RATE_LIMIT_ATTEMPTS:
        oldest = _reset_attempts[ip][0]
        retry_after = int((oldest + RESET_RATE_LIMIT_WINDOW - now).total_seconds()) + 1
        raise HTTPException(
            status_code=429,
            detail=f"Too many reset requests. Try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)},
        )
    _reset_attempts[ip].append(now)

class ForgotPasswordBody(BaseModel):
    email: str
    turnstile_token: str = ""

@App.post("/auth/forgot-password")
async def forgot_password(request: Request, body: ForgotPasswordBody):
    check_reset_rate_limit(request)
    await verify_turnstile(body.turnstile_token)
    users = load_users()
    user  = users.get(body.email.strip())
    if not user or not user.get("email_verified", True):
        return {"message": "If that email is registered, a reset link has been sent."}
    token  = secrets.token_urlsafe(32)
    user["password_reset_token"]        = token
    user["password_reset_token_issued"] = datetime.utcnow().isoformat()
    save_users(users)
    reset_url = f"{SITE_URL}/?reset_token={token}"
    html = f"""
    <div style="font-family:sans-serif;max-width:480px;margin:0 auto;background:#111115;color:#d0d4dc;padding:32px;border-radius:8px;border:1px solid #2a2a32;">
      <img src="https://unknown-technologies.us/Img/GBS/fav_icon.png" width="48" style="margin-bottom:16px;"/>
      <h2 style="color:#fff;margin:0 0 8px;">Reset your GBS password</h2>
      <p style="color:#5a6070;margin:0 0 24px;">Hi <strong style="color:#d0d4dc">{user['username']}</strong>, click the button below to set a new password. This link expires in 1 hour.</p>
      <a href="{reset_url}" style="display:inline-block;background:#e03030;color:#fff;text-decoration:none;padding:12px 28px;border-radius:4px;font-weight:700;letter-spacing:1px;text-transform:uppercase;font-size:13px;">Reset Password</a>
      <p style="color:#3a3f4a;font-size:11px;margin-top:24px;">Or copy this link: {reset_url}</p>
      <p style="color:#3a3f4a;font-size:11px;">If you didn't request this, ignore this email. Your password won't change.</p>
    </div>
    """
    try:
        async with httpx.AsyncClient() as client:
            r = await client.post(
                "https://api.resend.com/emails",
                headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"},
                json={"from": RESEND_FROM, "to": body.email, "subject": "Reset your GBS password", "html": html}
            )
            r.raise_for_status()
    except Exception as e:
        print(f"[GBS] Failed to send reset email to {body.email}: {e}")
    audit("auth.password_reset_requested", actor=user["username"], target=body.email)
    return {"message": "If that email is registered, a reset link has been sent."}

class SelfResetBody(BaseModel):
    token: str
    new_password: str

@App.post("/auth/reset-password")
async def reset_password_self(body: SelfResetBody):
    if len(body.new_password) < 6:
        raise HTTPException(400, "Password must be at least 6 characters")
    users = load_users()
    for email, user in users.items():
        if user.get("password_reset_token") == body.token:
            issued = user.get("password_reset_token_issued")
            if issued:
                issued_dt = datetime.fromisoformat(issued)
                if datetime.utcnow() - issued_dt > timedelta(hours=1):
                    raise HTTPException(400, "Reset link has expired. Please request a new one.")
            user["hashed_password"]             = pwd_context.hash(body.new_password)
            user["password_reset_token"]        = None
            user["password_reset_token_issued"] = None
            save_users(users)
            audit("auth.password_reset_completed", actor=user["username"], target=email)
            return {"message": "Password updated successfully."}
    raise HTTPException(400, "Invalid or already used reset link.")

async def send_verification_email(email: str, username: str, token: str):
    if not RESEND_API_KEY:
        print(f"[GBS] RESEND_API_KEY not set — skipping verification email for {email}")
        return
    verify_url = f"{SITE_URL}/verify/{token}"
    html = f"""
    <div style="font-family:sans-serif;max-width:480px;margin:0 auto;background:#111115;color:#d0d4dc;padding:32px;border-radius:8px;border:1px solid #2a2a32;">
      <img src="https://unknown-technologies.us/Img/GBS/fav_icon.png" width="48" style="margin-bottom:16px;"/>
      <h2 style="color:#fff;margin:0 0 8px;">Verify your GBS account</h2>
      <p style="color:#5a6070;margin:0 0 24px;">Hi <strong style="color:#d0d4dc">{username}</strong>, click the button below to verify your email address.</p>
      <a href="{verify_url}" style="display:inline-block;background:#e03030;color:#fff;text-decoration:none;padding:12px 28px;border-radius:4px;font-weight:700;letter-spacing:1px;text-transform:uppercase;font-size:13px;">Verify Email</a>
      <p style="color:#3a3f4a;font-size:11px;margin-top:24px;">Or copy this link: {verify_url}</p>
      <p style="color:#3a3f4a;font-size:11px;">This link expires in 24 hours. If you didn't register, ignore this email.</p>
    </div>
    """
    try:
        async with httpx.AsyncClient() as client:
            r = await client.post(
                "https://api.resend.com/emails",
                headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"},
                json={"from": RESEND_FROM, "to": email, "subject": "Verify your GBS account", "html": html}
            )
            r.raise_for_status()
            print(f"[GBS] Verification email sent to {email}")
    except Exception as e:
        print(f"[GBS] Failed to send verification email to {email}: {e}")

from fastapi.responses import RedirectResponse

@App.get("/auth/verify/{token}")
async def verify_email(token: str):
    users = load_users()
    for email, user in users.items():
        if user.get("verification_token") == token:
            issued = user.get("verification_token_issued")
            if issued:
                issued_dt = datetime.fromisoformat(issued)
                if datetime.utcnow() - issued_dt > timedelta(hours=24):
                    raise HTTPException(400, "Verification link has expired. Please register again.")
            user["email_verified"]            = True
            user["verification_token"]        = None
            user["verification_token_issued"] = None
            save_users(users)
            audit("auth.email_verified", actor=user["username"], target=email)
            return RedirectResponse(url=f"{SITE_URL}?verified=1")
    raise HTTPException(400, "Invalid or already used verification link.")

@App.post("/auth/resend-verification")
async def resend_verification(body: dict):
    email = body.get("email", "").strip()
    users = load_users()
    user  = users.get(email)
    if not user:
        return {"message": "If that email is registered, a verification link has been sent."}
    if user.get("email_verified"):
        return {"message": "Email already verified."}
    check_email_rate_limit(email)
    token = secrets.token_urlsafe(32)
    user["verification_token"]        = token
    user["verification_token_issued"] = datetime.utcnow().isoformat()
    save_users(users)
    await send_verification_email(email, user["username"], token)
    return {"message": "Verification email resent."}

class RegisterBody(BaseModel):
    email: str
    password: str
    username: str
    turnstile_token: str = ""

@App.post("/auth/register")
async def register(body: RegisterBody):
    await verify_turnstile(body.turnstile_token)
    # Validate email format
    if not re.match(r'^[^@\s<>"\'&]+@[^@\s<>"\'&]+\.[^@\s<>"\'&]+$', body.email.strip()):
        raise HTTPException(400, "Invalid email address")
    # Sanitize username — no HTML special characters
    if re.search(r'[<>"\'&]', body.username):
        raise HTTPException(400, "Username contains invalid characters")
    if len(body.username) > 32:
        raise HTTPException(400, "Username must be 32 characters or less")
    if len(body.password) < 6:
        raise HTTPException(400, "Password must be at least 6 characters")
    users = load_users()
    if body.email in users:
        raise HTTPException(400, "Email already registered")
    is_first = len(users) == 0
    token = secrets.token_urlsafe(32)
    users[body.email] = {
        "email":                      body.email,
        "username":                   body.username,
        "hashed_password":            pwd_context.hash(body.password),
        "status":                     "approved" if is_first else "pending",
        "is_admin":                   is_first,
        "created_at":                 datetime.utcnow().isoformat(),
        "email_verified":             is_first,
        "verification_token":         None if is_first else token,
        "verification_token_issued":  None if is_first else datetime.utcnow().isoformat(),
    }
    save_users(users)
    audit("auth.register", actor=body.username, target=body.email,
          detail="auto-approved as first user" if is_first else "pending approval")
    if not is_first:
        await send_verification_email(body.email, body.username, token)
    msg = "Account created. You are the first user — admin granted." if is_first else "Account created. Check your email to verify your address, then await admin approval."
    return {"message": msg, "status": "approved" if is_first else "pending"}

OTP_EXPIRE_MINUTES = 5
OTP_MAX_ATTEMPTS   = 3

# ── Email send rate limiter (protects Resend quota) ──────────────────────────
EMAIL_RATE_LIMIT_ATTEMPTS = 3
EMAIL_RATE_LIMIT_WINDOW   = timedelta(minutes=30)
_email_attempts: dict = defaultdict(list)

def check_email_rate_limit(identifier: str):
    """Rate limit by email address — max 3 emails per 30 min per address."""
    now    = datetime.utcnow()
    cutoff = now - EMAIL_RATE_LIMIT_WINDOW
    _email_attempts[identifier] = [t for t in _email_attempts[identifier] if t > cutoff]
    if len(_email_attempts[identifier]) >= EMAIL_RATE_LIMIT_ATTEMPTS:
        raise HTTPException(429, "Too many email requests. Please wait before trying again.")
    _email_attempts[identifier].append(now)

def generate_otp() -> str:
    return str(secrets.randbelow(900000) + 100000)

async def send_otp_email(email: str, username: str, otp: str):
    if not RESEND_API_KEY:
        print(f"[GBS] RESEND_API_KEY not set — OTP for {email}: {otp}")
        return
    html = f"""
    <div style="font-family:sans-serif;max-width:480px;margin:0 auto;background:#111115;color:#d0d4dc;padding:32px;border-radius:8px;border:1px solid #2a2a32;">
      <img src="https://unknown-technologies.us/Img/GBS/fav_icon.png" width="48" style="margin-bottom:16px;"/>
      <h2 style="color:#fff;margin:0 0 8px;">Your login code</h2>
      <p style="color:#5a6070;margin:0 0 24px;">Hi <strong style="color:#d0d4dc">{username}</strong>, use the code below to complete your login. It expires in {OTP_EXPIRE_MINUTES} minutes.</p>
      <div style="background:#0c0c0e;border:1px solid #2a2a32;border-radius:6px;padding:24px;text-align:center;margin-bottom:24px;">
        <span style="font-family:monospace;font-size:40px;font-weight:700;letter-spacing:12px;color:#e03030;">{otp}</span>
      </div>
      <p style="color:#3a3f4a;font-size:11px;">If you didn't try to log in, someone may have your password. Consider changing it immediately.</p>
    </div>
    """
    try:
        async with httpx.AsyncClient() as client:
            r = await client.post(
                "https://api.resend.com/emails",
                headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"},
                json={"from": RESEND_FROM, "to": email, "subject": "Your GBS login code", "html": html}
            )
            r.raise_for_status()
            print(f"[GBS] OTP sent to {email}")
    except Exception as e:
        print(f"[GBS] Failed to send OTP to {email}: {e}")

@App.post("/auth/login")
async def login(request: Request, form: OAuth2PasswordRequestForm = Depends()):
    check_login_rate_limit(request)
    raw_form = await request.form()
    turnstile_token = raw_form.get("turnstile_token", "")
    await verify_turnstile(turnstile_token)
    users = load_users()
    user  = users.get(form.username)
    if not user or not pwd_context.verify(form.password, user["hashed_password"]):
        raise HTTPException(401, "Incorrect email or password")
    if not user.get("email_verified", True):
        raise HTTPException(403, "Please verify your email address before logging in.")
    if user["status"] == "pending":
        raise HTTPException(403, "Account pending approval")
    if user["status"] == "rejected":
        raise HTTPException(403, "Account rejected")
    ip = request.client.host if request.client else "unknown"
    _login_attempts[ip] = []
    check_email_rate_limit(form.username)  # protect Resend quota
    otp = generate_otp()
    user["otp"]          = otp
    user["otp_issued"]   = datetime.utcnow().isoformat()
    user["otp_attempts"] = 0
    save_users(users)
    await send_otp_email(form.username, user["username"], otp)
    audit("auth.otp_sent", actor=user["username"], target=form.username)
    return {"requires_otp": True, "email": form.username}

class VerifyOTPBody(BaseModel):
    email: str
    otp: str

@App.post("/auth/verify-otp")
async def verify_otp(body: VerifyOTPBody):
    users = load_users()
    user  = users.get(body.email)
    if not user:
        raise HTTPException(401, "Invalid request")
    stored_otp = user.get("otp")
    issued     = user.get("otp_issued")
    attempts   = user.get("otp_attempts", 0)
    if not stored_otp or not issued:
        raise HTTPException(400, "No OTP pending — please log in again")
    issued_dt = datetime.fromisoformat(issued)
    if datetime.utcnow() - issued_dt > timedelta(minutes=OTP_EXPIRE_MINUTES):
        user["otp"] = None
        save_users(users)
        raise HTTPException(400, "Code expired — please log in again")
    if attempts >= OTP_MAX_ATTEMPTS:
        user["otp"] = None
        save_users(users)
        raise HTTPException(429, "Too many attempts — please log in again")
    if body.otp.strip() != stored_otp:
        user["otp_attempts"] = attempts + 1
        save_users(users)
        remaining = OTP_MAX_ATTEMPTS - (attempts + 1)
        raise HTTPException(401, f"Incorrect code — {remaining} attempt{'s' if remaining != 1 else ''} remaining")
    user["otp"]          = None
    user["otp_issued"]   = None
    user["otp_attempts"] = 0
    save_users(users)
    audit("auth.login", actor=user["username"], target=body.email)
    token = create_access_token({"sub": body.email}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": token, "token_type": "bearer",
            "username": user["username"], "is_admin": user["is_admin"]}

@App.post("/auth/resend-otp")
async def resend_otp(body: VerifyOTPBody):
    users = load_users()
    user  = users.get(body.email)
    if not user:
        return {"message": "If that account exists, a new code has been sent."}
    check_email_rate_limit(body.email)
    otp = generate_otp()
    user["otp"]          = otp
    user["otp_issued"]   = datetime.utcnow().isoformat()
    user["otp_attempts"] = 0
    save_users(users)
    await send_otp_email(body.email, user["username"], otp)
    return {"message": "New code sent."}

@App.get("/auth/me")
async def me(user=Depends(require_approved)):
    return {"email": user["email"], "username": user["username"],
            "is_admin": user["is_admin"], "status": user["status"]}

@App.post("/auth/logout")
async def logout(user=Depends(get_current_user)):
    raw_token = user.get("_raw_token")
    if raw_token:
        try:
            payload = jwt.decode(raw_token, SECRET_KEY, algorithms=[ALGORITHM])
            exp = datetime.utcfromtimestamp(payload["exp"]).isoformat()
        except Exception:
            exp = (datetime.utcnow() + timedelta(days=30)).isoformat()
        revoke_token(raw_token, exp)
        audit("auth.logout", actor=user["username"], target=user["email"])
    return {"message": "Logged out"}

@App.get("/admin/users")
async def list_users(admin=Depends(require_admin)):
    users = load_users()
    return [{"email": u["email"], "username": u["username"],
             "status": u["status"], "is_admin": u["is_admin"],
             "is_owner": u["email"] == OWNER_EMAIL,
             "created_at": u.get("created_at")}
            for u in users.values()]

@App.get("/admin/logs")
async def get_logs(admin=Depends(require_admin)):
    return load_log()

@App.post("/admin/users/{email}/approve")
async def approve_user(email: str, admin=Depends(require_admin)):
    users = load_users()
    if email not in users: raise HTTPException(404, "User not found")
    users[email]["status"] = "approved"
    save_users(users)
    audit("user.approved", actor=admin["username"], target=email)
    return {"message": f"{email} approved"}

@App.post("/admin/users/{email}/reject")
async def reject_user(email: str, admin=Depends(require_admin)):
    users = load_users()
    if email not in users: raise HTTPException(404, "User not found")
    users[email]["status"] = "rejected"
    save_users(users)
    audit("user.rejected", actor=admin["username"], target=email)
    return {"message": f"{email} rejected"}

@App.post("/admin/users/{email}/promote")
async def promote_user(email: str, admin=Depends(require_admin)):
    users = load_users()
    if email not in users: raise HTTPException(404, "User not found")
    users[email]["is_admin"] = True
    save_users(users)
    audit("user.promoted_to_admin", actor=admin["username"], target=email)
    return {"message": f"{email} promoted to admin"}

@App.post("/admin/users/{email}/demote")
async def demote_user(email: str, admin=Depends(require_admin)):
    if email == admin["email"]:
        raise HTTPException(400, "You cannot remove your own admin privileges")
    if email == OWNER_EMAIL:
        raise HTTPException(403, "The owner account cannot be demoted")
    users = load_users()
    if email not in users: raise HTTPException(404, "User not found")
    users[email]["is_admin"] = False
    save_users(users)
    audit("user.demoted_from_admin", actor=admin["username"], target=email)
    return {"message": f"{email} demoted from admin"}

@App.delete("/admin/users/{email}")
async def delete_user(email: str, admin=Depends(require_admin)):
    if email == OWNER_EMAIL:
        raise HTTPException(403, "The owner account cannot be deleted")
    users = load_users()
    if email not in users: raise HTTPException(404, "User not found")
    username = users[email].get("username", email)
    del users[email]
    save_users(users)
    audit("user.deleted", actor=admin["username"], target=email, detail=f"username: {username}")
    return {"message": f"{email} deleted"}

class ResetPasswordBody(BaseModel):
    new_password: str

@App.post("/admin/users/{email}/reset-password")
async def reset_password(email: str, body: ResetPasswordBody, admin=Depends(require_admin)):
    if email == OWNER_EMAIL and admin["email"] != OWNER_EMAIL:
        raise HTTPException(403, "Only the owner can reset their own password")
    users = load_users()
    if email not in users: raise HTTPException(404, "User not found")
    if len(body.new_password) < 6:
        raise HTTPException(400, "Password must be at least 6 characters")
    users[email]["hashed_password"] = pwd_context.hash(body.new_password)
    save_users(users)
    audit("user.password_reset", actor=admin["username"], target=email)
    return {"message": f"Password reset for {email}"}

@App.get("/debug/bans")
async def debug_bans():
    raw, _ = await gh_get_file()
    bans = parse_bans(raw)
    return {"count": len(bans), "ids": [b["userId"] for b in bans], "raw_preview": raw[:500]}

@App.get("/users/lookup")
async def lookup_user(username: str):
    async with httpx.AsyncClient() as client:
        r = await client.post(
            "https://users.roproxy.com/v1/usernames/users",
            json={"usernames": [username], "excludeBannedUsers": False},
            headers={"Content-Type": "application/json"}
        )
    if not r.is_success:
        raise HTTPException(404, "User not found")
    data = r.json()
    users = data.get("data", [])
    if not users:
        raise HTTPException(404, "User not found")
    user = users[0]
    avatar_url = None
    try:
        async with httpx.AsyncClient() as client:
            t = await client.get(
                "https://thumbnails.roproxy.com/v1/users/avatar-headshot",
                params={"userIds": user["id"], "size": "48x48", "format": "Png"}
            )
        thumb_data = t.json()
        avatar_url = thumb_data.get("data", [{}])[0].get("imageUrl")
    except Exception:
        pass
    return {
        "id": user["id"],
        "username": user["name"],
        "displayName": user["displayName"],
        "avatarUrl": avatar_url
    }

@App.on_event("startup")
async def scrub_ips_from_audit_log():
    """Remove any IP addresses previously logged in audit log details."""
    logs = load_log()
    changed = False
    for entry in logs:
        detail = entry.get("detail")
        if detail:
            # Remove "ip: x.x.x.x" in any position
            new_detail = re.sub(r",?\s*ip:\s*\S+", "", detail).strip()
            new_detail = new_detail or None
            if new_detail != detail:
                entry["detail"] = new_detail
                changed = True
    if changed:
        with open(LOG_FILE, "w") as f:
            json.dump(logs, f, indent=2)
        print("[GBS] Scrubbed IP addresses from audit log")

@App.post("/admin/scrub-ips")
async def scrub_ips(admin=Depends(require_admin)):
    """Manually trigger IP scrub from audit log."""
    logs = load_log()
    changed = 0
    for entry in logs:
        detail = entry.get("detail")
        if detail:
            new_detail = re.sub(r",?\s*ip:\s*\S+", "", detail).strip() or None
            if new_detail != detail:
                entry["detail"] = new_detail
                changed += 1
    with open(LOG_FILE, "w") as f:
        json.dump(logs, f, indent=2)
    return {"message": f"Scrubbed {changed} entries"}

@App.post("/admin/dedup-logs")
async def dedup_logs(admin=Depends(require_admin)):
    """Remove consecutive duplicate audit log entries (same action/actor/target/detail within 60s)."""
    logs = load_log()
    deduped = []
    for entry in logs:
        if deduped:
            prev = deduped[-1]
            same = (
                entry.get("action") == prev.get("action") and
                entry.get("actor")  == prev.get("actor")  and
                entry.get("target") == prev.get("target") and
                entry.get("detail") == prev.get("detail")
            )
            if same:
                try:
                    t1 = datetime.fromisoformat(entry["timestamp"].rstrip("Z"))
                    t2 = datetime.fromisoformat(prev["timestamp"].rstrip("Z"))
                    if abs((t1 - t2).total_seconds()) < 60:
                        continue
                except Exception:
                    pass
        deduped.append(entry)
    removed = len(logs) - len(deduped)
    with open(LOG_FILE, "w") as f:
        json.dump(deduped, f, indent=2)
    return {"message": f"Removed {removed} duplicate entries", "remaining": len(deduped)}

@App.get("/health")
async def health():
    return {"status": "ok", "service": "GBS API"}

@App.get("/bans")
async def get_bans():
    json_records, _ = await gh_get_json()
    if json_records:
        return {"bans": json_records, "total": len(json_records)}
    raw, _ = await gh_get_file()
    bans = parse_bans(raw)
    return {"bans": bans, "total": len(bans)}

class BanBody(BaseModel):
    userId: str
    message: str

@App.post("/bans")
async def add_ban(body: BanBody, user=Depends(require_approved)):
    raw, sha = await gh_get_file()
    bans = parse_bans(raw)
    if any(b["userId"] == body.userId for b in bans):
        raise HTTPException(400, "User already banned")
    bans.append({"userId": body.userId, "message": body.message})
    new_raw = serialize_bans(bans)
    await gh_write_file(new_raw, sha, f"ban: add {body.userId} by {user['username']}")
    await sync_json(bans, {
        body.userId: {
            "date":     datetime.utcnow().strftime("%Y-%m-%d"),
            "bannedBy": user["username"],
        }
    }, None, f"ban: sync json add {body.userId}")
    audit("ban.add", actor=user["username"], target=body.userId, detail=body.message)
    return {"message": "User banned", "total": len(bans)}

class BulkBanBody(BaseModel):
    userIds: list[str]
    message: str

class EditBanBody(BaseModel):
    message: str

@App.post("/bans/bulk")
async def add_ban_bulk(body: BulkBanBody, user=Depends(require_approved)):
    if not body.userIds:
        raise HTTPException(400, "No user IDs provided")
    raw, sha = await gh_get_file()
    bans = parse_bans(raw)
    existing_ids = {b["userId"] for b in bans}
    added, skipped = [], []
    today = datetime.utcnow().strftime("%Y-%m-%d")
    extra = {}
    for uid in body.userIds:
        uid = uid.strip()
        if not uid: continue
        try:
            uid = sanitize_user_id(uid)
        except HTTPException:
            skipped.append(uid)
            continue
        if uid in existing_ids:
            skipped.append(uid)
        else:
            bans.append({"userId": uid, "message": body.message})
            existing_ids.add(uid)
            added.append(uid)
            extra[uid] = {"date": today, "bannedBy": user["username"]}
    if not added:
        return {"message": "All users already banned", "added": [], "skipped": skipped}
    new_raw = serialize_bans(bans)
    await gh_write_file(new_raw, sha, f"ban: bulk add {len(added)} users by {user['username']}")
    await sync_json(bans, extra, None, f"ban: sync json bulk add {len(added)}")
    for uid in added:
        audit("ban.add", actor=user["username"], target=uid, detail=body.message)
    return {"message": f"Banned {len(added)} users", "added": added, "skipped": skipped, "total": len(bans)}

@App.patch("/bans/{user_id}")
async def edit_ban(user_id: str, body: EditBanBody, user=Depends(require_approved)):
    raw, sha = await gh_get_file()
    bans = parse_bans(raw)
    target = next((b for b in bans if b["userId"] == user_id), None)
    if not target:
        raise HTTPException(404, "User not in ban list")
    old_msg = target["message"]
    target["message"] = body.message
    new_raw = serialize_bans(bans)
    await gh_write_file(new_raw, sha, f"ban: edit reason for {user_id} by {user['username']}")
    today = datetime.utcnow().strftime("%Y-%m-%d")
    await sync_json(bans, {
        user_id: {"_modifier": user["username"], "_modified_date": today}
    }, None, f"ban: sync json edit {user_id}")
    audit("ban.edit", actor=user["username"], target=user_id,
          detail=f"old: {old_msg} | new: {body.message}")
    return {"message": "Ban reason updated"}

class BulkEditBody(BaseModel):
    userIds: list[str]
    message: str

@App.post("/bans/bulk-edit")
async def edit_ban_bulk(body: BulkEditBody, user=Depends(require_approved)):
    if not body.userIds:
        raise HTTPException(400, "No user IDs provided")
    target_ids = {uid.strip() for uid in body.userIds if uid.strip()}
    raw, sha = await gh_get_file()
    bans = parse_bans(raw)
    updated = []
    for b in bans:
        if b["userId"] in target_ids:
            old_msg = b["message"]
            b["message"] = body.message
            updated.append(b["userId"])
            audit("ban.edit", actor=user["username"], target=b["userId"],
                  detail=f"bulk edit | old: {old_msg} | new: {body.message}")
    if not updated:
        raise HTTPException(404, "None of the specified users are in the ban list")
    today = datetime.utcnow().strftime("%Y-%m-%d")
    modifier_extra = {uid: {"_modifier": user["username"], "_modified_date": today} for uid in updated}
    new_raw = serialize_bans(bans)
    await gh_write_file(new_raw, sha, f"ban: bulk edit {len(updated)} reasons by {user['username']}")
    await sync_json(bans, modifier_extra, None, f"ban: sync json bulk edit {len(updated)}")
    return {"message": f"Updated {len(updated)} ban reasons", "updated": len(updated)}

class BulkRemoveBody(BaseModel):
    userIds: list[str]

@App.post("/bans/bulk-remove")
async def remove_ban_bulk(body: BulkRemoveBody, user=Depends(require_approved)):
    if not body.userIds:
        raise HTTPException(400, "No user IDs provided")
    target_ids = {uid.strip() for uid in body.userIds if uid.strip()}
    raw, sha = await gh_get_file()
    bans = parse_bans(raw)
    new_bans = [b for b in bans if b["userId"] not in target_ids]
    removed  = [b["userId"] for b in bans if b["userId"] in target_ids]
    if not removed:
        raise HTTPException(404, "None of the specified users are in the ban list")
    new_raw = serialize_bans(new_bans)
    await gh_write_file(new_raw, sha, f"ban: bulk remove {len(removed)} users by {user['username']}")
    await sync_json(new_bans, {}, None, f"ban: sync json bulk remove {len(removed)}")
    for uid in removed:
        audit("ban.remove", actor=user["username"], target=uid, detail="bulk unban")
    return {"message": f"Unbanned {len(removed)} users", "removed": len(removed), "skipped": len(target_ids) - len(removed)}

@App.delete("/bans/{user_id}")
async def remove_ban(user_id: str, user=Depends(require_approved)):
    raw, sha = await gh_get_file()
    bans = parse_bans(raw)
    new_bans = [b for b in bans if b["userId"] != user_id]
    if len(new_bans) == len(bans):
        raise HTTPException(404, "User not in ban list")
    new_raw = serialize_bans(new_bans)
    await gh_write_file(new_raw, sha, f"ban: remove {user_id} by {user['username']}")
    await sync_json(new_bans, {}, None, f"ban: sync json remove {user_id}")
    audit("ban.remove", actor=user["username"], target=user_id)
    return {"message": "User unbanned", "total": len(new_bans)}

@App.get("/bans/stats")
async def ban_stats():
    json_records, _ = await gh_get_json()
    if not json_records:
        raw, _ = await gh_get_file()
        json_records = parse_bans(raw)
    total      = len(json_records)
    exploiters = sum(1 for b in json_records if "exploit" in b.get("message", "").lower())
    stolen     = sum(1 for b in json_records if any(k in b.get("message", "").lower() for k in ("stolen", "stealer", "assets")))
    bypass     = sum(1 for b in json_records if "bypass" in b.get("message", "").lower())
    bots       = sum(1 for b in json_records if "bot" in b.get("message", "").lower() or "spam" in b.get("message", "").lower())
    return {"total": total, "exploiters": exploiters, "stolen": stolen, "bypass": bypass, "bots": bots}

async def gh_get_groups() -> list[dict]:
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(NETLIFY_GROUP_URL)
        if r.status_code != 200:
            return []
        data = r.json()
        return data if isinstance(data, list) else []
    except Exception:
        return []

async def gh_write_groups(records: list[dict], commit_msg: str):
    async with httpx.AsyncClient() as client:
        r = await client.get(GH_GROUP_URL, headers=GH_HEADERS, params={"ref": GITHUB_BRANCH})
    sha = r.json().get("sha") if r.status_code == 200 else None
    encoded = base64.b64encode(json.dumps(records, indent=2).encode("utf-8")).decode("utf-8")
    payload = {"message": commit_msg, "content": encoded, "branch": GITHUB_BRANCH}
    if sha:
        payload["sha"] = sha
    async with httpx.AsyncClient() as client:
        r = await client.put(GH_GROUP_URL, headers=GH_HEADERS, json=payload)
    r.raise_for_status()
    return r.json()

class GroupBanBody(BaseModel):
    groupId: str
    message: str

class GroupBulkBanBody(BaseModel):
    groupIds: list[str]
    message: str

class GroupEditBody(BaseModel):
    message: str

class GroupBulkEditBody(BaseModel):
    groupIds: list[str]
    message: str

class GroupBulkRemoveBody(BaseModel):
    groupIds: list[str]

@App.get("/groups")
async def get_groups():
    groups = await gh_get_groups()
    return {"groups": groups, "total": len(groups)}

@App.get("/groups/stats")
async def group_stats():
    groups = await gh_get_groups()
    total      = len(groups)
    exploiters = sum(1 for b in groups if "exploit" in b.get("message", "").lower())
    stolen     = sum(1 for b in groups if any(k in b.get("message", "").lower() for k in ("stolen", "stealer", "assets")))
    bypass     = sum(1 for b in groups if "bypass" in b.get("message", "").lower())
    bots       = sum(1 for b in groups if "bot" in b.get("message", "").lower() or "spam" in b.get("message", "").lower())
    return {"total": total, "exploiters": exploiters, "stolen": stolen, "bypass": bypass, "bots": bots}

@App.post("/groups")
async def add_group_ban(body: GroupBanBody, user=Depends(require_approved)):
    groups = await gh_get_groups()
    if any(g["groupId"] == body.groupId for g in groups):
        raise HTTPException(400, "Group already banned")
    groups.append({
        "groupId":  body.groupId,
        "message":  body.message,
        "date":     datetime.utcnow().strftime("%Y-%m-%d"),
        "bannedBy": user["username"],
    })
    await gh_write_groups(groups, f"group-ban: add {body.groupId} by {user['username']}")
    audit("group.ban.add", actor=user["username"], target=body.groupId, detail=body.message)
    return {"message": "Group banned", "total": len(groups)}

@App.post("/groups/bulk")
async def add_group_ban_bulk(body: GroupBulkBanBody, user=Depends(require_approved)):
    if not body.groupIds:
        raise HTTPException(400, "No group IDs provided")
    groups = await gh_get_groups()
    existing = {g["groupId"] for g in groups}
    today    = datetime.utcnow().strftime("%Y-%m-%d")
    added, skipped = [], []
    for gid in body.groupIds:
        gid = gid.strip()
        if not gid: continue
        if gid in existing:
            skipped.append(gid)
        else:
            groups.append({"groupId": gid, "message": body.message, "date": today, "bannedBy": user["username"]})
            existing.add(gid)
            added.append(gid)
    if not added:
        return {"message": "All groups already banned", "added": [], "skipped": skipped}
    await gh_write_groups(groups, f"group-ban: bulk add {len(added)} by {user['username']}")
    for gid in added:
        audit("group.ban.add", actor=user["username"], target=gid, detail=body.message)
    return {"message": f"Banned {len(added)} groups", "added": added, "skipped": skipped, "total": len(groups)}

@App.patch("/groups/{group_id}")
async def edit_group_ban(group_id: str, body: GroupEditBody, user=Depends(require_approved)):
    groups = await gh_get_groups()
    target = next((g for g in groups if g["groupId"] == group_id), None)
    if not target:
        raise HTTPException(404, "Group not in ban list")
    old_msg = target["message"]
    target["message"] = body.message
    await gh_write_groups(groups, f"group-ban: edit {group_id} by {user['username']}")
    audit("group.ban.edit", actor=user["username"], target=group_id, detail=f"old: {old_msg} | new: {body.message}")
    return {"message": "Group ban reason updated"}

@App.post("/groups/bulk-edit")
async def edit_group_ban_bulk(body: GroupBulkEditBody, user=Depends(require_approved)):
    if not body.groupIds:
        raise HTTPException(400, "No group IDs provided")
    target_ids = {gid.strip() for gid in body.groupIds if gid.strip()}
    groups = await gh_get_groups()
    updated = []
    for g in groups:
        if g["groupId"] in target_ids:
            old_msg = g["message"]
            g["message"] = body.message
            updated.append(g["groupId"])
            audit("group.ban.edit", actor=user["username"], target=g["groupId"],
                  detail=f"bulk edit | old: {old_msg} | new: {body.message}")
    if not updated:
        raise HTTPException(404, "None of the specified groups are in the ban list")
    await gh_write_groups(groups, f"group-ban: bulk edit {len(updated)} by {user['username']}")
    return {"message": f"Updated {len(updated)} group ban reasons", "updated": len(updated)}

@App.delete("/groups/{group_id}")
async def remove_group_ban(group_id: str, user=Depends(require_approved)):
    groups = await gh_get_groups()
    new_groups = [g for g in groups if g["groupId"] != group_id]
    if len(new_groups) == len(groups):
        raise HTTPException(404, "Group not in ban list")
    await gh_write_groups(new_groups, f"group-ban: remove {group_id} by {user['username']}")
    audit("group.ban.remove", actor=user["username"], target=group_id)
    return {"message": "Group unbanned", "total": len(new_groups)}

@App.post("/groups/bulk-remove")
async def remove_group_ban_bulk(body: GroupBulkRemoveBody, user=Depends(require_approved)):
    if not body.groupIds:
        raise HTTPException(400, "No group IDs provided")
    target_ids = {gid.strip() for gid in body.groupIds if gid.strip()}
    groups = await gh_get_groups()
    new_groups = [g for g in groups if g["groupId"] not in target_ids]
    removed    = [g["groupId"] for g in groups if g["groupId"] in target_ids]
    if not removed:
        raise HTTPException(404, "None of the specified groups are in the ban list")
    await gh_write_groups(new_groups, f"group-ban: bulk remove {len(removed)} by {user['username']}")
    for gid in removed:
        audit("group.ban.remove", actor=user["username"], target=gid, detail="bulk remove")
    return {"message": f"Unbanned {len(removed)} groups", "removed": len(removed), "skipped": len(target_ids) - len(removed)}

class AddUserBody(BaseModel):
    userId:   str
    message:  str
    category: str           = "General"
    bannedBy: str           = "Roblox Game"
    date:     Optional[str] = None

@App.post("/AddUser")
async def add_user_from_roblox(body: AddUserBody, request: Request):
    if not UT_UTI_API_KEY:
        raise HTTPException(503, "Direct ban API is not configured on this server")
    if request.headers.get("X-API-Key") != UT_UTI_API_KEY:
        raise HTTPException(403, "Invalid API key")
    uid  = sanitize_user_id(body.userId)
    today   = datetime.utcnow().strftime("%Y-%m-%d")
    date    = body.date or today
    message = f"[{body.category}] {body.message}"
    raw, sha = await gh_get_file()
    bans = parse_bans(raw)
    if any(b["userId"] == uid for b in bans):
        raise HTTPException(400, f"User {uid} is already banned")
    bans.append({"userId": uid, "message": message})
    new_raw = serialize_bans(bans)
    await gh_write_file(new_raw, sha, f"ban: AddUser {uid} via UT_UTI by {body.bannedBy}")
    await sync_json(bans, {
        uid: {"date": date, "bannedBy": body.bannedBy}
    }, None, f"ban: sync json AddUser {uid}")
    audit("ban.add", actor=body.bannedBy, target=uid, detail=f"[UT_UTI] {message}")
    return {
        "success":  True,
        "userId":   uid,
        "message":  message,
        "bannedBy": body.bannedBy,
        "date":     date,
        "total":    len(bans),
    }