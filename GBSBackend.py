import asyncio
import os
import re
import json
import httpx
import secrets
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest
from starlette.responses import Response as StarletteResponse
from pydantic import BaseModel
from jose import JWTError, jwt
from passlib.context import CryptContext
from pathlib import Path
from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).parent.resolve()
load_dotenv(SCRIPT_DIR / ".env")

SECRET_KEY_FILE = SCRIPT_DIR / ".gbs_secret"

def _load_secret_key() -> str:
    env_secret = os.environ.get("GBS_SECRET_KEY")
    if env_secret:
        return env_secret
    if SECRET_KEY_FILE.exists():
        return SECRET_KEY_FILE.read_text(encoding="utf-8").strip()
    secret = secrets.token_urlsafe(48)
    SECRET_KEY_FILE.write_text(secret, encoding="utf-8")
    return secret

SECRET_KEY        = _load_secret_key()
ALGORITHM         = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 30
SESSION_COOKIE_NAME = os.environ.get("GBS_SESSION_COOKIE", "gbs_session")

# ── Owner account — cannot be demoted, deleted, or reset by other admins ─────
OWNER_EMAIL = os.environ.get("GBS_OWNER_EMAIL", "denverv1000@gmail.com")

App = FastAPI(title="Moderation Registry API", docs_url=None, redoc_url=None, openapi_url=None)

App.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:2949",
        "http://localhost:2949",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

GBS_API_KEY    = os.environ.get("REGISTRY_API_KEY", os.environ.get("GBS_API_KEY", ""))
DIRECT_BAN_API_KEY = os.environ.get("DIRECT_BAN_API_KEY", "")

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
}

class APIKeyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: StarletteRequest, call_next):
        if request.method == "OPTIONS":
            return await call_next(request)
        path = request.url.path
        if request.method == "GET" and (
            path in PUBLIC_READONLY_PATHS
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

LOG_FILE = SCRIPT_DIR / "audit_log.json"

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
    tmp = LOG_FILE.with_suffix(".tmp")
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

def _cookie_secure(request: Request) -> bool:
    setting = os.environ.get("GBS_COOKIE_SECURE", "auto").lower()
    if setting in ("1", "true", "yes", "on"):
        return True
    if setting in ("0", "false", "no", "off"):
        return False
    return request.url.scheme == "https"

def set_session_cookie(response: Response, request: Request, raw_token: str):
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=raw_token,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        httponly=True,
        secure=_cookie_secure(request),
        samesite="lax",
        path="/",
    )

def clear_session_cookie(response: Response, request: Request):
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        httponly=True,
        secure=_cookie_secure(request),
        samesite="lax",
        path="/",
    )

async def get_current_user(request: Request):
    cred_exc = HTTPException(status_code=401, detail="Invalid credentials")
    token = request.cookies.get(SESSION_COOKIE_NAME)
    auth_header = request.headers.get("Authorization", "")
    if not token and auth_header.lower().startswith("bearer "):
        token = auth_header.split(" ", 1)[1].strip()
    if not token:
        raise cred_exc
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

LOCAL_DATA_DIR        = SCRIPT_DIR / "data"
LOCAL_BANS_JSON_FILE  = LOCAL_DATA_DIR / "BannedUsersAPI.json"
LOCAL_GROUPS_FILE     = LOCAL_DATA_DIR / "BannedGroups.json"

def _ensure_local_data():
    LOCAL_DATA_DIR.mkdir(exist_ok=True)
    if not LOCAL_BANS_JSON_FILE.exists():
        LOCAL_BANS_JSON_FILE.write_text("[]", encoding="utf-8")
    if not LOCAL_GROUPS_FILE.exists():
        LOCAL_GROUPS_FILE.write_text("[]", encoding="utf-8")

def _load_local_json(path: Path) -> list[dict]:
    _ensure_local_data()
    try:
        data = json.loads(path.read_text(encoding="utf-8") or "[]")
        return data if isinstance(data, list) else []
    except json.JSONDecodeError:
        return []

def _save_local_json(path: Path, records: list[dict]):
    _ensure_local_data()
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(records, indent=2), encoding="utf-8")
    os.replace(tmp, path)

async def local_get_bans():
    return _load_local_json(LOCAL_BANS_JSON_FILE), None

_local_write_lock = asyncio.Lock()

async def local_write_bans(records: list[dict], commit_msg: str):
    async with _local_write_lock:
        _save_local_json(LOCAL_BANS_JSON_FILE, records)
        return {"message": commit_msg, "storage": "local"}

def sanitize_user_id(uid: str) -> str:
    """User IDs must be numeric only — reject anything else."""
    uid = uid.strip()
    if not uid.isdigit():
        raise HTTPException(400, f"Invalid user ID: {uid!r} — must be numeric")
    return uid

class RegisterBody(BaseModel):
    email: str
    password: str
    username: str

@App.post("/auth/register")
async def register(body: RegisterBody):
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
    users[body.email] = {
        "email":                      body.email,
        "username":                   body.username,
        "hashed_password":            pwd_context.hash(body.password),
        "status":                     "approved" if is_first else "pending",
        "is_admin":                   is_first,
        "created_at":                 datetime.utcnow().isoformat(),
    }
    save_users(users)
    audit("auth.register", actor=body.username, target=body.email,
          detail="auto-approved as first user" if is_first else "pending approval")
    msg = "Account created. You are the first user — admin granted." if is_first else "Account created. Await admin approval."
    return {"message": msg, "status": "approved" if is_first else "pending"}

@App.post("/auth/login")
async def login(response: Response, request: Request, form: OAuth2PasswordRequestForm = Depends()):
    check_login_rate_limit(request)
    users = load_users()
    user  = users.get(form.username)
    if not user or not pwd_context.verify(form.password, user["hashed_password"]):
        raise HTTPException(401, "Incorrect email or password")
    if user["status"] == "pending":
        raise HTTPException(403, "Account pending approval")
    if user["status"] == "rejected":
        raise HTTPException(403, "Account rejected")
    ip = request.client.host if request.client else "unknown"
    _login_attempts[ip] = []
    token = create_access_token({"sub": form.username}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    set_session_cookie(response, request, token)
    audit("auth.login", actor=user["username"], target=form.username)
    return {"message": "Logged in", "username": user["username"], "is_admin": user["is_admin"]}

@App.get("/auth/me")
async def me(user=Depends(require_approved)):
    return {"email": user["email"], "username": user["username"],
            "is_admin": user["is_admin"], "status": user["status"]}

@App.post("/auth/logout")
async def logout(response: Response, request: Request, user=Depends(get_current_user)):
    raw_token = user.get("_raw_token")
    if raw_token:
        try:
            payload = jwt.decode(raw_token, SECRET_KEY, algorithms=[ALGORITHM])
            exp = datetime.utcfromtimestamp(payload["exp"]).isoformat()
        except Exception:
            exp = (datetime.utcnow() + timedelta(days=30)).isoformat()
        revoke_token(raw_token, exp)
        audit("auth.logout", actor=user["username"], target=user["email"])
    clear_session_cookie(response, request)
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
    bans, _ = await local_get_bans()
    return {"count": len(bans), "ids": [b.get("userId") for b in bans], "preview": bans[:5]}

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
    return {"status": "ok", "service": "Moderation Registry API"}

@App.get("/bans")
async def get_bans():
    bans, _ = await local_get_bans()
    return {"bans": bans, "total": len(bans)}

class BanBody(BaseModel):
    userId: str
    message: str

@App.post("/bans")
async def add_ban(body: BanBody, user=Depends(require_approved)):
    bans, _ = await local_get_bans()
    if any(b["userId"] == body.userId for b in bans):
        raise HTTPException(400, "User already banned")
    bans.append({
        "userId": body.userId,
        "message": body.message,
        "date": datetime.utcnow().strftime("%Y-%m-%d"),
        "bannedBy": user["username"],
    })
    await local_write_bans(bans, f"ban: add {body.userId} by {user['username']}")
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
    bans, _ = await local_get_bans()
    existing_ids = {b["userId"] for b in bans}
    added, skipped = [], []
    today = datetime.utcnow().strftime("%Y-%m-%d")
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
            bans.append({
                "userId": uid,
                "message": body.message,
                "date": today,
                "bannedBy": user["username"],
            })
            existing_ids.add(uid)
            added.append(uid)
    if not added:
        return {"message": "All users already banned", "added": [], "skipped": skipped}
    await local_write_bans(bans, f"ban: bulk add {len(added)} users by {user['username']}")
    for uid in added:
        audit("ban.add", actor=user["username"], target=uid, detail=body.message)
    return {"message": f"Banned {len(added)} users", "added": added, "skipped": skipped, "total": len(bans)}

@App.patch("/bans/{user_id}")
async def edit_ban(user_id: str, body: EditBanBody, user=Depends(require_approved)):
    bans, _ = await local_get_bans()
    target = next((b for b in bans if b["userId"] == user_id), None)
    if not target:
        raise HTTPException(404, "User not in ban list")
    old_msg = target["message"]
    target["message"] = body.message
    target["modifiedBy"] = user["username"]
    target["modifiedDate"] = datetime.utcnow().strftime("%Y-%m-%d")
    await local_write_bans(bans, f"ban: edit reason for {user_id} by {user['username']}")
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
    bans, _ = await local_get_bans()
    updated = []
    today = datetime.utcnow().strftime("%Y-%m-%d")
    for b in bans:
        if b["userId"] in target_ids:
            old_msg = b["message"]
            b["message"] = body.message
            b["modifiedBy"] = user["username"]
            b["modifiedDate"] = today
            updated.append(b["userId"])
            audit("ban.edit", actor=user["username"], target=b["userId"],
                  detail=f"bulk edit | old: {old_msg} | new: {body.message}")
    if not updated:
        raise HTTPException(404, "None of the specified users are in the ban list")
    await local_write_bans(bans, f"ban: bulk edit {len(updated)} reasons by {user['username']}")
    return {"message": f"Updated {len(updated)} ban reasons", "updated": len(updated)}

class BulkRemoveBody(BaseModel):
    userIds: list[str]

@App.post("/bans/bulk-remove")
async def remove_ban_bulk(body: BulkRemoveBody, user=Depends(require_approved)):
    if not body.userIds:
        raise HTTPException(400, "No user IDs provided")
    target_ids = {uid.strip() for uid in body.userIds if uid.strip()}
    bans, _ = await local_get_bans()
    new_bans = [b for b in bans if b["userId"] not in target_ids]
    removed  = [b["userId"] for b in bans if b["userId"] in target_ids]
    if not removed:
        raise HTTPException(404, "None of the specified users are in the ban list")
    await local_write_bans(new_bans, f"ban: bulk remove {len(removed)} users by {user['username']}")
    for uid in removed:
        audit("ban.remove", actor=user["username"], target=uid, detail="bulk unban")
    return {"message": f"Unbanned {len(removed)} users", "removed": len(removed), "skipped": len(target_ids) - len(removed)}

@App.delete("/bans/{user_id}")
async def remove_ban(user_id: str, user=Depends(require_approved)):
    bans, _ = await local_get_bans()
    new_bans = [b for b in bans if b["userId"] != user_id]
    if len(new_bans) == len(bans):
        raise HTTPException(404, "User not in ban list")
    await local_write_bans(new_bans, f"ban: remove {user_id} by {user['username']}")
    audit("ban.remove", actor=user["username"], target=user_id)
    return {"message": "User unbanned", "total": len(new_bans)}

@App.get("/bans/stats")
async def ban_stats():
    json_records, _ = await local_get_bans()
    total      = len(json_records)
    exploiters = sum(1 for b in json_records if "exploit" in b.get("message", "").lower())
    stolen     = sum(1 for b in json_records if any(k in b.get("message", "").lower() for k in ("stolen", "stealer", "assets")))
    bypass     = sum(1 for b in json_records if "bypass" in b.get("message", "").lower())
    bots       = sum(1 for b in json_records if "bot" in b.get("message", "").lower() or "spam" in b.get("message", "").lower())
    return {"total": total, "exploiters": exploiters, "stolen": stolen, "bypass": bypass, "bots": bots}

async def local_get_groups() -> list[dict]:
    return _load_local_json(LOCAL_GROUPS_FILE)

async def local_write_groups(records: list[dict], commit_msg: str):
    _save_local_json(LOCAL_GROUPS_FILE, records)
    return {"message": commit_msg, "storage": "local"}

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
    groups = await local_get_groups()
    return {"groups": groups, "total": len(groups)}

@App.get("/groups/stats")
async def group_stats():
    groups = await local_get_groups()
    total      = len(groups)
    exploiters = sum(1 for b in groups if "exploit" in b.get("message", "").lower())
    stolen     = sum(1 for b in groups if any(k in b.get("message", "").lower() for k in ("stolen", "stealer", "assets")))
    bypass     = sum(1 for b in groups if "bypass" in b.get("message", "").lower())
    bots       = sum(1 for b in groups if "bot" in b.get("message", "").lower() or "spam" in b.get("message", "").lower())
    return {"total": total, "exploiters": exploiters, "stolen": stolen, "bypass": bypass, "bots": bots}

@App.post("/groups")
async def add_group_ban(body: GroupBanBody, user=Depends(require_approved)):
    groups = await local_get_groups()
    if any(g["groupId"] == body.groupId for g in groups):
        raise HTTPException(400, "Group already banned")
    groups.append({
        "groupId":  body.groupId,
        "message":  body.message,
        "date":     datetime.utcnow().strftime("%Y-%m-%d"),
        "bannedBy": user["username"],
    })
    await local_write_groups(groups, f"group-ban: add {body.groupId} by {user['username']}")
    audit("group.ban.add", actor=user["username"], target=body.groupId, detail=body.message)
    return {"message": "Group banned", "total": len(groups)}

@App.post("/groups/bulk")
async def add_group_ban_bulk(body: GroupBulkBanBody, user=Depends(require_approved)):
    if not body.groupIds:
        raise HTTPException(400, "No group IDs provided")
    groups = await local_get_groups()
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
    await local_write_groups(groups, f"group-ban: bulk add {len(added)} by {user['username']}")
    for gid in added:
        audit("group.ban.add", actor=user["username"], target=gid, detail=body.message)
    return {"message": f"Banned {len(added)} groups", "added": added, "skipped": skipped, "total": len(groups)}

@App.patch("/groups/{group_id}")
async def edit_group_ban(group_id: str, body: GroupEditBody, user=Depends(require_approved)):
    groups = await local_get_groups()
    target = next((g for g in groups if g["groupId"] == group_id), None)
    if not target:
        raise HTTPException(404, "Group not in ban list")
    old_msg = target["message"]
    target["message"] = body.message
    await local_write_groups(groups, f"group-ban: edit {group_id} by {user['username']}")
    audit("group.ban.edit", actor=user["username"], target=group_id, detail=f"old: {old_msg} | new: {body.message}")
    return {"message": "Group ban reason updated"}

@App.post("/groups/bulk-edit")
async def edit_group_ban_bulk(body: GroupBulkEditBody, user=Depends(require_approved)):
    if not body.groupIds:
        raise HTTPException(400, "No group IDs provided")
    target_ids = {gid.strip() for gid in body.groupIds if gid.strip()}
    groups = await local_get_groups()
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
    await local_write_groups(groups, f"group-ban: bulk edit {len(updated)} by {user['username']}")
    return {"message": f"Updated {len(updated)} group ban reasons", "updated": len(updated)}

@App.delete("/groups/{group_id}")
async def remove_group_ban(group_id: str, user=Depends(require_approved)):
    groups = await local_get_groups()
    new_groups = [g for g in groups if g["groupId"] != group_id]
    if len(new_groups) == len(groups):
        raise HTTPException(404, "Group not in ban list")
    await local_write_groups(new_groups, f"group-ban: remove {group_id} by {user['username']}")
    audit("group.ban.remove", actor=user["username"], target=group_id)
    return {"message": "Group unbanned", "total": len(new_groups)}

@App.post("/groups/bulk-remove")
async def remove_group_ban_bulk(body: GroupBulkRemoveBody, user=Depends(require_approved)):
    if not body.groupIds:
        raise HTTPException(400, "No group IDs provided")
    target_ids = {gid.strip() for gid in body.groupIds if gid.strip()}
    groups = await local_get_groups()
    new_groups = [g for g in groups if g["groupId"] not in target_ids]
    removed    = [g["groupId"] for g in groups if g["groupId"] in target_ids]
    if not removed:
        raise HTTPException(404, "None of the specified groups are in the ban list")
    await local_write_groups(new_groups, f"group-ban: bulk remove {len(removed)} by {user['username']}")
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
    if not DIRECT_BAN_API_KEY:
        raise HTTPException(503, "Direct ban API is not configured on this server")
    if request.headers.get("X-API-Key") != DIRECT_BAN_API_KEY:
        raise HTTPException(403, "Invalid API key")
    uid  = sanitize_user_id(body.userId)
    today   = datetime.utcnow().strftime("%Y-%m-%d")
    date    = body.date or today
    message = f"[{body.category}] {body.message}"
    bans, _ = await local_get_bans()
    if any(b["userId"] == uid for b in bans):
        raise HTTPException(400, f"User {uid} is already banned")
    bans.append({
        "userId": uid,
        "message": message,
        "date": date,
        "bannedBy": body.bannedBy,
    })
    await local_write_bans(bans, f"ban: AddUser {uid} via direct API by {body.bannedBy}")
    audit("ban.add", actor=body.bannedBy, target=uid, detail=f"[direct-api] {message}")
    return {
        "success":  True,
        "userId":   uid,
        "message":  message,
        "bannedBy": body.bannedBy,
        "date":     date,
        "total":    len(bans),
    }

