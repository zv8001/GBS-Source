"""
GBSFrontendServer.py — Serves GBS.html on port 2949 and reverse-proxies
all /gbs/* API calls to the local backend.

Routes:
  GET  /                    — serves GBS.html
  GET  /gbs.css             — serves local stylesheet
  GET  /gbs.js              — serves local JavaScript
  GET  /BannedUsers.json    — reads user bans from the backend
  GET  /BannedGroups.json   — reads group bans from the backend
  ANY  /gbs/*               — reverse-proxies to GBS backend

Environment variables:
  GBS_BACKEND_URL      — backend base URL (default: http://127.0.0.1:8000)
  REGISTRY_API_KEY     — optional shared secret injected as X-GBS-Key on /gbs/* requests
"""

import os
import time
import httpx
import uvicorn

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

# ── Config ────────────────────────────────────────────────────────────────────
GBS_BACKEND_URL    = os.environ.get("GBS_BACKEND_URL", "http://127.0.0.1:8000")
GBS_API_KEY        = os.environ.get("REGISTRY_API_KEY", os.environ.get("GBS_API_KEY", ""))
CACHE_TTL_SECONDS  = 30
_HTML_PATH   = os.path.join(os.path.dirname(__file__), "GBS.html")
_RAW_PATH    = os.path.join(os.path.dirname(__file__), "GBS_Raw.html")
_CSS_PATH    = os.path.join(os.path.dirname(__file__), "gbs.css")
_JS_PATH     = os.path.join(os.path.dirname(__file__), "gbs.js")

# ── App ───────────────────────────────────────────────────────────────────────
FrontendApp = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

# ── In-memory JSON cache ──────────────────────────────────────────────────────
_cache: dict = {
    "users": {"data": None, "fetched_at": 0.0},
    "groups": {"data": None, "fetched_at": 0.0},
}

# ── HTML builder ──────────────────────────────────────────────────────────────
def _build_html() -> str:
    with open(_HTML_PATH, encoding="utf-8") as f:
        html = f.read()
    injection = '<script>window.__GBS_API_BASE__ = "/gbs";</script>'
    return html.replace("<body>", f"<body>\n{injection}", 1)

FrontendApp.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routes ────────────────────────────────────────────────────────────────────
@FrontendApp.get("/", response_class=HTMLResponse)
async def serve_index():
    return HTMLResponse(_build_html())


@FrontendApp.get("/gbs.css")
async def serve_css():
    return FileResponse(_CSS_PATH, media_type="text/css")


@FrontendApp.get("/gbs.js")
async def serve_js():
    return FileResponse(_JS_PATH, media_type="application/javascript")


@FrontendApp.get("/raw", response_class=HTMLResponse)
async def serve_raw():
    raw_path = _RAW_PATH if os.path.exists(_RAW_PATH) else _HTML_PATH
    with open(raw_path, encoding="utf-8") as f:
        return HTMLResponse(f.read())


@FrontendApp.get("/BannedUsers.json")
async def banned_users_proxy():
    """Proxies & caches the backend ban list as a plain JSON list."""
    return await _cached_backend_list("users", "/bans", "bans")


@FrontendApp.get("/BannedGroups.json")
async def banned_groups_proxy():
    """Proxies & caches the backend group ban list as a plain JSON list."""
    return await _cached_backend_list("groups", "/groups", "groups")


async def _cached_backend_list(cache_key: str, path: str, response_key: str):
    now = time.monotonic()
    cache = _cache[cache_key]
    if cache["data"] is not None and (now - cache["fetched_at"]) < CACHE_TTL_SECONDS:
        return JSONResponse(content=cache["data"])
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(f"{GBS_BACKEND_URL.rstrip('/')}{path}")
            resp.raise_for_status()
            data = resp.json().get(response_key, [])
    except Exception as exc:
        if cache["data"] is not None:
            print(f"[GBSFrontend] Upstream error ({exc}), serving stale cache")
            return JSONResponse(content=cache["data"])
        return JSONResponse(content={"detail": f"Upstream unavailable: {exc}"}, status_code=502)
    cache["data"]       = data
    cache["fetched_at"] = now
    print(f"[GBSFrontend] Synced {len(data) if isinstance(data, list) else '?'} {cache_key} records from backend")
    return JSONResponse(content=data)


@FrontendApp.api_route("/gbs/{path:path}", methods=["GET","POST","PUT","PATCH","DELETE","OPTIONS"])
async def gbs_proxy(path: str, request: Request):
    """
    Reverse-proxy all /gbs/* requests to the backend, injecting X-GBS-Key
    server-side so the browser never sees or needs to know the key.
    """
    target_url = f"{GBS_BACKEND_URL.rstrip('/')}/{path}"

    # Forward original query string
    if request.url.query:
        target_url += f"?{request.url.query}"

    # Copy headers, strip hop-by-hop, inject the API key
    headers = dict(request.headers)
    for hop in ("host", "content-length", "transfer-encoding", "connection"):
        headers.pop(hop, None)
    if GBS_API_KEY:
        headers["X-GBS-Key"] = GBS_API_KEY

    body = await request.body()

    async with httpx.AsyncClient(timeout=30.0) as client:
        upstream = await client.request(
            method  = request.method,
            url     = target_url,
            headers = headers,
            content = body,
        )

    # Stream response back to browser
    excluded = {"content-encoding", "content-length", "transfer-encoding", "connection"}
    resp_headers = {k: v for k, v in upstream.headers.items() if k.lower() not in excluded}
    return Response(
        content    = upstream.content,
        status_code= upstream.status_code,
        headers    = resp_headers,
        media_type = upstream.headers.get("content-type", "application/json"),
    )



# ── 404 catch-all ─────────────────────────────────────────────────────────────
_404_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>404 - Moderation Registry</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&family=JetBrains+Mono:wght@500;700&display=swap" rel="stylesheet">
  <style>
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    body{background:#f6f8fb;color:#1f2933;font-family:'Inter',sans-serif;
         min-height:100vh;display:flex;flex-direction:column;overflow-x:hidden}
    nav{display:flex;align-items:center;justify-content:space-between;padding:0 28px;
        height:64px;background:#fff;border-bottom:1px solid #d7e0e7;position:sticky;top:0;z-index:100;
        box-shadow:0 12px 30px rgba(31,41,51,.08)}
    .brand{display:flex;align-items:center;gap:10px}
    .mark{width:38px;height:38px;border-radius:8px;background:#0f8b8d;color:#fff;display:grid;place-items:center;
          font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:800}
    .brand-text{font-weight:800;font-size:15px;color:#1f2933}
    .brand-sub{font-size:11px;color:#607080;margin-top:1px}
    .main{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;
          padding:40px 20px;text-align:center}
    .code{font-size:112px;font-weight:800;color:#0f8b8d;line-height:1}
    .label{font-size:24px;font-weight:800;color:#1f2933;margin-top:8px}
    .sub{color:#607080;font-size:14px;margin-top:10px;max-width:420px;line-height:1.6}
    .back{display:inline-flex;align-items:center;gap:8px;margin-top:32px;
          padding:10px 24px;font-size:13px;font-weight:700;text-decoration:none;
          border:1px solid #c5d1da;border-radius:8px;color:#1f2933;background:#fff;
          transition:all .15s}
    .back:hover{border-color:#0f8b8d;color:#0f8b8d}
    footer{text-align:center;padding:16px;font-size:11px;color:#607080;
           border-top:1px solid #d7e0e7}
  </style>
</head>
<body>
  <nav>
    <div class="brand">
      <div class="mark">MR</div>
      <div>
        <div class="brand-text">Moderation Registry</div>
        <div class="brand-sub">Standalone Archive</div>
      </div>
    </div>
  </nav>
  <div class="main">
    <div class="code">404</div>
    <div class="label">Page Not Found</div>
    <p class="sub">The page you're looking for doesn't exist or has been moved.</p>
    <a href="/" class="back">Back to Registry</a>
  </div>
  <footer>Standalone moderation archive</footer>
</body>
</html>"""

@FrontendApp.api_route("/{path:path}", methods=["GET","HEAD"])
async def catch_all(path: str):
    return HTMLResponse(content=_404_HTML, status_code=404)


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print(f"[GBSFrontend] Serving on http://0.0.0.0:2949")
    print(f"[GBSFrontend] Backend proxy: /gbs/* -> {GBS_BACKEND_URL}/*")
    print(f"[GBSFrontend] JSON proxy:    /BannedUsers.json -> backend /bans")
    print(f"[GBSFrontend] API key set:   {'yes' if GBS_API_KEY else 'not required'}")
    uvicorn.run(FrontendApp, host="0.0.0.0", port=2949, log_level="info")
