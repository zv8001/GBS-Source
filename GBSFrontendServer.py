"""
GBSFrontendServer.py — Serves index.html on port 2949, proxies the
ban list JSON from Netlify, and reverse-proxies all /gbs/* API calls
to the backend with the X-GBS-Key header injected server-side.

Routes:
  GET  /                    — serves GBS.html (Turnstile key injected)
  GET  /BannedUsers.json    — proxies BannedUsersAPI.json from Netlify (cached)
  ANY  /gbs/*               — reverse-proxies to GBS backend with API key

Environment variables:
  TURNSTILE_SITE_KEY   — Cloudflare Turnstile site key (injected into HTML)
  GBS_BACKEND_URL      — backend base URL (default: https://api.unknown-technologies.us)
  GBS_API_KEY          — shared secret injected as X-GBS-Key on every /gbs/* request
"""

import os
import time
import httpx
import uvicorn

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware

# ── Config ────────────────────────────────────────────────────────────────────
TURNSTILE_SITE_KEY = os.environ.get("TURNSTILE_SITE_KEY", "")
GBS_BACKEND_URL    = os.environ.get("GBS_BACKEND_URL", "https://api.unknown-technologies.us")
GBS_API_KEY        = os.environ.get("GBS_API_KEY", "")
UPSTREAM_JSON_URL  = "https://database.unknown-technologies.us/api/BannedUsersAPI.json"
CACHE_TTL_SECONDS  = 30
_HTML_PATH   = os.path.join(os.path.dirname(__file__), "GBS.html")
_RAW_PATH    = os.path.join(os.path.dirname(__file__), "GBS_Raw.html")
_CSS_PATH    = os.path.join(os.path.dirname(__file__), "gbs.css")
_JS_PATH     = os.path.join(os.path.dirname(__file__), "gbs.js")

# ── App ───────────────────────────────────────────────────────────────────────
FrontendApp = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

# ── In-memory JSON cache ──────────────────────────────────────────────────────
_cache: dict = {"data": None, "fetched_at": 0.0}

# ── HTML builder ──────────────────────────────────────────────────────────────
def _build_html() -> str:
    with open(_HTML_PATH, encoding="utf-8") as f:
        html = f.read()
    site_key  = os.environ.get("TURNSTILE_SITE_KEY", "")
    print(f"[GBSFrontend] Site key: '{site_key}'")
    print(f"[GBSFrontend] <body> found: {'<body>' in html}")
    injection = f'<script>window.__GBS_SITE_KEY__ = "{site_key}";</script>'
    return html.replace("<body>", f"<body>\n{injection}", 1)

FrontendApp.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)

# ── Routes ────────────────────────────────────────────────────────────────────
@FrontendApp.get("/", response_class=HTMLResponse)
async def serve_index():
    return HTMLResponse(_build_html())


@FrontendApp.get("/raw", response_class=HTMLResponse)
async def serve_raw():
    with open(_RAW_PATH, encoding="utf-8") as f:
        return HTMLResponse(f.read())


@FrontendApp.get("/verify/{token}")
async def verify_redirect(token: str):
    """Forward email verification clicks to the backend then redirect home."""
    target = f"{GBS_BACKEND_URL.rstrip('/')}/gbs/auth/verify/{token}"
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
        r = await client.get(target)
    # Backend returns a RedirectResponse — forward it
    location = r.headers.get("location", "/")
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url=location, status_code=302)


@FrontendApp.get("/BannedUsers.json")
async def banned_users_proxy():
    """Proxies & caches BannedUsersAPI.json from Netlify."""
    now = time.monotonic()
    if _cache["data"] is not None and (now - _cache["fetched_at"]) < CACHE_TTL_SECONDS:
        return JSONResponse(content=_cache["data"])
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(UPSTREAM_JSON_URL)
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        if _cache["data"] is not None:
            print(f"[GBSFrontend] Upstream error ({exc}), serving stale cache")
            return JSONResponse(content=_cache["data"])
        return JSONResponse(content={"detail": f"Upstream unavailable: {exc}"}, status_code=502)
    _cache["data"]       = data
    _cache["fetched_at"] = now
    print(f"[GBSFrontend] Synced {len(data) if isinstance(data, list) else '?'} records from upstream")
    return JSONResponse(content=data)


@FrontendApp.api_route("/gbs/{path:path}", methods=["GET","POST","PUT","PATCH","DELETE","OPTIONS"])
async def gbs_proxy(path: str, request: Request):
    """
    Reverse-proxy all /gbs/* requests to the backend, injecting X-GBS-Key
    server-side so the browser never sees or needs to know the key.
    """
    target_url = f"{GBS_BACKEND_URL.rstrip('/')}/gbs/{path}"

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
  <title>404 — BAN REGISTRY</title>
  <link rel="icon" type="image/x-icon" href="https://unknown-technologies.us/Img/GBS/fav_icon.ico">
  <link href="https://fonts.googleapis.com/css2?family=Rajdhani:wght@400;600;700&family=Share+Tech+Mono&family=Barlow+Condensed:wght@400;600;700&display=swap" rel="stylesheet">
  <style>
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    body{background:#0c0c0e;color:#d0d4dc;font-family:'Barlow Condensed',sans-serif;
         min-height:100vh;display:flex;flex-direction:column;overflow-x:hidden}
    body::after{content:'';pointer-events:none;position:fixed;inset:0;
      background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='1'/%3E%3C/svg%3E");
      opacity:.028;z-index:9999}
    nav{display:flex;align-items:center;justify-content:space-between;padding:0 28px;
        height:48px;background:#0e0e12;border-bottom:1px solid #222228;position:sticky;top:0;z-index:100}
    .brand{display:flex;align-items:center;gap:10px}
    .brand img{width:36px;height:36px;object-fit:contain}
    .brand-text{font-family:'Rajdhani',sans-serif;font-weight:700;font-size:16px;
                letter-spacing:2px;text-transform:uppercase;color:#fff}
    .brand-sub{font-size:10px;color:#5a6070;letter-spacing:1px;text-transform:uppercase;margin-top:1px}
    .main{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;
          padding:40px 20px;text-align:center;
          background:radial-gradient(ellipse 70% 60% at 50% 40%,rgba(224,48,48,.06) 0%,transparent 70%)}
    .code{font-family:'Rajdhani',sans-serif;font-size:120px;font-weight:700;
          color:#e03030;line-height:1;letter-spacing:4px;
          text-shadow:0 0 80px rgba(224,48,48,.3)}
    .label{font-family:'Rajdhani',sans-serif;font-size:22px;font-weight:600;
           letter-spacing:3px;text-transform:uppercase;color:#fff;margin-top:8px}
    .sub{color:#5a6070;font-size:14px;margin-top:10px;max-width:420px;line-height:1.6}
    .back{display:inline-flex;align-items:center;gap:8px;margin-top:32px;
          padding:10px 24px;font-family:'Barlow Condensed',sans-serif;font-size:13px;
          font-weight:700;letter-spacing:1px;text-transform:uppercase;text-decoration:none;
          border:1px solid #2a2a32;border-radius:3px;color:#d0d4dc;background:#111115;
          transition:all .15s}
    .back:hover{border-color:#e03030;color:#e03030}
    footer{text-align:center;padding:16px;font-size:11px;color:#3a3f4a;
           border-top:1px solid #222228;letter-spacing:.5px}
  </style>
</head>
<body>
  <nav>
    <div class="brand">
      <img src="https://unknown-technologies.us/Img/GBS/fav_icon.png" alt="GBS"/>
      <div>
        <div class="brand-text">Ban Registry</div>
        <div class="brand-sub">Unknown Technologies+</div>
      </div>
    </div>
  </nav>
  <div class="main">
    <div class="code">404</div>
    <div class="label">Page Not Found</div>
    <p class="sub">The page you're looking for doesn't exist or has been moved.</p>
    <a href="/" class="back">← Back to Ban Registry</a>
  </div>
  <footer>Managed by Unknown Technologies+</footer>
</body>
</html>"""

@FrontendApp.api_route("/{path:path}", methods=["GET","HEAD"])
async def catch_all(path: str):
    return HTMLResponse(content=_404_HTML, status_code=404)


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print(f"[GBSFrontend] Serving on http://0.0.0.0:2949")
    print(f"[GBSFrontend] Backend proxy: /gbs/* -> {GBS_BACKEND_URL}/gbs/*")
    print(f"[GBSFrontend] JSON proxy:    /BannedUsers.json -> {UPSTREAM_JSON_URL}")
    print(f"[GBSFrontend] API key set:   {'yes' if GBS_API_KEY else 'NO — set GBS_API_KEY'}")
    uvicorn.run(FrontendApp, host="0.0.0.0", port=2949, log_level="info")