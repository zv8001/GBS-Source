# Moderation Registry Standalone

This version runs locally with a FastAPI backend and a small frontend server. It does not require Cloudflare Turnstile, email login codes, Netlify, or GitHub storage.

## Run On Windows

```bat
start-windows.bat
```

Then open:

```text
http://127.0.0.1:2949
```

## Run On macOS

```sh
chmod +x start-macos.sh
./start-macos.sh
```

Then open:

```text
http://127.0.0.1:2949
```

## First Account

Register the first account from the web UI. The first account is approved automatically and made an admin. Later accounts still need admin approval.

## Environment File

Edit `.env` to change local settings. `.env.example` is the safe template to keep on GitHub.

## Sessions

Login sessions are stored in an HttpOnly SameSite cookie named `gbs_session`, not in `localStorage`. The cookie uses the `Secure` flag automatically when the app is served over HTTPS. For local `http://127.0.0.1` use, it stays HTTP-compatible so browser login works.

To force secure cookies, set:

```sh
GBS_COOKIE_SECURE=true
```

Only do that when serving the frontend over HTTPS.

## Local Data

Data is saved locally in:

```text
data/BannedUsersAPI.json
data/BannedGroups.json
users.json
audit_log.json
```

Those files are created automatically when needed.

You can also override:

```sh
REGISTRY_API_KEY=...
DIRECT_BAN_API_KEY=...
SITE_URL=http://127.0.0.1:2949
```

For the simplest setup, leave those unset.
