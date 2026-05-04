# manyrows

Official Python SDK for [ManyRows](https://manyrows.com). Mirrors the surface of [`manyrows-go`](https://github.com/manyrows/manyrows-go) and [`@manyrows/manyrows-node`](https://www.npmjs.com/package/@manyrows/manyrows-node).

## Install

```bash
pip install manyrows
```

Requires **Python 3.9+**. Sync and async clients are both included; both use [`httpx`](https://www.python-httpx.org/) under the hood.

## Client

The client wraps the ManyRows Server API. Requires an API key.

```python
from manyrows import Client

client = Client(
    base_url="https://app.manyrows.com",
    workspace_slug="your-workspace",
    app_id="your-app-id",
    api_key="mr_a1b2c3d4_yourSecretKey",
)
```

For async code:

```python
from manyrows import AsyncClient

async with AsyncClient(
    base_url="https://app.manyrows.com",
    workspace_slug="your-workspace",
    app_id="your-app-id",
    api_key="mr_...",
) as client:
    user = await client.get_user("u_123")
```

### Delivery (config + feature flags)

```python
delivery = client.get_delivery()
# delivery.config.public, delivery.config.private, delivery.config.secrets
# delivery.flags.client, delivery.flags.server
```

### Check permission

```python
allowed = client.has_permission(user_id, "posts:edit")

# Or get the full result:
result = client.check_permission(user_id, "posts:edit")
# result.allowed, result.permission, result.account_id
```

### User lookup

```python
# By ID
user = client.get_user(user_id)
# user.user.email, user.roles, user.permissions, user.fields

# By email
user = client.get_user_by_email("user@example.com")
```

### Members

```python
result = client.list_members(page=0, page_size=50)
# result.members, result.total, result.page, result.page_size

# Filter by email substring:
result = client.list_members(page=0, page_size=50, email="alice")

# Or the convenience alias:
result = client.list_members_by_email("alice")
```

### User fields

```python
fields = client.list_user_fields()
# fields[0].key, fields[0].value_type, fields[0].label
```

### Error handling

Non-2xx responses raise `ManyRowsError`:

```python
from manyrows import ManyRowsError

try:
    client.get_user("bogus")
except ManyRowsError as err:
    print(err.status, err.body)
```

## Auth helpers

Validate bearer tokens from your end users by calling the ManyRows `/a/me` endpoint, then read the user ID.

### `verify_token`

Returns the user ID on success, `None` if rejected, raises `httpx.HTTPStatusError` on network/server errors:

```python
from manyrows import bearer_token, verify_token

token = bearer_token(request.headers.get("Authorization"))
if not token:
    return Response("Unauthorized", status=401)

try:
    user_id = verify_token(
        token,
        base_url="https://app.manyrows.com",
        workspace_slug="your-workspace",
        app_id="your-app-id",
    )
except Exception:
    return Response("Unauthorized", status=401)  # fail closed on network errors

if user_id is None:
    return Response("Unauthorized", status=401)
```

### Async — `verify_token_async`

```python
from manyrows import verify_token_async

user_id = await verify_token_async(
    token,
    base_url="https://app.manyrows.com",
    workspace_slug="your-workspace",
    app_id="your-app-id",
)
```

### FastAPI

```python
from typing import Annotated
from fastapi import Depends, FastAPI, Header, HTTPException

from manyrows import bearer_token, verify_token_async

app = FastAPI()

async def manyrows_user_id(authorization: Annotated[str | None, Header()] = None) -> str:
    token = bearer_token(authorization)
    if not token:
        raise HTTPException(401)
    try:
        user_id = await verify_token_async(
            token,
            base_url="https://app.manyrows.com",
            workspace_slug="your-workspace",
            app_id="your-app-id",
        )
    except Exception as exc:
        raise HTTPException(401) from exc
    if user_id is None:
        raise HTTPException(401)
    return user_id

@app.get("/api/profile")
async def profile(user_id: Annotated[str, Depends(manyrows_user_id)]):
    return {"user_id": user_id}
```

### Flask

```python
from functools import wraps
from flask import Flask, request, abort, g

from manyrows import bearer_token, verify_token

app = Flask(__name__)

def manyrows_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = bearer_token(request.headers.get("Authorization"))
        if not token:
            abort(401)
        try:
            user_id = verify_token(
                token,
                base_url="https://app.manyrows.com",
                workspace_slug="your-workspace",
                app_id="your-app-id",
            )
        except Exception:
            abort(401)
        if user_id is None:
            abort(401)
        g.manyrows_user_id = user_id
        return f(*args, **kwargs)
    return wrapper

@app.route("/api/profile")
@manyrows_auth
def profile():
    return {"user_id": g.manyrows_user_id}
```

## Tier 1 vs full-BFF

The `verify_token` / `verify_token_async` helpers above are for **Tier 1**:
AppKit holds an access token in the browser and your backend validates it
on every authed request. Use that when your app is a SPA with no backend
session of its own.

For **full-BFF** (recommended for production): the browser holds only an
HttpOnly session cookie set by your backend; AppKit hits relative paths
on your server, and your handlers forward to ManyRows via `BffClient`
(auth + data calls) and `PublicProxy` (unauthed bootstrap + pre-login
surface). There is no auth middleware for BFF mode — the cookie + proxy
pattern replaces it: read the session ID from your own cookie in each
handler, pass it to `bff.proxy*`, propagate the upstream status to the
browser. A 401 from the proxy means the session expired; clear your
cookie and respond 401 yourself.

## BFF Client (full-BFF mode)

`BffClient` calls the ManyRows `/bff/*` server-to-server endpoints. AppKit
in the browser hits relative paths on your server (`/auth/login`,
`/auth/google`, `/auth/verify`, `/auth/totp/verify`,
`/auth/passkey/login/{begin,finish}`, `/auth/oauth/callback`,
`/auth/logout`, `/auth/forgot-password`, `/auth/reset-password`,
`/apps/{appId}/a/*` for authed data calls), and your handlers forward
each to ManyRows via `BffClient`.

Always pass the real browser IP and User-Agent (`ClientContext`) so per-IP
rate limits and audit logs in ManyRows attribute to the actual user.

```python
from manyrows import BffClient, ClientContext

bff = BffClient(
    base_url="https://app.manyrows.com",
    client_id=os.environ["MANYROWS_BFF_CLIENT_ID"],
    client_secret=os.environ["MANYROWS_BFF_CLIENT_SECRET"],
)

# /auth/login handler (FastAPI shown; Flask / Django / Starlette identical pattern):
ctx = ClientContext(
    client_ip=request.client.host,
    client_user_agent=request.headers.get("user-agent"),
)
s = bff.login_password(body.email, body.password, body.remember_me, ctx)

if s.totp_required:
    return {"totpRequired": True, "challengeToken": s.challenge_token}

request.session["manyrows_session_id"] = s.session_id  # your own cookie
return {"ok": True}
```

### Forwarding authed AppKit data calls

```python
# /apps/{app_id}/a/* handler:
r = bff.proxy_get(
    request.session["manyrows_session_id"],
    "/me",
    ClientContext(
        client_ip=request.client.host,
        client_user_agent=request.headers.get("user-agent"),
    ),
)
return Response(content=r.body, status_code=r.status, media_type=r.content_type)
```

`bff.proxy_post(session_id, path, body, ctx)` for POSTs;
`bff.proxy(method, session_id, path, body, ctx)` for any verb.

### Other login flows

```python
# Google ID token from GSI:
s = bff.login_google(id_token, remember_me, ctx)

# Email-OTP verify (registration when app_id is non-None):
s = bff.verify_otp(email, code, app_id, remember_me, ctx)
if s.password_already_set:
    # Existing user re-verifying — skip the "set your password" screen.
    pass

# Passkey:
begin = bff.passkey_login_begin(ctx)  # pass straight to the browser
s = bff.passkey_login_finish(challenge_id, response, remember_me, ctx)

# Apple/Microsoft/GitHub OAuth callback (after ManyRows redirects to your
# /auth/oauth/callback?code=...). See `OAuthCallbackHtml` below for the
# popup-aware response page AppKit expects.
s = bff.exchange_auth_code(code, redirect_uri, ctx)

# Logout:
bff.logout(session_id, ctx)
del request.session["manyrows_session_id"]
```

### Async

`AsyncBffClient` and `AsyncPublicProxy` are drop-in async equivalents
for FastAPI / Starlette / Django async views — same surface,
``await``-flavoured. Use these from inside ``async def`` handlers; the
sync versions block the event loop.

```python
from manyrows import AsyncBffClient, ClientContext

# Module-level — reused across requests; httpx.AsyncClient pools connections.
bff = AsyncBffClient(
    base_url="https://app.manyrows.com",
    client_id=os.environ["MANYROWS_BFF_CLIENT_ID"],
    client_secret=os.environ["MANYROWS_BFF_CLIENT_SECRET"],
)

@app.post("/auth/login")
async def login(body: LoginBody, request: Request):
    ctx = ClientContext(
        client_ip=request.client.host,
        client_user_agent=request.headers.get("user-agent"),
    )
    s = await bff.login_password(body.email, body.password, body.remember_me, ctx)
    if s.totp_required:
        return {"totpRequired": True, "challengeToken": s.challenge_token}
    request.session["manyrows_session_id"] = s.session_id
    return {"ok": True}
```

## Popup-aware OAuth callback HTML

AppKit's bffMode opens Apple/Microsoft/GitHub sign-in in a popup. After
ManyRows redirects the popup to your `/auth/oauth/callback?code=...`,
your handler must serve a specific HTML page that postMessages the
opener (or, when there's no opener, redirects the current tab):

```python
from manyrows import OAuthCallbackHtml, BffError

# /auth/oauth/callback handler:
code = request.query_params.get("code")
error = request.query_params.get("error")

if error:
    html = OAuthCallbackHtml.error(error, "/login?failed=1")
else:
    try:
        s = bff.exchange_auth_code(code, redirect_uri, ctx)
        if s.totp_required:
            html = OAuthCallbackHtml.totp(s.challenge_token, "/login/totp", "/login?failed=1")
        else:
            request.session["manyrows_session_id"] = s.session_id
            html = OAuthCallbackHtml.success(s.user_id, bool(s.totp_setup_required), "/")
    except BffError:
        html = OAuthCallbackHtml.error("exchange_failed", "/login?failed=1")

return Response(content=html, media_type="text/html", headers={"Cache-Control": "no-store"})
```

## Public proxies for AppKit boot + pre-login auth

AppKit also hits two unauthenticated endpoints on your backend that
forward to ManyRows: `/apps/{app_id}` (public app config) and
`/apps/{app_id}/auth/*` (OAuth authorize, OTP request, etc.). Use
`PublicProxy`:

```python
from manyrows import PublicProxy

pp = PublicProxy(base_url="https://app.manyrows.com", workspace_slug="your-workspace")

# /apps/{app_id} GET handler:
r = pp.app_boot_get(app_id)
return Response(content=r.body, status_code=r.status, media_type=r.content_type)

# /apps/{app_id}/auth/{rest:path} catch-all:
suffix = request.url.path[len(f"/apps/{app_id}/auth"):]
body = await request.body() if request.method != "GET" else None
r = pp.auth_forward(
    app_id,
    request.method,
    suffix,
    str(request.url.query) or None,
    body.decode() if body else None,
    request.headers.get("content-type"),
)
return Response(content=r.body, status_code=r.status, media_type=r.content_type)
```

## Session cookie security

`BffClient` returns the session ID; you store it in a browser-facing
cookie. Mark that cookie **HttpOnly + Secure + SameSite=Strict** —
Starlette / FastAPI's `SessionMiddleware` defaults to HttpOnly but you
must opt into Secure and SameSite=Strict explicitly. Without these flags
an XSS or CSRF on your domain hands the attacker a usable session ID.

## Custom HTTP client

Inject your own `httpx.Client` / `httpx.AsyncClient` for testing, request tracing, or custom timeout/transport configuration:

```python
import httpx
from manyrows import Client

http = httpx.Client(timeout=30.0, headers={"X-Trace-Id": "abc"})
client = Client(
    base_url="https://app.manyrows.com",
    workspace_slug="your-workspace",
    app_id="your-app-id",
    api_key="mr_...",
    http_client=http,
)
```

When you pass your own client, you own its lifecycle — call `http.close()` (or use it as a context manager) yourself.

## License

[MIT](./LICENSE)
