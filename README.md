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

### Decrypt secrets

Secret values are returned as encrypted envelopes. Decrypt them with
your workspace private key (downloaded once when you generated the
workspace key in the admin UI):

```python
import json, os
from manyrows import decrypt_secret

private_key_jwk = json.loads(os.environ["MANYROWS_WORKSPACE_PRIVATE_KEY"])
delivery = client.get_delivery()

for sec in delivery.config.secrets:
    if not sec.is_set or not sec.envelope:
        continue
    plaintext = decrypt_secret(sec.envelope, private_key_jwk)
    # plaintext is bytes of the JSON-encoded value. For a string secret
    # you'll get b'"hello"' (with quotes) — json.loads to recover.
    value = json.loads(plaintext.decode("utf-8"))
```

The private key never leaves your server — secrets are decrypted in
process. Requires the optional `cryptography` dep:

```bash
pip install 'manyrows[secrets]'
```

See `src/manyrows/secrets.py` for the full algorithm (ECDH P-256 +
HKDF-SHA256 + AES-256-GCM).

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

Verify the user's JWT **locally** against your install's JWKS. Fetches `${base_url}/.well-known/jwks.json` once on first verify, caches the parsed keys in-process, refetches on a kid mismatch. No per-request round trip to ManyRows. Use `bearer_token` to pull the JWT from the `Authorization` header and `mr_at_cookie` to fall back to the cookie that AppKit sets in cookie mode.

Built on [`PyJWT[crypto]`](https://github.com/jpadilla/pyjwt) — the de-facto Python JWT library.

### `verify_token`

Returns the user ID (`sub` claim) on success, `None` for any verification failure (expired, malformed, wrong signature, missing `sub`, JWKS unreachable). Doesn't raise on auth-decision-equivalent conditions — fail-closed is the caller's job; `None` is the "not authenticated" signal.

```python
from manyrows import bearer_token, mr_at_cookie, verify_token

# Try Authorization header first, then mr_at cookie (cookie-mode AppKit).
token = (
    bearer_token(request.headers.get("Authorization"))
    or mr_at_cookie(request.headers.get("Cookie"))
)
if not token:
    return Response("Unauthorized", status=401)

user_id = verify_token(
    token,
    base_url="https://app.manyrows.com",
    workspace_slug="your-workspace",
    app_id="your-app-id",
)
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

from manyrows import bearer_token, mr_at_cookie, verify_token_async

app = FastAPI()

async def manyrows_user_id(
    authorization: Annotated[str | None, Header()] = None,
    cookie: Annotated[str | None, Header()] = None,
) -> str:
    token = bearer_token(authorization) or mr_at_cookie(cookie)
    if not token:
        raise HTTPException(401)
    user_id = await verify_token_async(
        token,
        base_url="https://app.manyrows.com",
        workspace_slug="your-workspace",
        app_id="your-app-id",
    )
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

from manyrows import bearer_token, mr_at_cookie, verify_token

app = Flask(__name__)

def manyrows_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = (
            bearer_token(request.headers.get("Authorization"))
            or mr_at_cookie(request.headers.get("Cookie"))
        )
        if not token:
            abort(401)
        user_id = verify_token(
            token,
            base_url="https://app.manyrows.com",
            workspace_slug="your-workspace",
            app_id="your-app-id",
        )
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

## Webhook verification

ManyRows signs every outbound webhook delivery. Use `verify_webhook`
on your receiver:

```python
from manyrows import verify_webhook, WebhookError
from fastapi import FastAPI, Request, HTTPException

app = FastAPI()

@app.post("/webhooks/manyrows")
async def webhook(request: Request):
    body = await request.body()  # raw bytes — not request.json()
    try:
        verify_webhook(secret=secret, headers=request.headers, body=body)
    except WebhookError as err:
        raise HTTPException(401, detail=err.code)
    # body is verified — json.loads(body) and process
    return {"ok": True}
```

`verify_webhook` checks both the HMAC-SHA256 signature (over
`<timestamp>.<body>`) and that `X-Webhook-Timestamp` is within
±5 minutes of now. Pass `tolerance=timedelta(...)` to widen or tighten.

Read the body as **raw bytes** before verifying — re-serializing
parsed JSON changes whitespace and breaks the check.

## License

[MIT](./LICENSE)
