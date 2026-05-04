"""Bearer-token verification for server-side auth.

Mirrors the Go SDK's ``auth.Middleware`` pattern: validate the user's JWT
against the ManyRows ``/a/me`` endpoint, then return the authenticated
user ID.
"""

from __future__ import annotations

import httpx

_USER_AGENT = "manyrows-python-auth/1.0"


def _me_url(base_url: str, workspace_slug: str, app_id: str) -> str:
    base = base_url.rstrip("/")
    return f"{base}/x/{workspace_slug}/apps/{app_id}/a/me"


def verify_token(
    token: str,
    *,
    base_url: str,
    workspace_slug: str,
    app_id: str,
    http_client: httpx.Client | None = None,
) -> str | None:
    """Verify a user's bearer token by calling the ManyRows ``/a/me`` endpoint.

    Returns the user ID on success.
    Returns ``None`` if the token is empty or rejected by ManyRows (401/403).
    Raises ``httpx.HTTPError`` on network errors or unexpected (5xx, malformed) responses.

    Callers in security-sensitive contexts should treat raised errors the same
    as ``None`` — fail closed, don't let a flaky upstream become an auth bypass.
    """
    if not token:
        return None

    url = _me_url(base_url, workspace_slug, app_id)
    headers = {"Authorization": f"Bearer {token}", "User-Agent": _USER_AGENT}

    if http_client is not None:
        res = http_client.get(url, headers=headers)
    else:
        with httpx.Client(timeout=10.0) as c:
            res = c.get(url, headers=headers)

    if res.status_code in (401, 403):
        return None
    if not res.is_success:
        raise httpx.HTTPStatusError(
            f"manyrows: /me returned {res.status_code}",
            request=res.request,
            response=res,
        )

    data = res.json()
    if not isinstance(data, dict):
        return None
    user = data.get("user")
    if not isinstance(user, dict):
        return None
    user_id = user.get("id")
    return user_id if isinstance(user_id, str) and user_id else None


async def verify_token_async(
    token: str,
    *,
    base_url: str,
    workspace_slug: str,
    app_id: str,
    http_client: httpx.AsyncClient | None = None,
) -> str | None:
    """Async equivalent of :func:`verify_token`."""
    if not token:
        return None

    url = _me_url(base_url, workspace_slug, app_id)
    headers = {"Authorization": f"Bearer {token}", "User-Agent": _USER_AGENT}

    if http_client is not None:
        res = await http_client.get(url, headers=headers)
    else:
        async with httpx.AsyncClient(timeout=10.0) as c:
            res = await c.get(url, headers=headers)

    if res.status_code in (401, 403):
        return None
    if not res.is_success:
        raise httpx.HTTPStatusError(
            f"manyrows: /me returned {res.status_code}",
            request=res.request,
            response=res,
        )

    data = res.json()
    if not isinstance(data, dict):
        return None
    user = data.get("user")
    if not isinstance(user, dict):
        return None
    user_id = user.get("id")
    return user_id if isinstance(user_id, str) and user_id else None


def bearer_token(header_value: str | list[str] | None) -> str | None:
    """Extract the bearer token from an Authorization header value.

    Case-insensitive on the ``Bearer `` prefix. Trims whitespace.
    Returns ``None`` for missing, malformed, or empty input.
    Accepts a list (uses the first value) for compatibility with frameworks
    that surface duplicate headers.
    """
    if header_value is None:
        return None
    if isinstance(header_value, list):
        if not header_value:
            return None
        header_value = header_value[0]
    if not isinstance(header_value, str):
        return None

    trimmed = header_value.strip()
    if len(trimmed) < 7:
        return None
    if trimmed[:7].lower() != "bearer ":
        return None
    tok = trimmed[7:].strip()
    return tok if tok else None
