"""Local JWT verification against the install's JWKS, with cookie-mode
fallback for browsers that hold the session in an HttpOnly cookie
instead of a Bearer header. Mirrors ``manyrows-go/auth.Middleware``.

Tokens are signed ES256. The verifier fetches
``${base_url}/.well-known/jwks.json`` once on first verify, caches the
keys in-process, and refetches on a kid mismatch (with a short
cooldown to prevent thundering on a stream of bad kids).
"""

from __future__ import annotations

import json
import time
from threading import Lock
from typing import Any

import httpx
import jwt
from jwt.algorithms import ECAlgorithm

_USER_AGENT = "manyrows-python-auth/1.0"

# Cookie name is per-app — "mr_at_<app_id>" — so two ManyRows apps on
# the same eTLD don't share one cookie slot in the browser jar.
# Mirrors manyrows-core's clientauth.AccessCookieName(appID). Keep in
# sync if the server-side naming ever changes.
_ACCESS_COOKIE_PREFIX = "mr_at_"


def _access_cookie_name(app_id: str) -> str:
    return _ACCESS_COOKIE_PREFIX + app_id

# JWKS cache parameters. ``_TTL`` is how long a fetched JWKS is trusted
# before a refetch on the next miss; ``_COOLDOWN`` rate-limits refetches
# triggered by an unknown kid (so a stream of bad kids can't pin us
# against the network).
_TTL = 600.0  # 10 min
_COOLDOWN = 30.0


class _JWKSEntry:
    __slots__ = ("keys", "fetched_at", "last_refetch_attempt")

    def __init__(self, keys: dict[str, Any]) -> None:
        self.keys = keys
        now = time.monotonic()
        self.fetched_at = now
        self.last_refetch_attempt = now


# Module-level cache keyed by JWKS URL. Lock guards mutations; HTTP
# fetches happen *outside* the lock so concurrent verify_token calls
# for different URLs don't serialise on each other.
_jwks_cache: dict[str, _JWKSEntry] = {}
_jwks_lock = Lock()


def _jwks_url(base_url: str) -> str:
    return f"{base_url.rstrip('/')}/.well-known/jwks.json"


def _parse_jwks(data: Any) -> dict[str, Any]:
    """Decode a JWKS payload into a {kid: cryptography_public_key} map.

    Non-EC / non-P-256 / kid-less entries are skipped silently — a
    future server that publishes mixed key types stays compatible.
    """
    if not isinstance(data, dict):
        return {}
    raw_keys = data.get("keys")
    if not isinstance(raw_keys, list):
        return {}
    out: dict[str, Any] = {}
    for jwk_dict in raw_keys:
        if not isinstance(jwk_dict, dict):
            continue
        kid = jwk_dict.get("kid")
        if not kid or jwk_dict.get("kty") != "EC" or jwk_dict.get("crv") != "P-256":
            continue
        try:
            key = ECAlgorithm.from_jwk(json.dumps(jwk_dict))
        except Exception:
            continue
        out[kid] = key
    return out


def _fetch_jwks_sync(url: str, http_client: httpx.Client | None) -> dict[str, Any]:
    headers = {"User-Agent": _USER_AGENT}
    if http_client is not None:
        res = http_client.get(url, headers=headers)
    else:
        with httpx.Client(timeout=10.0) as c:
            res = c.get(url, headers=headers)
    res.raise_for_status()
    return _parse_jwks(res.json())


async def _fetch_jwks_async(url: str, http_client: httpx.AsyncClient | None) -> dict[str, Any]:
    headers = {"User-Agent": _USER_AGENT}
    if http_client is not None:
        res = await http_client.get(url, headers=headers)
    else:
        async with httpx.AsyncClient(timeout=10.0) as c:
            res = await c.get(url, headers=headers)
    res.raise_for_status()
    return _parse_jwks(res.json())


def _peek_cached(url: str, kid: str) -> tuple[Any | None, bool]:
    """Return ``(key, should_refetch)`` for the cached JWKS at ``url``.

    ``key`` may be a usable key, a stale (but cached) fallback, or
    ``None`` when nothing is cached. ``should_refetch`` is True when
    the caller should hit the network — either no cache, or unknown
    kid past cooldown, or TTL expired.
    """
    now = time.monotonic()
    with _jwks_lock:
        entry = _jwks_cache.get(url)
        if entry is None:
            return None, True
        fresh = (now - entry.fetched_at) < _TTL
        cached_key = entry.keys.get(kid)
        if fresh and cached_key is not None:
            return cached_key, False
        # Either stale or unknown kid. Respect cooldown to avoid
        # hammering the JWKS endpoint on a hostile token stream.
        if (now - entry.last_refetch_attempt) < _COOLDOWN:
            return cached_key, False
        entry.last_refetch_attempt = now
        return cached_key, True


def _store_jwks(url: str, keys: dict[str, Any]) -> None:
    with _jwks_lock:
        _jwks_cache[url] = _JWKSEntry(keys)


def _resolve_key_sync(base_url: str, kid: str, http_client: httpx.Client | None) -> Any | None:
    url = _jwks_url(base_url)
    cached, should_refetch = _peek_cached(url, kid)
    if not should_refetch:
        return cached
    try:
        keys = _fetch_jwks_sync(url, http_client)
    except Exception:
        # Fall back to whatever's cached (possibly stale, possibly
        # missing) — better to keep authenticating users on the kids
        # we already know than to hard-fail every request during a
        # transient JWKS outage.
        return cached
    _store_jwks(url, keys)
    return keys.get(kid)


async def _resolve_key_async(
    base_url: str, kid: str, http_client: httpx.AsyncClient | None
) -> Any | None:
    url = _jwks_url(base_url)
    cached, should_refetch = _peek_cached(url, kid)
    if not should_refetch:
        return cached
    try:
        keys = await _fetch_jwks_async(url, http_client)
    except Exception:
        return cached
    _store_jwks(url, keys)
    return keys.get(kid)


def _verify_with_key(token: str, key: Any, app_id: str) -> str | None:
    try:
        # `audience=app_id` enforces that the token's aud claim contains
        # this app's ID — PyJWT accepts both string and list[str] shapes
        # per RFC 7519. Catches the cross-app cookie ride-along between
        # two ManyRows apps on the same eTLD.
        payload = jwt.decode(
            token,
            key,
            algorithms=["ES256"],
            leeway=60,
            audience=app_id,
        )
    except jwt.PyJWTError:
        return None
    if not isinstance(payload, dict):
        return None
    sub = payload.get("sub")
    return sub if isinstance(sub, str) and sub else None


def verify_token(
    token: str,
    *,
    base_url: str,
    workspace_slug: str,
    app_id: str,
    http_client: httpx.Client | None = None,
) -> str | None:
    """Verify a user's bearer JWT against the install's JWKS.

    Returns the user ID (``sub`` claim) on success.
    Returns ``None`` if the token is empty, malformed, expired, or
    fails signature verification — caller should treat as "not
    authenticated" and 401 the request.

    The token's ``aud`` claim must contain ``app_id`` — a token minted
    for a different app on the same install is rejected (catches the
    cross-app cookie ride-along between sibling subdomains).
    ``workspace_slug`` is currently unused; kept on the signature for
    forward-compat (e.g. a future per-workspace check).
    """
    _ = workspace_slug
    if not token:
        return None
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        return None
    kid = header.get("kid") if isinstance(header, dict) else None
    if not isinstance(kid, str) or not kid:
        return None
    key = _resolve_key_sync(base_url, kid, http_client)
    if key is None:
        return None
    return _verify_with_key(token, key, app_id)


async def verify_token_async(
    token: str,
    *,
    base_url: str,
    workspace_slug: str,
    app_id: str,
    http_client: httpx.AsyncClient | None = None,
) -> str | None:
    """Async equivalent of :func:`verify_token`. Same JWKS cache."""
    _ = workspace_slug
    if not token:
        return None
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        return None
    kid = header.get("kid") if isinstance(header, dict) else None
    if not isinstance(kid, str) or not kid:
        return None
    key = await _resolve_key_async(base_url, kid, http_client)
    if key is None:
        return None
    return _verify_with_key(token, key, app_id)


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


def mr_at_cookie(
    cookie_header_value: str | list[str] | None,
    app_id: str,
) -> str | None:
    """Extract the ``mr_at_<app_id>`` session cookie from a Cookie header.

    Used as a fallback when the SDK is in cookie mode and no
    Authorization header is present. The cookie name is per-app so
    two ManyRows apps on the same eTLD don't collide — pass the
    configured ``app_id`` to read the right one. Returns ``None``
    when absent, empty, or malformed. Accepts a list (joined into one
    cookie string) for compatibility with frameworks that surface
    duplicate headers.
    """
    if cookie_header_value is None or not app_id:
        return None
    if isinstance(cookie_header_value, list):
        if not cookie_header_value:
            return None
        cookie_header_value = "; ".join(cookie_header_value)
    if not isinstance(cookie_header_value, str):
        return None
    target = _access_cookie_name(app_id)
    for raw in cookie_header_value.split(";"):
        eq = raw.find("=")
        if eq < 0:
            continue
        name = raw[:eq].strip()
        if name != target:
            continue
        value = raw[eq + 1 :].strip()
        return value if value else None
    return None


def reset_jwks_cache_for_test() -> None:
    """Clear the in-process JWKS cache. Test seam — production code
    should never call this.
    """
    with _jwks_lock:
        _jwks_cache.clear()
