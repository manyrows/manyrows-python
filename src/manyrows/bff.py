"""Full-BFF client for the ManyRows ``/bff/*`` server-to-server surface.

Mirrors manyrows-go's ``bff.Client`` + ``bff.MountAppBoot`` + the
popup-aware OAuth callback HTML. Python web frameworks are too varied
(Flask vs. FastAPI vs. Django vs. Starlette vs. raw WSGI) to ship a
router-mount helper; this module provides the typed HTTP calls + the
popup HTML + public proxies — the irreducible pieces a Python backend
needs to stand up against AppKit's bffMode. Customers wire the routes
themselves with their framework.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

import httpx

_USER_AGENT_BFF = "manyrows-python-bff/1.0"
_USER_AGENT_PUBLIC_PROXY = "manyrows-python-public-proxy/1.0"

_HEADER_SESSION_ID = "X-BFF-Session-ID"
_HEADER_CLIENT_IP = "X-BFF-Client-IP"
_HEADER_CLIENT_UA = "X-BFF-Client-User-Agent"


class BffError(Exception):
    """Raised for non-2xx responses from /bff/* or network/decoding failures.

    Inspect ``status`` and ``body`` to distinguish auth failures (401),
    rate limits (429), server errors (5xx).
    """

    def __init__(self, message: str, status: int | None = None, body: str | None = None):
        super().__init__(message)
        self.status = status
        self.body = body


@dataclass
class BffSession:
    """Wire shape returned by every :class:`BffClient` auth call.

    Stash ``session_id`` in a browser-facing HttpOnly cookie. On every
    authed AppKit request your handler proxies via :meth:`BffClient.proxy`
    with that same ``session_id`` (carried as ``X-BFF-Session-ID``).

    ``expires_at`` is informational — your cookie's ``Max-Age`` may
    mirror it but ManyRows is the authority on session lifetime.

    ``totp_required`` (with ``challenge_token``) is set when the user has
    TOTP enrolled — the customer's UI prompts for the code and calls
    :meth:`BffClient.verify_totp`. No session is issued on this branch.

    ``totp_setup_required`` is set when ``app.Require2FA`` is on but the
    user hasn't enrolled yet. The session IS issued; the customer's UI
    should route to a TOTP setup screen.

    ``password_already_set`` is set on the verify-OTP path (registration
    flow) when the verifying user already has a password — the customer's
    create-account UI uses this to skip the post-verify "set your
    password" screen.
    """

    session_id: str | None = None
    user_id: str | None = None
    expires_at: str | None = None
    totp_required: bool | None = None
    challenge_token: str | None = None
    totp_setup_required: bool | None = None
    password_already_set: bool | None = None

    @classmethod
    def _from_json(cls, data: dict[str, Any]) -> BffSession:
        return cls(
            session_id=_opt_str(data.get("sessionId")),
            user_id=_opt_str(data.get("userId")),
            expires_at=_opt_str(data.get("expiresAt")),
            totp_required=_opt_bool(data.get("totpRequired")),
            challenge_token=_opt_str(data.get("challengeToken")),
            totp_setup_required=_opt_bool(data.get("totpSetupRequired")),
            password_already_set=_opt_bool(data.get("passwordAlreadySet")),
        )


@dataclass
class ClientContext:
    """Forwarded browser metadata. Pass on every BFF call.

    Without these, ManyRows' per-IP rate limits and audit logs attribute
    to the customer backend's egress IP instead of the real user. The
    customer pulls these off the framework request (e.g. ``request.client.host``
    for FastAPI, ``request.remote_addr`` for Flask).
    """

    client_ip: str | None = None
    client_user_agent: str | None = None


@dataclass
class ProxyResponse:
    """Raw upstream proxy response — caller decides what to forward.

    ``body`` is decoded as text (UTF-8). All ManyRows /bff/proxy/*
    endpoints respond with JSON, so this is fine in practice; if you
    extend the proxy to forward binary upstream responses you'll need
    a separate path that uses ``response.content`` instead.
    """

    status: int
    body: str
    content_type: str
    headers: dict[str, str] = field(default_factory=dict)


class BffClient:
    """Sync client for the ManyRows ``/bff/*`` endpoints.

    Authenticates with HTTP Basic. Always pass ``ctx`` on each call so
    per-IP rate limits and audit logs in ManyRows attribute to the real
    user, not the customer backend's egress IP.

    Example (FastAPI / Flask / Django pattern is the same — pull
    ``client_ip`` and ``client_user_agent`` off your framework's request)::

        from manyrows.bff import BffClient, ClientContext

        bff = BffClient(
            base_url="https://app.manyrows.com",
            client_id=os.environ["MANYROWS_BFF_CLIENT_ID"],
            client_secret=os.environ["MANYROWS_BFF_CLIENT_SECRET"],
        )

        # /auth/login handler:
        ctx = ClientContext(client_ip=request.client.host,
                            client_user_agent=request.headers.get("user-agent"))
        s = bff.login_password(body.email, body.password, body.remember_me, ctx)
        if s.totp_required:
            return {"totpRequired": True, "challengeToken": s.challenge_token}
        request.session["manyrows_session_id"] = s.session_id
        return {"ok": True}
    """

    def __init__(
        self,
        *,
        base_url: str,
        client_id: str,
        client_secret: str,
        http_client: httpx.Client | None = None,
    ) -> None:
        if not base_url:
            raise ValueError("manyrows: base_url is required")
        if not client_id:
            raise ValueError("manyrows: client_id is required")
        if not client_secret:
            raise ValueError("manyrows: client_secret is required")

        self._base_url = base_url.rstrip("/")
        # Both values are ASCII-safe; encode-then-decode keeps the auth
        # header a plain str regardless of input quirks.
        creds = f"{client_id}:{client_secret}".encode()
        self._basic_auth = "Basic " + base64.b64encode(creds).decode("ascii")
        self._http = http_client
        self._owns_http = http_client is None

    def __enter__(self) -> BffClient:
        if self._http is None:
            self._http = httpx.Client(timeout=30.0)
        return self

    def __exit__(self, *_: Any) -> None:
        if self._owns_http and self._http is not None:
            self._http.close()
            self._http = None

    def close(self) -> None:
        if self._owns_http and self._http is not None:
            self._http.close()
            self._http = None

    # ===== Login flows =====

    def login_password(
        self, email: str, password: str, remember_me: bool, ctx: ClientContext | None = None
    ) -> BffSession:
        """Password login. Returns a :class:`BffSession`; check ``totp_required``."""
        return self._post_session(
            "/bff/login",
            {"email": email, "password": password, "rememberMe": remember_me},
            ctx,
        )

    def login_google(
        self, credential: str, remember_me: bool, ctx: ClientContext | None = None
    ) -> BffSession:
        """Google sign-in. ``credential`` is the Google ID token from GSI."""
        return self._post_session(
            "/bff/google",
            {"credential": credential, "rememberMe": remember_me},
            ctx,
        )

    def verify_otp(
        self,
        email: str,
        code: str,
        app_id: str | None,
        remember_me: bool,
        ctx: ClientContext | None = None,
    ) -> BffSession:
        """Email-OTP verification. Pass ``app_id`` non-None for the register flow."""
        body: dict[str, Any] = {"email": email, "code": code, "rememberMe": remember_me}
        if app_id:
            body["appId"] = app_id
        return self._post_session("/bff/verify", body, ctx)

    def verify_totp(
        self, challenge_token: str, code: str, ctx: ClientContext | None = None
    ) -> BffSession:
        """Complete a TOTP step-up after a login flow returned ``totp_required``."""
        return self._post_session(
            "/bff/totp/verify",
            {"challengeToken": challenge_token, "code": code},
            ctx,
        )

    def passkey_login_begin(self, ctx: ClientContext | None = None) -> Any:
        """Start a discoverable WebAuthn login.

        Returns the raw ``{challengeId, publicKeyOptions}`` payload — pass
        it through to the browser unchanged for ``navigator.credentials.get``.
        """
        return self._post_raw("/bff/passkey/login/begin", {}, ctx)

    def passkey_login_finish(
        self,
        challenge_id: str,
        response: Any,
        remember_me: bool,
        ctx: ClientContext | None = None,
    ) -> BffSession:
        """Verify the WebAuthn assertion the browser returned and land a session."""
        return self._post_session(
            "/bff/passkey/login/finish",
            {"challengeId": challenge_id, "response": response, "rememberMe": remember_me},
            ctx,
        )

    def exchange_auth_code(
        self, code: str, redirect_uri: str, ctx: ClientContext | None = None
    ) -> BffSession:
        """Exchange a one-time auth code (from an OAuth provider redirect) for a session.

        ``redirect_uri`` MUST match what the OAuth flow was started with —
        same protection as any standard OAuth code exchange.
        """
        return self._post_session(
            "/bff/exchange",
            {"code": code, "redirectUri": redirect_uri},
            ctx,
        )

    # ===== Misc =====

    def forgot_password(
        self, email: str, app_id: str | None, ctx: ClientContext | None = None
    ) -> None:
        """Email-OTP password reset request. Anti-enumeration: returns silently."""
        body: dict[str, Any] = {"email": email}
        if app_id:
            body["appId"] = app_id
        self._post_void("/bff/forgot-password", body, ctx)

    def reset_password(
        self,
        email: str,
        code: str,
        new_password: str,
        app_id: str | None,
        logout_all: bool,
        ctx: ClientContext | None = None,
    ) -> None:
        """Complete the email-OTP password-reset flow."""
        body: dict[str, Any] = {
            "email": email,
            "code": code,
            "newPassword": new_password,
            "logoutAll": logout_all,
        }
        if app_id:
            body["appId"] = app_id
        self._post_void("/bff/reset-password", body, ctx)

    def logout(self, session_id: str, ctx: ClientContext | None = None) -> None:
        """Revoke a session in ManyRows. Idempotent."""
        self._post_void("/bff/logout", {"sessionId": session_id}, ctx)

    # ===== Authenticated proxy =====

    def proxy(
        self,
        method: str,
        session_id: str,
        path_and_query: str,
        body: str | None = None,
        ctx: ClientContext | None = None,
    ) -> ProxyResponse:
        """Proxy an authenticated AppKit data call.

        Forwards to ManyRows ``/bff/proxy{path_and_query}`` with the
        session ID and forwarded browser metadata. The customer's
        framework wires ``/apps/{appId}/a/*`` (or wherever) to call
        this and relay status + body back to the browser.
        """
        if not session_id:
            raise ValueError("manyrows: session_id is required")
        url = f"{self._base_url}/bff/proxy{path_and_query}"
        headers = {
            "Authorization": self._basic_auth,
            _HEADER_SESSION_ID: session_id,
            "User-Agent": _USER_AGENT_BFF,
        }
        if ctx:
            if ctx.client_ip:
                headers[_HEADER_CLIENT_IP] = ctx.client_ip
            if ctx.client_user_agent:
                headers[_HEADER_CLIENT_UA] = ctx.client_user_agent
        if body is not None:
            headers["Content-Type"] = "application/json"

        try:
            res = self._do_request(method, url, headers, body)
        except httpx.HTTPError as e:
            raise BffError(f"manyrows: proxy {method} {path_and_query} failed: {e}") from e
        return ProxyResponse(
            status=res.status_code,
            body=res.text,
            content_type=res.headers.get("content-type", "application/json"),
            headers=dict(res.headers),
        )

    def proxy_get(
        self, session_id: str, path_and_query: str, ctx: ClientContext | None = None
    ) -> ProxyResponse:
        """GET shortcut for :meth:`proxy`."""
        return self.proxy("GET", session_id, path_and_query, None, ctx)

    def proxy_post(
        self,
        session_id: str,
        path_and_query: str,
        body: str,
        ctx: ClientContext | None = None,
    ) -> ProxyResponse:
        """POST shortcut for :meth:`proxy`."""
        return self.proxy("POST", session_id, path_and_query, body, ctx)

    # ===== internals =====

    def _post_session(
        self, path: str, body: Any, ctx: ClientContext | None
    ) -> BffSession:
        res = self._send(path, body, ctx)
        if not res.is_success:
            raise BffError(
                f"manyrows {path} failed: {res.text}", res.status_code, res.text
            )
        try:
            data = res.json()
        except json.JSONDecodeError as e:
            raise BffError(f"manyrows: decode session response: {e}") from e
        if not isinstance(data, dict):
            raise BffError(f"manyrows: unexpected session response type: {type(data).__name__}")
        return BffSession._from_json(data)

    def _post_raw(self, path: str, body: Any, ctx: ClientContext | None) -> Any:
        res = self._send(path, body, ctx)
        if not res.is_success:
            raise BffError(
                f"manyrows {path} failed: {res.text}", res.status_code, res.text
            )
        return res.json()

    def _post_void(self, path: str, body: Any, ctx: ClientContext | None) -> None:
        res = self._send(path, body, ctx)
        if not res.is_success:
            raise BffError(
                f"manyrows {path} failed: {res.text}", res.status_code, res.text
            )

    def _send(self, path: str, body: Any, ctx: ClientContext | None) -> httpx.Response:
        headers = {
            "Authorization": self._basic_auth,
            "Content-Type": "application/json",
            "User-Agent": _USER_AGENT_BFF,
        }
        if ctx:
            if ctx.client_ip:
                headers[_HEADER_CLIENT_IP] = ctx.client_ip
            if ctx.client_user_agent:
                headers[_HEADER_CLIENT_UA] = ctx.client_user_agent
        try:
            return self._do_request("POST", f"{self._base_url}{path}", headers, json.dumps(body))
        except httpx.HTTPError as e:
            raise BffError(f"manyrows {path} failed: {e}") from e

    def _do_request(
        self, method: str, url: str, headers: dict[str, str], body: str | None
    ) -> httpx.Response:
        if self._http is not None:
            return self._http.request(method, url, headers=headers, content=body)
        with httpx.Client(timeout=30.0) as c:
            return c.request(method, url, headers=headers, content=body)


class AsyncBffClient:
    """Async equivalent of :class:`BffClient`.

    Same surface, ``await``-flavoured. Use this from FastAPI, Starlette,
    Django async views, or anywhere ``async def`` handlers live; the sync
    :class:`BffClient` blocks the event loop and shouldn't be called from
    inside an ``async def``.
    """

    def __init__(
        self,
        *,
        base_url: str,
        client_id: str,
        client_secret: str,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        if not base_url:
            raise ValueError("manyrows: base_url is required")
        if not client_id:
            raise ValueError("manyrows: client_id is required")
        if not client_secret:
            raise ValueError("manyrows: client_secret is required")

        self._base_url = base_url.rstrip("/")
        creds = f"{client_id}:{client_secret}".encode()
        self._basic_auth = "Basic " + base64.b64encode(creds).decode("ascii")
        self._http = http_client
        self._owns_http = http_client is None

    async def __aenter__(self) -> AsyncBffClient:
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=30.0)
        return self

    async def __aexit__(self, *_: Any) -> None:
        if self._owns_http and self._http is not None:
            await self._http.aclose()
            self._http = None

    async def aclose(self) -> None:
        if self._owns_http and self._http is not None:
            await self._http.aclose()
            self._http = None

    # ===== Login flows =====

    async def login_password(
        self, email: str, password: str, remember_me: bool, ctx: ClientContext | None = None
    ) -> BffSession:
        return await self._post_session(
            "/bff/login",
            {"email": email, "password": password, "rememberMe": remember_me},
            ctx,
        )

    async def login_google(
        self, credential: str, remember_me: bool, ctx: ClientContext | None = None
    ) -> BffSession:
        return await self._post_session(
            "/bff/google",
            {"credential": credential, "rememberMe": remember_me},
            ctx,
        )

    async def verify_otp(
        self,
        email: str,
        code: str,
        app_id: str | None,
        remember_me: bool,
        ctx: ClientContext | None = None,
    ) -> BffSession:
        body: dict[str, Any] = {"email": email, "code": code, "rememberMe": remember_me}
        if app_id:
            body["appId"] = app_id
        return await self._post_session("/bff/verify", body, ctx)

    async def verify_totp(
        self, challenge_token: str, code: str, ctx: ClientContext | None = None
    ) -> BffSession:
        return await self._post_session(
            "/bff/totp/verify",
            {"challengeToken": challenge_token, "code": code},
            ctx,
        )

    async def passkey_login_begin(self, ctx: ClientContext | None = None) -> Any:
        return await self._post_raw("/bff/passkey/login/begin", {}, ctx)

    async def passkey_login_finish(
        self,
        challenge_id: str,
        response: Any,
        remember_me: bool,
        ctx: ClientContext | None = None,
    ) -> BffSession:
        return await self._post_session(
            "/bff/passkey/login/finish",
            {"challengeId": challenge_id, "response": response, "rememberMe": remember_me},
            ctx,
        )

    async def exchange_auth_code(
        self, code: str, redirect_uri: str, ctx: ClientContext | None = None
    ) -> BffSession:
        return await self._post_session(
            "/bff/exchange",
            {"code": code, "redirectUri": redirect_uri},
            ctx,
        )

    # ===== Misc =====

    async def forgot_password(
        self, email: str, app_id: str | None, ctx: ClientContext | None = None
    ) -> None:
        body: dict[str, Any] = {"email": email}
        if app_id:
            body["appId"] = app_id
        await self._post_void("/bff/forgot-password", body, ctx)

    async def reset_password(
        self,
        email: str,
        code: str,
        new_password: str,
        app_id: str | None,
        logout_all: bool,
        ctx: ClientContext | None = None,
    ) -> None:
        body: dict[str, Any] = {
            "email": email,
            "code": code,
            "newPassword": new_password,
            "logoutAll": logout_all,
        }
        if app_id:
            body["appId"] = app_id
        await self._post_void("/bff/reset-password", body, ctx)

    async def logout(self, session_id: str, ctx: ClientContext | None = None) -> None:
        await self._post_void("/bff/logout", {"sessionId": session_id}, ctx)

    # ===== Authenticated proxy =====

    async def proxy(
        self,
        method: str,
        session_id: str,
        path_and_query: str,
        body: str | None = None,
        ctx: ClientContext | None = None,
    ) -> ProxyResponse:
        if not session_id:
            raise ValueError("manyrows: session_id is required")
        url = f"{self._base_url}/bff/proxy{path_and_query}"
        headers = {
            "Authorization": self._basic_auth,
            _HEADER_SESSION_ID: session_id,
            "User-Agent": _USER_AGENT_BFF,
        }
        if ctx:
            if ctx.client_ip:
                headers[_HEADER_CLIENT_IP] = ctx.client_ip
            if ctx.client_user_agent:
                headers[_HEADER_CLIENT_UA] = ctx.client_user_agent
        if body is not None:
            headers["Content-Type"] = "application/json"

        try:
            res = await self._do_request(method, url, headers, body)
        except httpx.HTTPError as e:
            raise BffError(f"manyrows: proxy {method} {path_and_query} failed: {e}") from e
        return ProxyResponse(
            status=res.status_code,
            body=res.text,
            content_type=res.headers.get("content-type", "application/json"),
            headers=dict(res.headers),
        )

    async def proxy_get(
        self, session_id: str, path_and_query: str, ctx: ClientContext | None = None
    ) -> ProxyResponse:
        return await self.proxy("GET", session_id, path_and_query, None, ctx)

    async def proxy_post(
        self,
        session_id: str,
        path_and_query: str,
        body: str,
        ctx: ClientContext | None = None,
    ) -> ProxyResponse:
        return await self.proxy("POST", session_id, path_and_query, body, ctx)

    # ===== internals =====

    async def _post_session(
        self, path: str, body: Any, ctx: ClientContext | None
    ) -> BffSession:
        res = await self._send(path, body, ctx)
        if not res.is_success:
            raise BffError(
                f"manyrows {path} failed: {res.text}", res.status_code, res.text
            )
        try:
            data = res.json()
        except json.JSONDecodeError as e:
            raise BffError(f"manyrows: decode session response: {e}") from e
        if not isinstance(data, dict):
            raise BffError(f"manyrows: unexpected session response type: {type(data).__name__}")
        return BffSession._from_json(data)

    async def _post_raw(self, path: str, body: Any, ctx: ClientContext | None) -> Any:
        res = await self._send(path, body, ctx)
        if not res.is_success:
            raise BffError(
                f"manyrows {path} failed: {res.text}", res.status_code, res.text
            )
        return res.json()

    async def _post_void(self, path: str, body: Any, ctx: ClientContext | None) -> None:
        res = await self._send(path, body, ctx)
        if not res.is_success:
            raise BffError(
                f"manyrows {path} failed: {res.text}", res.status_code, res.text
            )

    async def _send(
        self, path: str, body: Any, ctx: ClientContext | None
    ) -> httpx.Response:
        headers = {
            "Authorization": self._basic_auth,
            "Content-Type": "application/json",
            "User-Agent": _USER_AGENT_BFF,
        }
        if ctx:
            if ctx.client_ip:
                headers[_HEADER_CLIENT_IP] = ctx.client_ip
            if ctx.client_user_agent:
                headers[_HEADER_CLIENT_UA] = ctx.client_user_agent
        try:
            return await self._do_request(
                "POST", f"{self._base_url}{path}", headers, json.dumps(body)
            )
        except httpx.HTTPError as e:
            raise BffError(f"manyrows {path} failed: {e}") from e

    async def _do_request(
        self, method: str, url: str, headers: dict[str, str], body: str | None
    ) -> httpx.Response:
        if self._http is not None:
            return await self._http.request(method, url, headers=headers, content=body)
        async with httpx.AsyncClient(timeout=30.0) as c:
            return await c.request(method, url, headers=headers, content=body)


# ===========================================================================
# PublicProxy — unauthenticated browser-facing surface
# ===========================================================================


class PublicProxy:
    """Forwards the unauthenticated browser-facing surface AppKit hits.

    Two patterns:

    - GET ``/apps/{appId}`` → ``/x/{workspace_slug}/apps/{appId}`` (public
      boot — auth methods, branding, OAuth client IDs)
    - GET|POST ``/apps/{appId}/auth/*`` → pre-login auth surface (OAuth
      authorize, OTP request, etc.)

    Conceptually distinct from :class:`BffClient`: that calls authenticated
    server-to-server endpoints with HTTP Basic; this just relays browser
    requests with no credentials. Customer's framework wires the routes
    and calls into this class.
    """

    def __init__(
        self,
        *,
        base_url: str,
        workspace_slug: str,
        http_client: httpx.Client | None = None,
    ) -> None:
        if not base_url:
            raise ValueError("manyrows: base_url is required")
        if not workspace_slug:
            raise ValueError("manyrows: workspace_slug is required")
        self._base_url = base_url.rstrip("/")
        self._workspace_slug = workspace_slug
        self._http = http_client
        self._owns_http = http_client is None

    def __enter__(self) -> PublicProxy:
        if self._http is None:
            self._http = httpx.Client(timeout=30.0)
        return self

    def __exit__(self, *_: Any) -> None:
        if self._owns_http and self._http is not None:
            self._http.close()
            self._http = None

    def close(self) -> None:
        if self._owns_http and self._http is not None:
            self._http.close()
            self._http = None

    def app_boot_get(self, app_id: str) -> ProxyResponse:
        """GET /x/{workspace_slug}/apps/{app_id}. AppKit's bootstrap fetch."""
        if not app_id:
            raise ValueError("manyrows: app_id is required")
        url = f"{self._base_url}/x/{self._workspace_slug}/apps/{app_id}"
        return self._forward("GET", url, None, None)

    def auth_forward(
        self,
        app_id: str,
        method: str,
        suffix: str,
        query: str | None,
        body: str | None,
        content_type: str | None,
    ) -> ProxyResponse:
        """Forward an /apps/{app_id}/auth/* request to ManyRows.

        ``suffix`` is the path after ``/apps/{app_id}/auth`` — for the
        bare ``/apps/{app_id}/auth`` (the OTP send endpoint) pass ``""``;
        for ``/apps/{app_id}/auth/microsoft/authorize`` pass
        ``"/microsoft/authorize"``. Missing leading slash gets normalised.
        """
        if not app_id:
            raise ValueError("manyrows: app_id is required")
        if not method:
            raise ValueError("manyrows: method is required")
        s = suffix or ""
        if s and not s.startswith("/"):
            s = "/" + s
        url = f"{self._base_url}/x/{self._workspace_slug}/apps/{app_id}/auth{s}"
        if query:
            url += f"?{query}"
        return self._forward(method, url, body, content_type)

    def _forward(
        self, method: str, url: str, body: str | None, content_type: str | None
    ) -> ProxyResponse:
        headers: dict[str, str] = {"User-Agent": _USER_AGENT_PUBLIC_PROXY}
        if body is not None and content_type:
            headers["Content-Type"] = content_type
        try:
            if self._http is not None:
                res = self._http.request(method, url, headers=headers, content=body)
            else:
                with httpx.Client(timeout=30.0) as c:
                    res = c.request(method, url, headers=headers, content=body)
        except httpx.HTTPError as e:
            raise BffError(f"manyrows: public proxy {method} {url} failed: {e}") from e
        return ProxyResponse(
            status=res.status_code,
            body=res.text,
            content_type=res.headers.get("content-type", "application/json"),
            headers=dict(res.headers),
        )


class AsyncPublicProxy:
    """Async equivalent of :class:`PublicProxy`."""

    def __init__(
        self,
        *,
        base_url: str,
        workspace_slug: str,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        if not base_url:
            raise ValueError("manyrows: base_url is required")
        if not workspace_slug:
            raise ValueError("manyrows: workspace_slug is required")
        self._base_url = base_url.rstrip("/")
        self._workspace_slug = workspace_slug
        self._http = http_client
        self._owns_http = http_client is None

    async def __aenter__(self) -> AsyncPublicProxy:
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=30.0)
        return self

    async def __aexit__(self, *_: Any) -> None:
        if self._owns_http and self._http is not None:
            await self._http.aclose()
            self._http = None

    async def aclose(self) -> None:
        if self._owns_http and self._http is not None:
            await self._http.aclose()
            self._http = None

    async def app_boot_get(self, app_id: str) -> ProxyResponse:
        if not app_id:
            raise ValueError("manyrows: app_id is required")
        url = f"{self._base_url}/x/{self._workspace_slug}/apps/{app_id}"
        return await self._forward("GET", url, None, None)

    async def auth_forward(
        self,
        app_id: str,
        method: str,
        suffix: str,
        query: str | None,
        body: str | None,
        content_type: str | None,
    ) -> ProxyResponse:
        if not app_id:
            raise ValueError("manyrows: app_id is required")
        if not method:
            raise ValueError("manyrows: method is required")
        s = suffix or ""
        if s and not s.startswith("/"):
            s = "/" + s
        url = f"{self._base_url}/x/{self._workspace_slug}/apps/{app_id}/auth{s}"
        if query:
            url += f"?{query}"
        return await self._forward(method, url, body, content_type)

    async def _forward(
        self, method: str, url: str, body: str | None, content_type: str | None
    ) -> ProxyResponse:
        headers: dict[str, str] = {"User-Agent": _USER_AGENT_PUBLIC_PROXY}
        if body is not None and content_type:
            headers["Content-Type"] = content_type
        try:
            if self._http is not None:
                res = await self._http.request(method, url, headers=headers, content=body)
            else:
                async with httpx.AsyncClient(timeout=30.0) as c:
                    res = await c.request(method, url, headers=headers, content=body)
        except httpx.HTTPError as e:
            raise BffError(f"manyrows: public proxy {method} {url} failed: {e}") from e
        return ProxyResponse(
            status=res.status_code,
            body=res.text,
            content_type=res.headers.get("content-type", "application/json"),
            headers=dict(res.headers),
        )


# ===========================================================================
# OAuthCallbackHtml — popup-aware /auth/oauth/callback page
# ===========================================================================


class OAuthCallbackHtml:
    """Builds the popup-aware HTML page the customer's /auth/oauth/callback serves.

    Inline JS branches on ``window.opener`` at runtime: postMessage to
    opener (popup mode) or full-page redirect to the configured
    success/totp/error URL. Defuses ``</script>`` injection in payload
    values via ``</`` → ``<\\/`` replacement; escapes ``<`` to ``\\u003c``
    in JS string literals so injected payloads can't break out either way.
    """

    @staticmethod
    def success(
        user_id: str | None, totp_setup_required: bool, redirect_success_url: str
    ) -> str:
        """Successful login outcome."""
        payload: dict[str, Any] = {"ok": True}
        if user_id:
            payload["userId"] = user_id
        if totp_setup_required:
            payload["totpSetupRequired"] = True
        return _render(200, payload, redirect_success_url)

    @staticmethod
    def totp(
        challenge_token: str, redirect_totp_url: str, redirect_error_url: str
    ) -> str:
        """TOTP-required outcome.

        Falls back to ``redirect_error_url`` (with
        ``?error=totp_redirect_not_configured``) when ``redirect_totp_url``
        is empty.
        """
        if not redirect_totp_url:
            return OAuthCallbackHtml.error(
                "totp_redirect_not_configured", redirect_error_url
            )
        payload = {"totpRequired": True, "challengeToken": challenge_token}
        return _render(
            200, payload, _append_query(redirect_totp_url, "challengeToken", challenge_token)
        )

    @staticmethod
    def error(error_code: str, redirect_error_url: str) -> str:
        """Error outcome."""
        payload = {"error": error_code}
        redirect = (
            _append_query(redirect_error_url, "error", error_code)
            if redirect_error_url
            else None
        )
        return _render(400, payload, redirect)


# ===========================================================================
# dispatch_oauth_callback — full /auth/oauth/callback handler logic
# ===========================================================================


@dataclass
class OAuthCallbackOutcome:
    """Discriminated outcome of :func:`dispatch_oauth_callback`.

    The customer's handler writes ``html`` to the response and, for the
    ``"success"`` branch, issues a cookie carrying ``session.session_id``
    before sending the body. The ``"totp"`` and ``"error"`` branches
    are cookie-less by design.
    """

    kind: str  # "success" | "totp" | "error"
    html: str
    session: BffSession | None = None
    challenge_token: str | None = None
    error: str | None = None


def _dispatch_pre_exchange(
    query: Mapping[str, str],
    redirect_uri_unused: str,
    success_redirect_unused: str,
    error_redirect: str,
    totp_redirect: str,
) -> OAuthCallbackOutcome | None:
    """Returns an outcome for the pre-exchange branches (error / challenge / missing_code).

    Returns None when the query is well-formed enough that the caller
    should proceed to exchange the auth code.
    """
    err_code = (query.get("error") or "").strip()
    if err_code:
        return OAuthCallbackOutcome(
            kind="error",
            error=err_code,
            html=OAuthCallbackHtml.error(err_code, error_redirect),
        )
    if query.get("challengeRequired") == "1":
        ct = (query.get("challengeToken") or "").strip()
        return OAuthCallbackOutcome(
            kind="totp",
            challenge_token=ct,
            html=OAuthCallbackHtml.totp(ct, totp_redirect, error_redirect),
        )
    if not (query.get("code") or "").strip():
        return OAuthCallbackOutcome(
            kind="error",
            error="missing_code",
            html=OAuthCallbackHtml.error("missing_code", error_redirect),
        )
    return None


def _exchange_error_outcome(e: BffError, error_redirect: str) -> OAuthCallbackOutcome:
    err = "exchange_failed"
    body = e.body or ""
    if body:
        try:
            parsed = json.loads(body)
            if isinstance(parsed, dict) and parsed.get("error"):
                err = str(parsed["error"])
        except (ValueError, TypeError):
            pass
    return OAuthCallbackOutcome(
        kind="error", error=err, html=OAuthCallbackHtml.error(err, error_redirect)
    )


def _post_exchange_outcome(
    session: BffSession, success_redirect: str, error_redirect: str, totp_redirect: str
) -> OAuthCallbackOutcome:
    if session.totp_required:
        ct = session.challenge_token or ""
        return OAuthCallbackOutcome(
            kind="totp",
            challenge_token=ct,
            html=OAuthCallbackHtml.totp(ct, totp_redirect, error_redirect),
        )
    return OAuthCallbackOutcome(
        kind="success",
        session=session,
        html=OAuthCallbackHtml.success(
            session.user_id, bool(session.totp_setup_required), success_redirect
        ),
    )


def dispatch_oauth_callback(
    *,
    query: Mapping[str, str],
    bff: BffClient,
    redirect_uri: str,
    success_redirect: str,
    error_redirect: str,
    totp_redirect: str = "",
    ctx: ClientContext | None = None,
) -> OAuthCallbackOutcome:
    """Single entry point for ``/auth/oauth/callback`` (sync).

    Mirrors the manyrows-go ``Handlers.OAuthCallback``: parses the query
    (error / challengeRequired / code), exchanges the auth code via
    :meth:`BffClient.exchange_auth_code` when present, and returns the
    popup-aware HTML the customer should write to the response — plus
    the parsed session on success so the customer's framework can
    issue its own cookie.

    The async variant is :func:`dispatch_oauth_callback_async`.
    """
    pre = _dispatch_pre_exchange(
        query, redirect_uri, success_redirect, error_redirect, totp_redirect
    )
    if pre is not None:
        return pre
    code = query["code"].strip()
    try:
        session = bff.exchange_auth_code(code, redirect_uri, ctx)
    except BffError as e:
        return _exchange_error_outcome(e, error_redirect)
    return _post_exchange_outcome(session, success_redirect, error_redirect, totp_redirect)


async def dispatch_oauth_callback_async(
    *,
    query: Mapping[str, str],
    bff: AsyncBffClient,
    redirect_uri: str,
    success_redirect: str,
    error_redirect: str,
    totp_redirect: str = "",
    ctx: ClientContext | None = None,
) -> OAuthCallbackOutcome:
    """Async variant of :func:`dispatch_oauth_callback`."""
    pre = _dispatch_pre_exchange(
        query, redirect_uri, success_redirect, error_redirect, totp_redirect
    )
    if pre is not None:
        return pre
    code = query["code"].strip()
    try:
        session = await bff.exchange_auth_code(code, redirect_uri, ctx)
    except BffError as e:
        return _exchange_error_outcome(e, error_redirect)
    return _post_exchange_outcome(session, success_redirect, error_redirect, totp_redirect)


def _render(status: int, payload: dict[str, Any], redirect_url: str | None) -> str:
    payload_json = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    # Defuse </script> injection: an error code or other field whose
    # value contains </script> would terminate our inline <script>
    # block. Replace </ with <\/ — valid JSON (the / can be escaped),
    # safe in HTML (no </script> sequence in the source).
    payload_json = payload_json.replace("</", "<\\/")
    redirect_js = '""' if redirect_url is None else _js_string(redirect_url)
    fallback_text = _html_escape(payload_json)

    # Mirrors manyrows-go bff/popup.go writeOAuthCallbackResult.
    return f"""<!DOCTYPE html>
<html>
<head><title>Completing sign-in…</title></head>
<body>
<p>Completing sign-in…</p>
<script>
(function() {{
  var status = {status};
  var payload = {payload_json};
  var redirectURL = {redirect_js};
  if (window.opener) {{
    try {{
      window.opener.postMessage(
        {{ type: "manyrows-oauth-callback", status: status, payload: payload }},
        window.location.origin
      );
    }} catch (e) {{ /* opener may be closed */ }}
    window.close();
    return;
  }}
  if (redirectURL) {{
    window.location.replace(redirectURL);
    return;
  }}
  document.body.innerHTML = "<pre>" + {_js_string(fallback_text)} + "</pre>";
}})();
</script>
</body>
</html>"""


def _append_query(base: str, key: str, value: str) -> str:
    """Append ``key=value`` to ``base``, picking ``?`` or ``&`` as the separator.

    Internal helper — exported for tests via the deep import path.
    """
    if not base:
        return base
    sep = "&" if "?" in base else "?"
    return f"{base}{sep}{quote(key, safe='')}={quote(value, safe='')}"


def _js_string(raw: str) -> str:
    """Build a JS string literal.

    Escapes only what's actually dangerous inside an inline <script>
    block: the standard JSON-string set plus ``<`` (for ``</script>``
    safety) and U+2028 / U+2029 (which are line terminators in JS,
    unlike in JSON, and would break a single-line string). ``&`` and
    ``>`` are safe inside <script> — the HTML parser doesn't process
    entities there, and only ``<`` starts a tag close.
    """
    out = ['"']
    for ch in raw:
        c = ord(ch)
        if c == 0x22:
            out.append('\\"')
        elif c == 0x5C:
            out.append("\\\\")
        elif c == 0x0A:
            out.append("\\n")
        elif c == 0x0D:
            out.append("\\r")
        elif c == 0x09:
            out.append("\\t")
        elif c == 0x3C:
            out.append("\\u003c")
        elif c == 0x2028:
            out.append("\\u2028")
        elif c == 0x2029:
            out.append("\\u2029")
        elif c < 0x20:
            out.append(f"\\u{c:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _html_escape(raw: str) -> str:
    return (
        raw.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _opt_str(v: Any) -> str | None:
    return v if isinstance(v, str) and v else None


def _opt_bool(v: Any) -> bool | None:
    return v if isinstance(v, bool) else None
