"""Async tests for AsyncBffClient + AsyncPublicProxy.

Light coverage — the async classes mirror the sync ones via the same
helpers, so the sync test_bff.py exercises the shared decoding /
URL-construction / error-wrapping paths. These tests verify the async
plumbing itself: await semantics, header forwarding, basic auth, and
network-error wrapping.
"""

from __future__ import annotations

import base64

import httpx
import pytest

from manyrows import AsyncBffClient, AsyncPublicProxy, BffError, ClientContext
from manyrows.bff import dispatch_oauth_callback_async

from .conftest import make_transport

BASE = "https://app.manyrows.com"
CID = "client_abc"
CSECRET = "secret_xyz"
EXPECTED_BASIC = "Basic " + base64.b64encode(f"{CID}:{CSECRET}".encode()).decode()


def _new_async_bff(transport: httpx.MockTransport) -> AsyncBffClient:
    return AsyncBffClient(
        base_url=BASE,
        client_id=CID,
        client_secret=CSECRET,
        http_client=httpx.AsyncClient(transport=transport),
    )


class TestAsyncBffClientConstructor:
    def test_rejects_empty_args(self) -> None:
        with pytest.raises(ValueError):
            AsyncBffClient(base_url="", client_id=CID, client_secret=CSECRET)
        with pytest.raises(ValueError):
            AsyncBffClient(base_url=BASE, client_id="", client_secret=CSECRET)
        with pytest.raises(ValueError):
            AsyncBffClient(base_url=BASE, client_id=CID, client_secret="")


class TestAsyncLoginPassword:
    @pytest.mark.asyncio
    async def test_posts_with_basic_auth_and_decodes_session(self) -> None:
        transport, captured = make_transport(
            [
                {
                    "json": {
                        "sessionId": "sess_async",
                        "userId": "u_async",
                        "expiresAt": "2030-01-01T00:00:00Z",
                    }
                }
            ]
        )
        async with _new_async_bff(transport) as bff:
            s = await bff.login_password(
                "a@b.com",
                "pw",
                True,
                ClientContext(client_ip="1.2.3.4", client_user_agent="Mozilla"),
            )

        assert s.session_id == "sess_async"
        assert s.user_id == "u_async"

        req = captured[0]
        assert str(req.url) == BASE + "/bff/login"
        assert req.headers["Authorization"] == EXPECTED_BASIC
        assert req.headers["X-BFF-Client-IP"] == "1.2.3.4"
        assert req.headers["X-BFF-Client-User-Agent"] == "Mozilla"

    @pytest.mark.asyncio
    async def test_surfaces_totp_required(self) -> None:
        transport, _ = make_transport(
            [{"json": {"totpRequired": True, "challengeToken": "ct"}}]
        )
        async with _new_async_bff(transport) as bff:
            s = await bff.login_password("a@b.com", "pw", False)
        assert s.totp_required is True
        assert s.challenge_token == "ct"


class TestAsyncProxy:
    @pytest.mark.asyncio
    async def test_get_adds_session_header(self) -> None:
        transport, captured = make_transport([{"json": {"ok": True}}])
        async with _new_async_bff(transport) as bff:
            r = await bff.proxy_get("sess_a", "/me")
        assert r.status == 200
        req = captured[0]
        assert str(req.url) == BASE + "/bff/proxy/me"
        assert req.headers["X-BFF-Session-ID"] == "sess_a"

    @pytest.mark.asyncio
    async def test_rejects_empty_session_id(self) -> None:
        transport, _ = make_transport([])
        async with _new_async_bff(transport) as bff:
            with pytest.raises(ValueError, match="session_id"):
                await bff.proxy_get("", "/me")


class TestAsyncErrors:
    @pytest.mark.asyncio
    async def test_wraps_non_2xx_as_bff_error(self) -> None:
        transport, _ = make_transport(
            [{"status": 401, "json": {"error": "error.invalidCredentials"}}]
        )
        async with _new_async_bff(transport) as bff:
            with pytest.raises(BffError) as exc_info:
                await bff.login_password("a@b.com", "wrong", False)
        assert exc_info.value.status == 401

    @pytest.mark.asyncio
    async def test_wraps_network_errors_as_bff_error(self) -> None:
        transport, _ = make_transport([{"error": httpx.ConnectError("refused")}])
        async with _new_async_bff(transport) as bff:
            with pytest.raises(BffError):
                await bff.login_password("a@b.com", "pw", False)


class TestAsyncPublicProxy:
    @pytest.mark.asyncio
    async def test_app_boot_get(self) -> None:
        transport, captured = make_transport([{"json": {"name": "X"}}])
        async with AsyncPublicProxy(
            base_url=BASE,
            workspace_slug="acme",
            http_client=httpx.AsyncClient(transport=transport),
        ) as pp:
            r = await pp.app_boot_get("app_42")

        assert r.status == 200
        req = captured[0]
        assert str(req.url) == BASE + "/x/acme/apps/app_42"
        assert "Authorization" not in req.headers

    @pytest.mark.asyncio
    async def test_auth_forward_post_with_query(self) -> None:
        transport, captured = make_transport([{"json": {}}])
        async with AsyncPublicProxy(
            base_url=BASE,
            workspace_slug="acme",
            http_client=httpx.AsyncClient(transport=transport),
        ) as pp:
            await pp.auth_forward(
                "app_42",
                "POST",
                "/microsoft/authorize",
                "openerOrigin=http%3A%2F%2Flocalhost",
                "{}",
                "application/json",
            )

        req = captured[0]
        assert str(req.url) == (
            BASE
            + "/x/acme/apps/app_42/auth/microsoft/authorize"
            + "?openerOrigin=http%3A%2F%2Flocalhost"
        )
        assert req.method == "POST"


class TestAsyncDispatchOAuthCallback:
    @pytest.mark.asyncio
    async def test_short_circuits_challenge_required(self) -> None:
        transport, captured = make_transport([])
        async with _new_async_bff(transport) as bff:
            out = await dispatch_oauth_callback_async(
                query={"challengeRequired": "1", "challengeToken": "ct_async"},
                bff=bff,
                redirect_uri="https://yourapp.com/auth/oauth/callback",
                success_redirect="/",
                error_redirect="/login?failed=1",
                totp_redirect="/login/totp",
            )
        assert out.kind == "totp"
        assert out.challenge_token == "ct_async"
        assert captured == []

    @pytest.mark.asyncio
    async def test_success_path_invokes_async_exchange(self) -> None:
        transport, captured = make_transport(
            [
                {
                    "json": {
                        "sessionId": "sess_async",
                        "userId": "u_async",
                        "expiresAt": "2030-01-01T00:00:00Z",
                    }
                }
            ]
        )
        async with _new_async_bff(transport) as bff:
            out = await dispatch_oauth_callback_async(
                query={"code": "abc"},
                bff=bff,
                redirect_uri="https://yourapp.com/auth/oauth/callback",
                success_redirect="/",
                error_redirect="/login?failed=1",
            )
        assert out.kind == "success"
        assert out.session is not None
        assert out.session.session_id == "sess_async"
        assert len(captured) == 1
        assert str(captured[0].url) == BASE + "/bff/exchange"
