from __future__ import annotations

import httpx
import pytest

from manyrows import bearer_token, verify_token, verify_token_async

from .conftest import make_transport

VERIFY_OPTS = {
    "base_url": "https://app.manyrows.com",
    "workspace_slug": "acme",
    "app_id": "app_123",
}


# ===== bearer_token =====


class TestBearerToken:
    def test_extracts_token_after_bearer_prefix(self):
        assert bearer_token("Bearer abc123") == "abc123"

    def test_is_case_insensitive_on_prefix(self):
        assert bearer_token("bearer abc") == "abc"
        assert bearer_token("BEARER abc") == "abc"
        assert bearer_token("BeArEr abc") == "abc"

    def test_trims_surrounding_whitespace(self):
        assert bearer_token("  Bearer   abc   ") == "abc"

    def test_returns_none_for_missing_or_wrong_input(self):
        assert bearer_token(None) is None
        assert bearer_token("") is None
        assert bearer_token("Basic xyz") is None
        assert bearer_token("Bearer ") is None
        assert bearer_token("Bearer") is None

    def test_uses_first_value_when_given_a_list(self):
        assert bearer_token(["Bearer abc", "Bearer def"]) == "abc"
        assert bearer_token([]) is None


# ===== verify_token (sync) =====


class TestVerifyTokenSync:
    def test_returns_user_id_on_200(self):
        transport, _ = make_transport([{"json": {"user": {"id": "user_xyz"}}}])
        with httpx.Client(transport=transport) as http:
            assert verify_token("tok", **VERIFY_OPTS, http_client=http) == "user_xyz"

    def test_returns_none_for_empty_token_no_network(self):
        transport, captured = make_transport([{"json": {"user": {"id": "x"}}}])
        with httpx.Client(transport=transport) as http:
            assert verify_token("", **VERIFY_OPTS, http_client=http) is None
        assert captured == []

    def test_returns_none_on_401(self):
        transport, _ = make_transport([{"status": 401, "text": ""}])
        with httpx.Client(transport=transport) as http:
            assert verify_token("tok", **VERIFY_OPTS, http_client=http) is None

    def test_returns_none_on_403(self):
        transport, _ = make_transport([{"status": 403, "text": ""}])
        with httpx.Client(transport=transport) as http:
            assert verify_token("tok", **VERIFY_OPTS, http_client=http) is None

    def test_raises_on_5xx(self):
        transport, _ = make_transport([{"status": 500, "text": "oops"}])
        with httpx.Client(transport=transport) as http:
            with pytest.raises(httpx.HTTPStatusError, match="500"):
                verify_token("tok", **VERIFY_OPTS, http_client=http)

    def test_returns_none_when_response_has_no_user_id(self):
        transport, _ = make_transport([{"json": {"user": {}}}])
        with httpx.Client(transport=transport) as http:
            assert verify_token("tok", **VERIFY_OPTS, http_client=http) is None

    def test_sends_authorization_and_user_agent(self):
        transport, captured = make_transport([{"json": {"user": {"id": "u"}}}])
        with httpx.Client(transport=transport) as http:
            verify_token("tok123", **VERIFY_OPTS, http_client=http)
        assert captured[0].headers["Authorization"] == "Bearer tok123"
        assert captured[0].headers["User-Agent"].startswith("manyrows-python-auth/")

    def test_strips_trailing_slash_on_base_url(self):
        transport, captured = make_transport([{"json": {"user": {"id": "u"}}}])
        with httpx.Client(transport=transport) as http:
            verify_token(
                "tok",
                base_url="https://app.manyrows.com/",
                workspace_slug="acme",
                app_id="app_123",
                http_client=http,
            )
        assert (
            str(captured[0].url)
            == "https://app.manyrows.com/x/acme/apps/app_123/a/me"
        )


# ===== verify_token (async) =====


class TestVerifyTokenAsync:
    async def test_returns_user_id_on_200(self):
        transport, _ = make_transport([{"json": {"user": {"id": "user_xyz"}}}])
        async with httpx.AsyncClient(transport=transport) as http:
            assert (
                await verify_token_async("tok", **VERIFY_OPTS, http_client=http)
                == "user_xyz"
            )

    async def test_returns_none_for_empty_token(self):
        transport, captured = make_transport([{"json": {}}])
        async with httpx.AsyncClient(transport=transport) as http:
            assert await verify_token_async("", **VERIFY_OPTS, http_client=http) is None
        assert captured == []

    async def test_returns_none_on_401(self):
        transport, _ = make_transport([{"status": 401, "text": ""}])
        async with httpx.AsyncClient(transport=transport) as http:
            assert await verify_token_async("tok", **VERIFY_OPTS, http_client=http) is None

    async def test_raises_on_5xx(self):
        transport, _ = make_transport([{"status": 500, "text": "oops"}])
        async with httpx.AsyncClient(transport=transport) as http:
            with pytest.raises(httpx.HTTPStatusError, match="500"):
                await verify_token_async("tok", **VERIFY_OPTS, http_client=http)

    async def test_sends_authorization_header(self):
        transport, captured = make_transport([{"json": {"user": {"id": "u"}}}])
        async with httpx.AsyncClient(transport=transport) as http:
            await verify_token_async("tok123", **VERIFY_OPTS, http_client=http)
        assert captured[0].headers["Authorization"] == "Bearer tok123"
