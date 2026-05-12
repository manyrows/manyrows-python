from __future__ import annotations

import base64
import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from manyrows import bearer_token, mr_at_cookie, verify_token, verify_token_async
from manyrows.auth import reset_jwks_cache_for_test


VERIFY_OPTS = {
    "base_url": "https://app.manyrows.com",
    "workspace_slug": "acme",
    "app_id": "app_123",
}


# =====================================================================
# Test helpers
# =====================================================================
#
# Each test stands up a fresh ES256 keypair, publishes the public half
# via a mocked /.well-known/jwks.json endpoint, and signs JWTs with the
# private half. Mirrors what manyrows-core does in production.
# ``reset_jwks_cache_for_test`` clears the in-process key cache between
# tests so a stale entry doesn't bleed across.


def _b64u_uint(n: int, length: int) -> str:
    return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()


def _generate_keypair():
    """Return ``(private_pem, jwk_dict, kid)``."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    pub_numbers = private_key.public_key().public_numbers()
    x = _b64u_uint(pub_numbers.x, 32)
    y = _b64u_uint(pub_numbers.y, 32)
    # Use a stable test kid; production uses RFC 7638 thumbprints, but
    # the cache only cares that it matches between JWT header and JWKS.
    kid = "test-kid-" + str(time.time_ns())
    jwk = {"kty": "EC", "crv": "P-256", "x": x, "y": y, "kid": kid, "alg": "ES256", "use": "sig"}
    return private_key, jwk, kid


def _sign(private_key, kid: str, *, sub: str = "user_xyz", aud: str = "app_123", **claims) -> str:
    payload = {
        "sub": sub,
        "aud": aud,
        "iat": int(time.time()),
        "exp": int(time.time()) + 300,
        **claims,
    }
    return jwt.encode(payload, private_key, algorithm="ES256", headers={"kid": kid})


def _jwks_transport(jwks: dict, captured: list[httpx.Request] | None = None) -> httpx.MockTransport:
    """Build an httpx mock transport that serves ``jwks`` at the
    well-known path and 404s anything else."""

    def handler(request: httpx.Request) -> httpx.Response:
        if captured is not None:
            captured.append(request)
        if request.url.path.endswith("/.well-known/jwks.json"):
            return httpx.Response(200, json=jwks)
        return httpx.Response(404, text="not found")

    return httpx.MockTransport(handler)


@pytest.fixture(autouse=True)
def _clear_cache():
    reset_jwks_cache_for_test()
    yield
    reset_jwks_cache_for_test()


# =====================================================================
# bearer_token
# =====================================================================


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


# =====================================================================
# mr_at_cookie
# =====================================================================


class TestMrAtCookie:
    APP_ID = "app_123"
    COOKIE_NAME = "mr_at_app_123"

    def test_extracts_per_app_value(self):
        assert mr_at_cookie(f"{self.COOKIE_NAME}=abc123", self.APP_ID) == "abc123"

    def test_ignores_other_cookies_and_whitespace(self):
        assert mr_at_cookie(f"foo=1; {self.COOKIE_NAME}=abc; bar=2", self.APP_ID) == "abc"
        assert mr_at_cookie(f"  {self.COOKIE_NAME}=abc  ", self.APP_ID) == "abc"

    def test_handles_values_containing_eq(self):
        assert mr_at_cookie(f"{self.COOKIE_NAME}=eyJ.payload=xyz", self.APP_ID) == "eyJ.payload=xyz"

    def test_ignores_a_different_apps_cookie(self):
        assert mr_at_cookie("mr_at_app_other=abc", self.APP_ID) is None

    def test_returns_none_when_absent_or_empty(self):
        assert mr_at_cookie(None, self.APP_ID) is None
        assert mr_at_cookie("", self.APP_ID) is None
        assert mr_at_cookie("foo=1; bar=2", self.APP_ID) is None
        assert mr_at_cookie(f"{self.COOKIE_NAME}=", self.APP_ID) is None

    def test_joins_lists_into_one_cookie_string(self):
        assert mr_at_cookie(["foo=1", f"{self.COOKIE_NAME}=abc"], self.APP_ID) == "abc"


# =====================================================================
# verify_token (sync)
# =====================================================================


class TestVerifyTokenSync:
    def test_returns_sub_on_a_valid_token(self):
        priv, jwk, kid = _generate_keypair()
        tok = _sign(priv, kid, sub="user_xyz")
        with httpx.Client(transport=_jwks_transport({"keys": [jwk]})) as http:
            assert verify_token(tok, **VERIFY_OPTS, http_client=http) == "user_xyz"

    def test_returns_none_for_empty_token_no_network(self):
        captured: list[httpx.Request] = []
        with httpx.Client(transport=_jwks_transport({"keys": []}, captured)) as http:
            assert verify_token("", **VERIFY_OPTS, http_client=http) is None
        assert captured == []

    def test_returns_none_for_malformed_jwt(self):
        with httpx.Client(transport=_jwks_transport({"keys": []})) as http:
            assert verify_token("not.a.jwt", **VERIFY_OPTS, http_client=http) is None

    def test_returns_none_for_expired_token(self):
        priv, jwk, kid = _generate_keypair()
        payload = {
            "sub": "user_xyz",
            "iat": int(time.time()) - 3600,
            "exp": int(time.time()) - 1800,  # 30 min ago, well past 60s leeway
        }
        tok = jwt.encode(payload, priv, algorithm="ES256", headers={"kid": kid})
        with httpx.Client(transport=_jwks_transport({"keys": [jwk]})) as http:
            assert verify_token(tok, **VERIFY_OPTS, http_client=http) is None

    def test_returns_none_when_kid_not_in_jwks(self):
        priv, _jwk, kid = _generate_keypair()
        tok = _sign(priv, kid, sub="user_xyz")
        # JWKS doesn't include this kid.
        with httpx.Client(transport=_jwks_transport({"keys": []})) as http:
            assert verify_token(tok, **VERIFY_OPTS, http_client=http) is None

    def test_returns_none_when_signature_invalid(self):
        # JWKS publishes pub_A's key under kid_a. JWT carries kid_a in
        # its header but is signed with priv_B — verifier looks up
        # pub_A successfully, then signature verification fails.
        _priv_a, jwk_a, kid_a = _generate_keypair()
        priv_b, _jwk_b, _kid_b = _generate_keypair()
        tok = jwt.encode(
            {"sub": "user_xyz", "iat": int(time.time()), "exp": int(time.time()) + 300},
            priv_b,
            algorithm="ES256",
            headers={"kid": kid_a},
        )
        with httpx.Client(transport=_jwks_transport({"keys": [jwk_a]})) as http:
            assert verify_token(tok, **VERIFY_OPTS, http_client=http) is None

    def test_returns_none_when_sub_missing(self):
        priv, jwk, kid = _generate_keypair()
        payload = {"aud": "app_123", "iat": int(time.time()), "exp": int(time.time()) + 300}
        tok = jwt.encode(payload, priv, algorithm="ES256", headers={"kid": kid})
        with httpx.Client(transport=_jwks_transport({"keys": [jwk]})) as http:
            assert verify_token(tok, **VERIFY_OPTS, http_client=http) is None

    def test_rejects_token_minted_for_different_app(self):
        # Cross-app cookie ride-along: a token with aud=app_other must
        # not authenticate a request landing on the middleware configured
        # for app_123. Catches sibling-subdomain cookie reuse between two
        # ManyRows apps on the same eTLD.
        priv, jwk, kid = _generate_keypair()
        tok = _sign(priv, kid, aud="app_other")
        with httpx.Client(transport=_jwks_transport({"keys": [jwk]})) as http:
            assert verify_token(tok, **VERIFY_OPTS, http_client=http) is None

    def test_strips_trailing_slash_on_base_url(self):
        priv, jwk, kid = _generate_keypair()
        tok = _sign(priv, kid)
        captured: list[httpx.Request] = []
        with httpx.Client(transport=_jwks_transport({"keys": [jwk]}, captured)) as http:
            verify_token(
                tok,
                base_url="https://app.manyrows.com/",
                workspace_slug="acme",
                app_id="app_123",
                http_client=http,
            )
        assert (
            str(captured[0].url) == "https://app.manyrows.com/.well-known/jwks.json"
        )


# =====================================================================
# verify_token_async
# =====================================================================


class TestVerifyTokenAsync:
    async def test_returns_sub_on_a_valid_token(self):
        priv, jwk, kid = _generate_keypair()
        tok = _sign(priv, kid, sub="user_xyz")
        async with httpx.AsyncClient(transport=_jwks_transport({"keys": [jwk]})) as http:
            assert (
                await verify_token_async(tok, **VERIFY_OPTS, http_client=http) == "user_xyz"
            )

    async def test_returns_none_for_empty_token_no_network(self):
        captured: list[httpx.Request] = []
        async with httpx.AsyncClient(
            transport=_jwks_transport({"keys": []}, captured)
        ) as http:
            assert await verify_token_async("", **VERIFY_OPTS, http_client=http) is None
        assert captured == []

    async def test_returns_none_when_kid_not_in_jwks(self):
        priv, _, kid = _generate_keypair()
        tok = _sign(priv, kid)
        async with httpx.AsyncClient(transport=_jwks_transport({"keys": []})) as http:
            assert await verify_token_async(tok, **VERIFY_OPTS, http_client=http) is None
