"""Tests for the full-BFF surface (BffClient + PublicProxy + OAuthCallbackHtml)."""

from __future__ import annotations

import base64
import re

import httpx
import pytest

from manyrows import (
    BffClient,
    BffError,
    ClientContext,
    OAuthCallbackHtml,
    PublicProxy,
    dispatch_oauth_callback,
)
from manyrows.bff import _append_query

from .conftest import make_transport

BASE = "https://app.manyrows.com"
CID = "client_abc"
CSECRET = "secret_xyz"
EXPECTED_BASIC = "Basic " + base64.b64encode(f"{CID}:{CSECRET}".encode()).decode()


def _new_bff(transport: httpx.MockTransport) -> BffClient:
    return BffClient(
        base_url=BASE,
        client_id=CID,
        client_secret=CSECRET,
        http_client=httpx.Client(transport=transport),
    )


# ===== BffClient constructor =====


class TestBffClientConstructor:
    def test_rejects_empty_args(self) -> None:
        with pytest.raises(ValueError):
            BffClient(base_url="", client_id=CID, client_secret=CSECRET)
        with pytest.raises(ValueError):
            BffClient(base_url=BASE, client_id="", client_secret=CSECRET)
        with pytest.raises(ValueError):
            BffClient(base_url=BASE, client_id=CID, client_secret="")

    def test_strips_trailing_slashes_on_base_url(self) -> None:
        transport, captured = make_transport(
            [{"json": {"sessionId": "s", "userId": "u", "expiresAt": "x"}}]
        )
        bff = BffClient(
            base_url=BASE + "//",
            client_id=CID,
            client_secret=CSECRET,
            http_client=httpx.Client(transport=transport),
        )
        bff.login_password("a@b.com", "pw", False)
        assert str(captured[0].url) == BASE + "/bff/login"


# ===== Login flows =====


class TestLoginPassword:
    def test_posts_with_basic_auth_and_forwarded_headers(self) -> None:
        transport, captured = make_transport(
            [
                {
                    "json": {
                        "sessionId": "sess_1",
                        "userId": "u_1",
                        "expiresAt": "2030-01-01T00:00:00Z",
                    }
                }
            ]
        )
        bff = _new_bff(transport)
        s = bff.login_password(
            "a@b.com",
            "pw",
            True,
            ClientContext(client_ip="1.2.3.4", client_user_agent="Mozilla"),
        )

        assert s.session_id == "sess_1"
        assert s.user_id == "u_1"
        assert s.totp_required is None

        req = captured[0]
        assert str(req.url) == BASE + "/bff/login"
        assert req.method == "POST"
        assert req.headers["Authorization"] == EXPECTED_BASIC
        assert req.headers["X-BFF-Client-IP"] == "1.2.3.4"
        assert req.headers["X-BFF-Client-User-Agent"] == "Mozilla"

    def test_surfaces_totp_required_branch(self) -> None:
        transport, _ = make_transport(
            [{"json": {"totpRequired": True, "challengeToken": "ct_xyz"}}]
        )
        s = _new_bff(transport).login_password("a@b.com", "pw", False)
        assert s.totp_required is True
        assert s.challenge_token == "ct_xyz"
        assert s.session_id is None

    def test_omits_forwarded_headers_when_absent(self) -> None:
        transport, captured = make_transport(
            [{"json": {"sessionId": "s", "userId": "u", "expiresAt": "x"}}]
        )
        _new_bff(transport).login_password("a@b.com", "pw", False)
        req = captured[0]
        assert "X-BFF-Client-IP" not in req.headers
        assert "X-BFF-Client-User-Agent" not in req.headers


class TestVerifyOtp:
    def test_omits_app_id_when_none(self) -> None:
        transport, captured = make_transport(
            [{"json": {"sessionId": "s", "userId": "u", "expiresAt": "x"}}]
        )
        _new_bff(transport).verify_otp("a@b.com", "123456", None, False)
        body = captured[0].content.decode()
        assert "appId" not in body

    def test_includes_app_id_and_decodes_password_already_set(self) -> None:
        transport, captured = make_transport(
            [
                {
                    "json": {
                        "sessionId": "s",
                        "userId": "u",
                        "expiresAt": "x",
                        "passwordAlreadySet": True,
                    }
                }
            ]
        )
        s = _new_bff(transport).verify_otp("a@b.com", "123456", "app_42", True)
        assert s.password_already_set is True
        body = captured[0].content.decode()
        assert "app_42" in body


# ===== Proxy =====


class TestProxy:
    def test_get_adds_session_header_and_basic_auth(self) -> None:
        transport, captured = make_transport([{"json": {"ok": True}}])
        bff = _new_bff(transport)
        r = bff.proxy_get(
            "sess_42",
            "/me",
            ClientContext(client_ip="1.2.3.4", client_user_agent="Mozilla"),
        )
        assert r.status == 200
        assert r.body == '{"ok":true}'

        req = captured[0]
        assert str(req.url) == BASE + "/bff/proxy/me"
        assert req.headers["X-BFF-Session-ID"] == "sess_42"
        assert req.headers["Authorization"] == EXPECTED_BASIC

    def test_post_sets_content_type_when_body_provided(self) -> None:
        transport, captured = make_transport([{"json": {"ok": True}}])
        _new_bff(transport).proxy_post("sess", "/setups", '{"name":"x"}')
        req = captured[0]
        assert req.headers["Content-Type"] == "application/json"
        assert req.content.decode() == '{"name":"x"}'

    def test_rejects_empty_session_id(self) -> None:
        transport, _ = make_transport([])
        with pytest.raises(ValueError, match="session_id"):
            _new_bff(transport).proxy_get("", "/me")


# ===== Logout =====


class TestLogout:
    def test_posts_session_id(self) -> None:
        transport, captured = make_transport([{"json": {}}])
        _new_bff(transport).logout("sess_99")
        req = captured[0]
        assert str(req.url) == BASE + "/bff/logout"
        assert "sess_99" in req.content.decode()


# ===== Errors =====


class TestErrors:
    def test_wraps_non_2xx_as_bff_error(self) -> None:
        transport, _ = make_transport(
            [{"status": 401, "json": {"error": "error.invalidCredentials"}}]
        )
        with pytest.raises(BffError) as exc_info:
            _new_bff(transport).login_password("a@b.com", "wrong", False)
        assert exc_info.value.status == 401
        assert "invalidCredentials" in exc_info.value.body  # type: ignore[arg-type]

    def test_wraps_network_errors_as_bff_error(self) -> None:
        transport, _ = make_transport([{"error": httpx.ConnectError("connection refused")}])
        with pytest.raises(BffError):
            _new_bff(transport).login_password("a@b.com", "pw", False)


# ===== PublicProxy =====


class TestPublicProxyAppBootGet:
    def test_builds_expected_upstream_url_with_no_basic_auth(self) -> None:
        transport, captured = make_transport([{"json": {"name": "X"}}])
        pp = PublicProxy(
            base_url=BASE,
            workspace_slug="acme",
            http_client=httpx.Client(transport=transport),
        )
        r = pp.app_boot_get("app_42")
        assert r.status == 200
        assert r.body == '{"name":"X"}'

        req = captured[0]
        assert str(req.url) == BASE + "/x/acme/apps/app_42"
        assert req.method == "GET"
        assert "Authorization" not in req.headers

    def test_rejects_empty_app_id(self) -> None:
        transport, _ = make_transport([])
        pp = PublicProxy(
            base_url=BASE,
            workspace_slug="acme",
            http_client=httpx.Client(transport=transport),
        )
        with pytest.raises(ValueError):
            pp.app_boot_get("")


class TestPublicProxyAuthForward:
    def _newpp(self, transport: httpx.MockTransport) -> PublicProxy:
        return PublicProxy(
            base_url=BASE,
            workspace_slug="acme",
            http_client=httpx.Client(transport=transport),
        )

    def test_posts_to_full_suffix_with_query_string(self) -> None:
        transport, captured = make_transport([{"json": {}}])
        self._newpp(transport).auth_forward(
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
        assert req.headers["Content-Type"] == "application/json"

    def test_supports_bare_auth_path_for_otp_send(self) -> None:
        transport, captured = make_transport([{"json": {}}])
        self._newpp(transport).auth_forward(
            "app_42", "POST", "", None, '{"email":"a@b.com"}', "application/json"
        )
        assert str(captured[0].url) == BASE + "/x/acme/apps/app_42/auth"

    def test_normalises_missing_leading_slash(self) -> None:
        transport, captured = make_transport([{"json": {}}])
        self._newpp(transport).auth_forward(
            "app_42", "GET", "google/authorize", None, None, None
        )
        assert str(captured[0].url) == BASE + "/x/acme/apps/app_42/auth/google/authorize"

    def test_preserves_upstream_non_2xx(self) -> None:
        transport, _ = make_transport(
            [{"status": 409, "json": {"error": "error.emailAlreadyRegistered"}}]
        )
        r = self._newpp(transport).auth_forward(
            "app_42",
            "POST",
            "/register",
            None,
            '{"email":"a@b.com"}',
            "application/json",
        )
        assert r.status == 409
        assert "emailAlreadyRegistered" in r.body


# ===== OAuthCallbackHtml =====


class TestOAuthCallbackHtmlSuccess:
    def test_includes_ok_and_user_id_omits_setup_when_false(self) -> None:
        html = OAuthCallbackHtml.success("u_42", False, "/")
        assert '"ok":true' in html
        assert '"userId":"u_42"' in html
        assert "totpSetupRequired" not in html
        assert 'redirectURL = "/"' in html

    def test_flags_totp_setup_required_when_true(self) -> None:
        html = OAuthCallbackHtml.success("u_42", True, "/welcome")
        assert '"totpSetupRequired":true' in html

    def test_omits_user_id_when_none(self) -> None:
        html = OAuthCallbackHtml.success(None, False, "/")
        assert '"ok":true' in html
        assert "userId" not in html


class TestOAuthCallbackHtmlTotp:
    def test_appends_challenge_token_to_redirect_url(self) -> None:
        html = OAuthCallbackHtml.totp("ct_abc", "/login/totp", "/login?failed=1")
        assert '"totpRequired":true' in html
        assert '"challengeToken":"ct_abc"' in html
        assert "/login/totp?challengeToken=ct_abc" in html

    def test_falls_back_to_error_when_totp_url_missing(self) -> None:
        html = OAuthCallbackHtml.totp("ct_abc", "", "/login?failed=1")
        assert "totp_redirect_not_configured" in html
        assert "/login?failed=1&error=totp_redirect_not_configured" in html


class TestOAuthCallbackHtmlError:
    def test_encodes_code_into_query(self) -> None:
        html = OAuthCallbackHtml.error("exchange_failed", "/login?failed=1")
        assert '"error":"exchange_failed"' in html
        assert "/login?failed=1&error=exchange_failed" in html

    def test_starts_query_when_redirect_has_none(self) -> None:
        html = OAuthCallbackHtml.error("missing_code", "/login")
        assert "/login?error=missing_code" in html

    def test_renders_without_redirect_when_url_empty(self) -> None:
        html = OAuthCallbackHtml.error("missing_code", "")
        assert '"error":"missing_code"' in html
        assert 'redirectURL = ""' in html


class TestOAuthCallbackHtmlStructure:
    def test_is_popup_aware(self) -> None:
        html = OAuthCallbackHtml.success("u_42", False, "/")
        assert "if (window.opener)" in html
        assert "window.location.replace" in html
        assert "manyrows-oauth-callback" in html
        assert "window.close()" in html

    def test_defuses_script_injection_in_payload(self) -> None:
        # An error code containing </script> would terminate our inline
        # <script> block if not escaped. The </ → <\/ replacement on
        # payload + < → < in JS strings keeps the only </script>
        # in the source the legitimate closing tag.
        html = OAuthCallbackHtml.error(
            "</script><script>alert(1)</script>", "/oops"
        )
        closes = len(re.findall(r"</script>", html))
        assert closes == 1, f"expected exactly one </script> tag, found {closes}"


class TestAppendQuery:
    def test_picks_right_separator(self) -> None:
        assert _append_query("/x", "a", "b") == "/x?a=b"
        assert _append_query("/x?y=1", "a", "b") == "/x?y=1&a=b"

    def test_url_encodes_value(self) -> None:
        # quote(safe='') uses %20 for spaces (RFC 3986).
        assert _append_query("/x", "a", "hello world") == "/x?a=hello%20world"


# ===== dispatch_oauth_callback =====


REDIRECT = "https://yourapp.com/auth/oauth/callback"
SUCCESS = "/"
ERR = "/login?failed=1"
TOTP = "/login/totp"


class TestDispatchOAuthCallback:
    def test_error_branch_short_circuits(self) -> None:
        transport, captured = make_transport([])  # no upstream call expected
        bff = _new_bff(transport)
        out = dispatch_oauth_callback(
            query={"error": "provider_exchange_failed"},
            bff=bff,
            redirect_uri=REDIRECT,
            success_redirect=SUCCESS,
            error_redirect=ERR,
        )
        assert out.kind == "error"
        assert out.error == "provider_exchange_failed"
        assert "provider_exchange_failed" in out.html
        assert captured == []

    def test_challenge_required_short_circuits(self) -> None:
        transport, captured = make_transport([])
        bff = _new_bff(transport)
        out = dispatch_oauth_callback(
            query={"challengeRequired": "1", "challengeToken": "ct_abc", "state": "s"},
            bff=bff,
            redirect_uri=REDIRECT,
            success_redirect=SUCCESS,
            error_redirect=ERR,
            totp_redirect=TOTP,
        )
        assert out.kind == "totp"
        assert out.challenge_token == "ct_abc"
        assert '"totpRequired":true' in out.html
        assert "/login/totp?challengeToken=ct_abc" in out.html
        assert captured == []

    def test_missing_code_when_query_empty(self) -> None:
        transport, _ = make_transport([])
        bff = _new_bff(transport)
        out = dispatch_oauth_callback(
            query={},
            bff=bff,
            redirect_uri=REDIRECT,
            success_redirect=SUCCESS,
            error_redirect=ERR,
        )
        assert out.kind == "error"
        assert out.error == "missing_code"

    def test_success_returns_session_and_html(self) -> None:
        transport, _ = make_transport(
            [
                {
                    "json": {
                        "sessionId": "sess_123",
                        "userId": "u_42",
                        "expiresAt": "2030-01-01T00:00:00Z",
                    }
                }
            ]
        )
        bff = _new_bff(transport)
        out = dispatch_oauth_callback(
            query={"code": "abc123", "state": "s"},
            bff=bff,
            redirect_uri=REDIRECT,
            success_redirect=SUCCESS,
            error_redirect=ERR,
        )
        assert out.kind == "success"
        assert out.session is not None
        assert out.session.session_id == "sess_123"
        assert '"userId":"u_42"' in out.html

    def test_post_exchange_totp_required(self) -> None:
        transport, _ = make_transport(
            [{"json": {"totpRequired": True, "challengeToken": "ct_xyz"}}]
        )
        bff = _new_bff(transport)
        out = dispatch_oauth_callback(
            query={"code": "abc123"},
            bff=bff,
            redirect_uri=REDIRECT,
            success_redirect=SUCCESS,
            error_redirect=ERR,
            totp_redirect=TOTP,
        )
        assert out.kind == "totp"
        assert out.challenge_token == "ct_xyz"

    def test_exchange_error_surfaces_upstream_code(self) -> None:
        transport, _ = make_transport(
            [{"status": 401, "json": {"error": "exchange_token_invalid"}}]
        )
        bff = _new_bff(transport)
        out = dispatch_oauth_callback(
            query={"code": "abc123"},
            bff=bff,
            redirect_uri=REDIRECT,
            success_redirect=SUCCESS,
            error_redirect=ERR,
        )
        assert out.kind == "error"
        assert out.error == "exchange_token_invalid"

    def test_exchange_error_falls_back_when_body_isnt_json(self) -> None:
        transport, _ = make_transport([{"status": 500, "text": "not json"}])
        bff = _new_bff(transport)
        out = dispatch_oauth_callback(
            query={"code": "abc123"},
            bff=bff,
            redirect_uri=REDIRECT,
            success_redirect=SUCCESS,
            error_redirect=ERR,
        )
        assert out.kind == "error"
        assert out.error == "exchange_failed"
