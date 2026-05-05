"""ManyRows Server API client. Mirrors the surface of manyrows-go / manyrows-node."""

from __future__ import annotations

from dataclasses import dataclass, field
from types import TracebackType
from typing import Any

import httpx

_USER_AGENT = "manyrows-python/1.0"


class ManyRowsError(Exception):
    """Raised for any non-2xx response from the ManyRows API.

    Inspect ``status`` and ``body`` to distinguish auth failures (401),
    rate limits (429), server errors (5xx), etc.
    """

    def __init__(self, message: str, status: int | None = None, body: str | None = None):
        super().__init__(message)
        self.status = status
        self.body = body


# ===== Delivery =====


@dataclass
class ConfigItem:
    key: str
    type: str
    value: Any = None
    is_set: bool | None = None
    # For ``secrets`` only: the encrypted envelope, as returned by the
    # server-API delivery endpoint. Pass to ``manyrows.secrets.decrypt_secret``
    # along with your workspace private JWK to recover the plaintext.
    # Only set when ``is_set`` is True.
    envelope: dict[str, Any] | None = None


@dataclass
class FeatureFlag:
    key: str
    enabled: bool


@dataclass
class DeliveryConfig:
    public: list[ConfigItem] = field(default_factory=list)
    private: list[ConfigItem] = field(default_factory=list)
    secrets: list[ConfigItem] = field(default_factory=list)


@dataclass
class DeliveryFlags:
    client: list[FeatureFlag] = field(default_factory=list)
    server: list[FeatureFlag] = field(default_factory=list)


@dataclass
class Delivery:
    workspace_id: str
    project_id: str
    app_id: str
    updated_at: str
    config: DeliveryConfig
    flags: DeliveryFlags


# ===== Permissions =====


@dataclass
class PermissionResult:
    allowed: bool
    permission: str
    account_id: str


# ===== Members =====


@dataclass
class Member:
    user_id: str
    email: str
    enabled: bool
    source: str
    added_at: str
    roles: list[str] = field(default_factory=list)
    name: str | None = None
    email_verified_at: str | None = None
    password_set_at: str | None = None
    last_login_at: str | None = None


@dataclass
class MembersResult:
    members: list[Member]
    total: int
    page: int
    page_size: int


# ===== Users =====


@dataclass
class User:
    id: str
    email: str
    enabled: bool
    source: str
    email_verified_at: str | None = None
    password_set_at: str | None = None
    totp_enabled: bool | None = None


@dataclass
class UserFieldValue:
    id: str
    user_field_id: str
    value: Any
    updated_at: str
    project_id: str | None = None
    user_id: str | None = None
    updated_by: str | None = None


@dataclass
class UserResult:
    user: User
    roles: list[str] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)
    fields: list[UserFieldValue] = field(default_factory=list)


# ===== User Fields =====


@dataclass
class UserField:
    id: str
    key: str
    value_type: str
    status: str
    label: str | None = None
    visibility: str | None = None


# ===== Parsers (camelCase wire format -> snake_case dataclasses) =====


def _parse_config_item(d: dict[str, Any]) -> ConfigItem:
    return ConfigItem(
        key=d["key"],
        type=d["type"],
        value=d.get("value"),
        is_set=d.get("isSet"),
        envelope=d.get("envelope"),
    )


def _parse_feature_flag(d: dict[str, Any]) -> FeatureFlag:
    return FeatureFlag(key=d["key"], enabled=d["enabled"])


def _parse_delivery(d: dict[str, Any]) -> Delivery:
    cfg = d.get("config") or {}
    flags = d.get("flags") or {}
    return Delivery(
        workspace_id=d["workspaceId"],
        project_id=d["projectId"],
        app_id=d["appId"],
        updated_at=d["updatedAt"],
        config=DeliveryConfig(
            public=[_parse_config_item(c) for c in cfg.get("public") or []],
            private=[_parse_config_item(c) for c in cfg.get("private") or []],
            secrets=[_parse_config_item(c) for c in cfg.get("secrets") or []],
        ),
        flags=DeliveryFlags(
            client=[_parse_feature_flag(f) for f in flags.get("client") or []],
            server=[_parse_feature_flag(f) for f in flags.get("server") or []],
        ),
    )


def _parse_permission_result(d: dict[str, Any]) -> PermissionResult:
    return PermissionResult(
        allowed=bool(d.get("allowed")),
        permission=d.get("permission", ""),
        account_id=d.get("accountId", ""),
    )


def _parse_member(d: dict[str, Any]) -> Member:
    return Member(
        user_id=d["userId"],
        email=d["email"],
        enabled=bool(d.get("enabled", True)),
        source=d.get("source", ""),
        added_at=d.get("addedAt", ""),
        roles=list(d.get("roles") or []),
        name=d.get("name"),
        email_verified_at=d.get("emailVerifiedAt"),
        password_set_at=d.get("passwordSetAt"),
        last_login_at=d.get("lastLoginAt"),
    )


def _parse_members_result(d: dict[str, Any]) -> MembersResult:
    return MembersResult(
        members=[_parse_member(m) for m in d.get("members") or []],
        total=int(d.get("total", 0)),
        page=int(d.get("page", 0)),
        page_size=int(d.get("pageSize", 0)),
    )


def _parse_user(d: dict[str, Any]) -> User:
    return User(
        id=d["id"],
        email=d["email"],
        enabled=bool(d.get("enabled", True)),
        source=d.get("source", ""),
        email_verified_at=d.get("emailVerifiedAt"),
        password_set_at=d.get("passwordSetAt"),
        totp_enabled=d.get("totpEnabled"),
    )


def _parse_user_field_value(d: dict[str, Any]) -> UserFieldValue:
    return UserFieldValue(
        id=d["id"],
        user_field_id=d["userFieldId"],
        value=d.get("value"),
        updated_at=d.get("updatedAt", ""),
        project_id=d.get("projectId"),
        user_id=d.get("userId"),
        updated_by=d.get("updatedBy"),
    )


def _parse_user_result(d: dict[str, Any]) -> UserResult:
    return UserResult(
        user=_parse_user(d["user"]),
        roles=list(d.get("roles") or []),
        permissions=list(d.get("permissions") or []),
        fields=[_parse_user_field_value(f) for f in d.get("fields") or []],
    )


def _parse_user_field(d: dict[str, Any]) -> UserField:
    return UserField(
        id=d["id"],
        key=d["key"],
        value_type=d["valueType"],
        status=d["status"],
        label=d.get("label"),
        visibility=d.get("visibility"),
    )


# ===== Sync Client =====


def _validate_opts(base_url: str, workspace_slug: str, app_id: str, api_key: str) -> None:
    if not base_url:
        raise ValueError("manyrows: base_url is required")
    if not workspace_slug:
        raise ValueError("manyrows: workspace_slug is required")
    if not app_id:
        raise ValueError("manyrows: app_id is required")
    if not api_key:
        raise ValueError("manyrows: api_key is required")


def _strip_trailing_slashes(s: str) -> str:
    return s.rstrip("/")


def _raise_for_status(res: httpx.Response) -> None:
    if not res.is_success:
        body = res.text
        raise ManyRowsError(
            f"manyrows: {body or res.reason_phrase} (status {res.status_code})",
            status=res.status_code,
            body=body,
        )


class Client:
    """Synchronous client for the ManyRows Server API.

    Construct once and reuse; the underlying ``httpx.Client`` pools connections.
    Supports use as a context manager:

        with Client(...) as c:
            user = c.get_user("u_1")
    """

    def __init__(
        self,
        base_url: str,
        workspace_slug: str,
        app_id: str,
        api_key: str,
        *,
        http_client: httpx.Client | None = None,
    ):
        _validate_opts(base_url, workspace_slug, app_id, api_key)

        self._base_url = _strip_trailing_slashes(base_url)
        self._workspace_slug = workspace_slug
        self._app_id = app_id
        self._api_key = api_key
        self._owns_http = http_client is None
        self._http = http_client if http_client is not None else httpx.Client(timeout=10.0)

    def _api_url(self, path: str) -> str:
        return (
            f"{self._base_url}/x/{self._workspace_slug}/api/apps/{self._app_id}{path}"
        )

    def _get_json(self, url: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            res = self._http.get(
                url,
                params=params,
                headers={"X-API-Key": self._api_key, "User-Agent": _USER_AGENT},
            )
        except httpx.HTTPError as exc:
            raise ManyRowsError(f"manyrows: request failed: {exc}") from exc

        _raise_for_status(res)

        try:
            data = res.json()
        except ValueError as exc:
            raise ManyRowsError(f"manyrows: failed to decode response: {exc}") from exc

        if not isinstance(data, dict):
            raise ManyRowsError("manyrows: unexpected response shape (not an object)")
        return data

    # === Lifecycle ===

    def close(self) -> None:
        if self._owns_http:
            self._http.close()

    def __enter__(self) -> Client:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    # === Delivery ===

    def get_delivery(self) -> Delivery:
        """Returns config keys + feature flags for this app."""
        return _parse_delivery(self._get_json(self._api_url("/")))

    # === Permissions ===

    def check_permission(self, account_id: str, permission: str) -> PermissionResult:
        """Checks whether a user has a specific permission."""
        return _parse_permission_result(
            self._get_json(
                self._api_url("/check-permission"),
                params={"accountId": account_id, "permission": permission},
            )
        )

    def has_permission(self, account_id: str, permission: str) -> bool:
        """Convenience: returns just the boolean from ``check_permission``."""
        return self.check_permission(account_id, permission).allowed

    # === Members ===

    def list_members(
        self,
        page: int = 0,
        page_size: int = 50,
        email: str | None = None,
    ) -> MembersResult:
        """Returns paginated members for the app. Pass ``email`` to filter (substring match)."""
        params: dict[str, Any] = {"page": page, "pageSize": page_size}
        if email:
            params["email"] = email
        return _parse_members_result(self._get_json(self._api_url("/members"), params=params))

    def list_members_by_email(
        self, email: str, page: int = 0, page_size: int = 50
    ) -> MembersResult:
        """Convenience for ``list_members(email=..., page=..., page_size=...)``."""
        return self.list_members(page=page, page_size=page_size, email=email)

    # === Users ===

    def get_user(self, user_id: str) -> UserResult:
        """Look up a user by ID."""
        return _parse_user_result(
            self._get_json(self._api_url("/users"), params={"id": user_id})
        )

    def get_user_by_email(self, email: str) -> UserResult:
        """Look up a user by email within the app's auth scope."""
        return _parse_user_result(
            self._get_json(self._api_url("/users"), params={"email": email})
        )

    # === User Fields ===

    def list_user_fields(self) -> list[UserField]:
        """Returns all user field definitions for the app."""
        data = self._get_json(self._api_url("/user-fields"))
        items = data.get("userFields") or []
        return [_parse_user_field(f) for f in items]


# ===== Async Client =====


class AsyncClient:
    """Asynchronous client for the ManyRows Server API.

    Construct once and reuse. Supports use as an async context manager:

        async with AsyncClient(...) as c:
            user = await c.get_user("u_1")
    """

    def __init__(
        self,
        base_url: str,
        workspace_slug: str,
        app_id: str,
        api_key: str,
        *,
        http_client: httpx.AsyncClient | None = None,
    ):
        _validate_opts(base_url, workspace_slug, app_id, api_key)

        self._base_url = _strip_trailing_slashes(base_url)
        self._workspace_slug = workspace_slug
        self._app_id = app_id
        self._api_key = api_key
        self._owns_http = http_client is None
        self._http = (
            http_client if http_client is not None else httpx.AsyncClient(timeout=10.0)
        )

    def _api_url(self, path: str) -> str:
        return (
            f"{self._base_url}/x/{self._workspace_slug}/api/apps/{self._app_id}{path}"
        )

    async def _get_json(
        self, url: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        try:
            res = await self._http.get(
                url,
                params=params,
                headers={"X-API-Key": self._api_key, "User-Agent": _USER_AGENT},
            )
        except httpx.HTTPError as exc:
            raise ManyRowsError(f"manyrows: request failed: {exc}") from exc

        _raise_for_status(res)

        try:
            data = res.json()
        except ValueError as exc:
            raise ManyRowsError(f"manyrows: failed to decode response: {exc}") from exc

        if not isinstance(data, dict):
            raise ManyRowsError("manyrows: unexpected response shape (not an object)")
        return data

    # === Lifecycle ===

    async def aclose(self) -> None:
        if self._owns_http:
            await self._http.aclose()

    async def __aenter__(self) -> AsyncClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    # === Delivery ===

    async def get_delivery(self) -> Delivery:
        return _parse_delivery(await self._get_json(self._api_url("/")))

    # === Permissions ===

    async def check_permission(self, account_id: str, permission: str) -> PermissionResult:
        return _parse_permission_result(
            await self._get_json(
                self._api_url("/check-permission"),
                params={"accountId": account_id, "permission": permission},
            )
        )

    async def has_permission(self, account_id: str, permission: str) -> bool:
        r = await self.check_permission(account_id, permission)
        return r.allowed

    # === Members ===

    async def list_members(
        self,
        page: int = 0,
        page_size: int = 50,
        email: str | None = None,
    ) -> MembersResult:
        params: dict[str, Any] = {"page": page, "pageSize": page_size}
        if email:
            params["email"] = email
        return _parse_members_result(
            await self._get_json(self._api_url("/members"), params=params)
        )

    async def list_members_by_email(
        self, email: str, page: int = 0, page_size: int = 50
    ) -> MembersResult:
        return await self.list_members(page=page, page_size=page_size, email=email)

    # === Users ===

    async def get_user(self, user_id: str) -> UserResult:
        return _parse_user_result(
            await self._get_json(self._api_url("/users"), params={"id": user_id})
        )

    async def get_user_by_email(self, email: str) -> UserResult:
        return _parse_user_result(
            await self._get_json(self._api_url("/users"), params={"email": email})
        )

    # === User Fields ===

    async def list_user_fields(self) -> list[UserField]:
        data = await self._get_json(self._api_url("/user-fields"))
        items = data.get("userFields") or []
        return [_parse_user_field(f) for f in items]
