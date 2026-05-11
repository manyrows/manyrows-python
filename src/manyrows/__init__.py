"""Official Python SDK for the ManyRows Server API."""

from manyrows.auth import bearer_token, mr_at_cookie, verify_token, verify_token_async
from manyrows.client import (
    AsyncClient,
    Client,
    ConfigItem,
    Delivery,
    DeliveryConfig,
    DeliveryFlags,
    FeatureFlag,
    ManyRowsError,
    Member,
    MembersResult,
    PermissionResult,
    User,
    UserField,
    UserFieldValue,
    UserResult,
)
from manyrows.secrets import SecretsError, compute_public_jwk_fingerprint, decrypt_secret
from manyrows.webhook import WebhookError, verify_webhook

__all__ = [
    "AsyncClient",
    "Client",
    "ConfigItem",
    "Delivery",
    "DeliveryConfig",
    "DeliveryFlags",
    "FeatureFlag",
    "ManyRowsError",
    "Member",
    "MembersResult",
    "PermissionResult",
    "SecretsError",
    "User",
    "UserField",
    "UserFieldValue",
    "UserResult",
    "WebhookError",
    "bearer_token",
    "compute_public_jwk_fingerprint",
    "decrypt_secret",
    "mr_at_cookie",
    "verify_token",
    "verify_token_async",
    "verify_webhook",
]

__version__ = "1.0.0"
