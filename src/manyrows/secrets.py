"""Decrypt ManyRows config-secret envelopes server-side.

Usage::

    from manyrows import Client
    from manyrows.secrets import decrypt_secret
    import json, os

    private_key_jwk = json.loads(os.environ["MANYROWS_WORKSPACE_PRIVATE_KEY"])
    delivery = client.get_delivery()

    for sec in delivery.config.secrets:
        if not sec.is_set or not sec.envelope:
            continue
        plaintext = decrypt_secret(sec.envelope, private_key_jwk)
        # plaintext is bytes of the JSON-encoded value. For a string
        # secret you'll get b'"hello"' (with quotes) — json.loads to recover.
        value = json.loads(plaintext.decode("utf-8"))

Algorithm: ECDH P-256 -> HKDF-SHA256 (salt "manyrows:secrets:v1",
info "workspace-fingerprint:<hex>") -> AES-256-GCM. Mirrors the
browser-side encrypt path in the ManyRows admin UI; if those
constants change, update them here too.

Requires the optional ``cryptography`` package::

    pip install 'manyrows[secrets]'
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

_HKDF_SALT = b"manyrows:secrets:v1"
_HKDF_INFO_PREFIX = "workspace-fingerprint:"
_EXPECTED_ALGORITHM = "ECDH-P256+HKDF-SHA256+AES-256-GCM"
_EXPECTED_VERSION = 1


class SecretsError(Exception):
    """Raised on any decryption failure or malformed envelope."""


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def decrypt_secret(envelope: Any, private_key_jwk: dict[str, str]) -> bytes:
    """Decrypt a secret envelope using the workspace private JWK.

    Returns the JSON-encoded plaintext exactly as the browser stored
    it (i.e. for a string-typed secret you get ``b'"hello"'`` with the
    quotes — ``json.loads(plaintext.decode("utf-8"))`` recovers the
    typed value).

    Raises ``SecretsError`` on any mismatch: malformed envelope, wrong
    algorithm version, base64 decode failures, missing key fields,
    GCM authentication failure (which covers both ciphertext tamper
    and wrong-key cases).
    """
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
    except ImportError as e:  # pragma: no cover
        raise SecretsError(
            "manyrows secrets: the 'cryptography' package is required. "
            "Install with: pip install 'manyrows[secrets]'"
        ) from e

    env = _parse_envelope(envelope)

    if env["v"] != _EXPECTED_VERSION:
        raise SecretsError(f"manyrows secrets: unsupported envelope version {env['v']}")
    if env["alg"] != _EXPECTED_ALGORITHM:
        raise SecretsError(f"manyrows secrets: unsupported algorithm {env['alg']!r}")
    fingerprint = env["fingerprintSha256"]
    if not fingerprint:
        raise SecretsError("manyrows secrets: missing fingerprintSha256")

    private_key = _load_private_key(private_key_jwk, ec)
    ephemeral_public = _load_ephemeral_public_key(env["ephemeralPublicKeyJwk"], ec)

    shared = private_key.exchange(ec.ECDH(), ephemeral_public)

    info = (_HKDF_INFO_PREFIX + fingerprint).encode("utf-8")
    aes_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=_HKDF_SALT, info=info).derive(shared)

    try:
        iv = base64.b64decode(env["ivB64"])
    except Exception as e:
        raise SecretsError("manyrows secrets: ivB64 base64 decode failed") from e
    if len(iv) < 12:
        raise SecretsError("manyrows secrets: ivB64 too short")

    try:
        ct = base64.b64decode(env["ciphertextB64"])
    except Exception as e:
        raise SecretsError("manyrows secrets: ciphertextB64 base64 decode failed") from e
    # GCM tag is 16 bytes; anything shorter can't possibly contain ciphertext + tag.
    if len(ct) < 16:
        raise SecretsError("manyrows secrets: ciphertextB64 too short")

    # WebCrypto AES-GCM appends the 16-byte tag at the end of the
    # ciphertext; cryptography's AESGCM expects that same layout.
    try:
        return AESGCM(aes_key).decrypt(iv, ct, None)
    except Exception as e:
        # Wrong key, tampered ciphertext, fingerprint mismatch all land here.
        # Don't leak which.
        raise SecretsError(
            "manyrows secrets: decrypt failed (signature mismatch or wrong key)"
        ) from e


def compute_public_jwk_fingerprint(public_jwk: dict[str, str]) -> str:
    """Compute the canonical SHA-256 fingerprint of a public JWK.

    Sorted keys: crv, kty, x, y -> SHA-256 hex. Useful for verifying
    the fingerprint shown in the admin UI matches the JWK you have on
    disk. Not required for normal decryption.
    """
    canonical = json.dumps(
        {
            "crv": public_jwk["crv"],
            "kty": public_jwk["kty"],
            "x": public_jwk["x"],
            "y": public_jwk["y"],
        },
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _parse_envelope(raw: Any) -> dict[str, Any]:
    if isinstance(raw, str):
        try:
            env = json.loads(raw)
        except Exception as e:
            raise SecretsError("manyrows secrets: malformed envelope JSON") from e
    else:
        env = raw
    if not isinstance(env, dict):
        raise SecretsError("manyrows secrets: envelope must be an object or JSON string")
    for key in ("v", "alg", "fingerprintSha256", "ephemeralPublicKeyJwk", "ivB64", "ciphertextB64"):
        if key not in env:
            raise SecretsError(f"manyrows secrets: missing {key}")
    return env


def _load_private_key(jwk: dict[str, str], ec: Any) -> Any:
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise SecretsError("manyrows secrets: private key must be EC P-256 JWK")
    try:
        d = _b64url_decode(jwk["d"])
    except Exception as e:
        raise SecretsError("manyrows secrets: private key 'd' base64url decode failed") from e
    secret = int.from_bytes(d, "big")
    return ec.derive_private_key(secret, ec.SECP256R1())


def _load_ephemeral_public_key(jwk: dict[str, str], ec: Any) -> Any:
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise SecretsError("manyrows secrets: ephemeral public key must be EC P-256 JWK")
    try:
        x = _b64url_decode(jwk["x"])
        y = _b64url_decode(jwk["y"])
    except Exception as e:
        raise SecretsError("manyrows secrets: ephemeral public key x/y decode failed") from e
    if len(x) != 32 or len(y) != 32:
        raise SecretsError("manyrows secrets: ephemeral public key coords must be 32 bytes each")
    public_numbers = ec.EllipticCurvePublicNumbers(
        x=int.from_bytes(x, "big"),
        y=int.from_bytes(y, "big"),
        curve=ec.SECP256R1(),
    )
    return public_numbers.public_key()
