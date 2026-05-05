"""Round-trip tests for manyrows.secrets.decrypt_secret.

Mirrors the browser-side encrypt path in
manyrows-ui/src/project/ConfigKeys.tsx::encryptSecretValueToEnvelope.
If algorithm constants change, update them in three places: the
browser, secrets.py, and this test helper.
"""

from __future__ import annotations

import base64
import json
import os
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from manyrows.secrets import (
    SecretsError,
    compute_public_jwk_fingerprint,
    decrypt_secret,
)

_HKDF_SALT = b"manyrows:secrets:v1"
_HKDF_INFO_PREFIX = "workspace-fingerprint:"


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _generate_keypair() -> tuple[dict[str, str], dict[str, str], str]:
    """Returns (private_jwk, public_jwk, fingerprint)."""
    priv = ec.generate_private_key(ec.SECP256R1())
    nums = priv.private_numbers()
    pub_nums = nums.public_numbers
    x_bytes = pub_nums.x.to_bytes(32, "big")
    y_bytes = pub_nums.y.to_bytes(32, "big")
    d_bytes = nums.private_value.to_bytes(32, "big")

    public_jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url(x_bytes),
        "y": _b64url(y_bytes),
    }
    private_jwk = {
        **public_jwk,
        "d": _b64url(d_bytes),
    }
    fingerprint = compute_public_jwk_fingerprint(public_jwk)
    return private_jwk, public_jwk, fingerprint


def _encrypt_for_test(
    plaintext: bytes,
    public_jwk: dict[str, str],
    fingerprint: str,
) -> dict[str, Any]:
    """Browser-side encrypt — ECDH(P256) + HKDF-SHA256 + AES-256-GCM."""
    ws_pub = ec.EllipticCurvePublicNumbers(
        x=int.from_bytes(base64.urlsafe_b64decode(public_jwk["x"] + "=="), "big"),
        y=int.from_bytes(base64.urlsafe_b64decode(public_jwk["y"] + "=="), "big"),
        curve=ec.SECP256R1(),
    ).public_key()

    eph_priv = ec.generate_private_key(ec.SECP256R1())
    eph_pub = eph_priv.public_key()
    eph_pub_nums = eph_pub.public_numbers()

    shared = eph_priv.exchange(ec.ECDH(), ws_pub)
    info = (_HKDF_INFO_PREFIX + fingerprint).encode("utf-8")
    aes_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=_HKDF_SALT, info=info
    ).derive(shared)

    iv = os.urandom(12)
    ct_with_tag = AESGCM(aes_key).encrypt(iv, plaintext, None)

    return {
        "v": 1,
        "alg": "ECDH-P256+HKDF-SHA256+AES-256-GCM",
        "fingerprintSha256": fingerprint,
        "ephemeralPublicKeyJwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": _b64url(eph_pub_nums.x.to_bytes(32, "big")),
            "y": _b64url(eph_pub_nums.y.to_bytes(32, "big")),
        },
        "ivB64": base64.b64encode(iv).decode("ascii"),
        "ciphertextB64": base64.b64encode(ct_with_tag).decode("ascii"),
    }


class TestDecryptSecret:
    def test_round_trip_string(self) -> None:
        priv, pub, fp = _generate_keypair()
        env = _encrypt_for_test(b'"hello"', pub, fp)
        plaintext = decrypt_secret(env, priv)
        assert plaintext == b'"hello"'
        assert json.loads(plaintext.decode("utf-8")) == "hello"

    def test_round_trip_object(self) -> None:
        priv, pub, fp = _generate_keypair()
        payload = json.dumps({"db_url": "postgres://localhost", "port": 5432}).encode()
        env = _encrypt_for_test(payload, pub, fp)
        plaintext = decrypt_secret(env, priv)
        assert plaintext == payload

    def test_accepts_envelope_as_json_string(self) -> None:
        priv, pub, fp = _generate_keypair()
        env = _encrypt_for_test(b'"hello"', pub, fp)
        plaintext = decrypt_secret(json.dumps(env), priv)
        assert plaintext == b'"hello"'

    def test_rejects_tampered_ciphertext(self) -> None:
        priv, pub, fp = _generate_keypair()
        env = _encrypt_for_test(b'"hello"', pub, fp)
        ct = bytearray(base64.b64decode(env["ciphertextB64"]))
        ct[0] ^= 0xFF
        env["ciphertextB64"] = base64.b64encode(bytes(ct)).decode("ascii")
        with pytest.raises(SecretsError, match="decrypt failed"):
            decrypt_secret(env, priv)

    def test_rejects_wrong_private_key(self) -> None:
        _, pub, fp = _generate_keypair()
        other_priv, _, _ = _generate_keypair()
        env = _encrypt_for_test(b'"hello"', pub, fp)
        with pytest.raises(SecretsError, match="decrypt failed"):
            decrypt_secret(env, other_priv)

    def test_rejects_fingerprint_mismatch(self) -> None:
        priv, pub, fp = _generate_keypair()
        env = _encrypt_for_test(b'"hello"', pub, fp)
        env["fingerprintSha256"] = "a" * 64
        with pytest.raises(SecretsError, match="decrypt failed"):
            decrypt_secret(env, priv)

    def test_rejects_unsupported_algorithm(self) -> None:
        priv, pub, fp = _generate_keypair()
        env = _encrypt_for_test(b'"hello"', pub, fp)
        env["alg"] = "AES-128-CBC"
        with pytest.raises(SecretsError, match="unsupported algorithm"):
            decrypt_secret(env, priv)

    def test_rejects_unsupported_version(self) -> None:
        priv, pub, fp = _generate_keypair()
        env = _encrypt_for_test(b'"hello"', pub, fp)
        env["v"] = 2
        with pytest.raises(SecretsError, match="unsupported envelope version"):
            decrypt_secret(env, priv)

    def test_rejects_malformed_envelope_json(self) -> None:
        priv, _, _ = _generate_keypair()
        with pytest.raises(SecretsError, match="malformed envelope"):
            decrypt_secret("not json", priv)

    def test_rejects_envelope_missing_fields(self) -> None:
        priv, _, _ = _generate_keypair()
        with pytest.raises(SecretsError, match="missing"):
            decrypt_secret({"v": 1, "alg": "x"}, priv)


class TestComputePublicJwkFingerprint:
    def test_stable_hex_digest(self) -> None:
        jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": "WxXEJP0w8e3FKpNi3qwJtBkb1H1bYU2pwLRm6q3a3Ww",
            "y": "5y4FJW3LZ1MIK6CuM_kyLQH8UkN7q3KbbpXaWPOkY1Y",
        }
        fp1 = compute_public_jwk_fingerprint(jwk)
        assert len(fp1) == 64
        assert all(c in "0123456789abcdef" for c in fp1)

        fp2 = compute_public_jwk_fingerprint(jwk)
        assert fp2 == fp1
