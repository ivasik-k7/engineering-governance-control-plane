"""Ed25519 signatures for policy bundles and catalog documents, verified against $GOV_TRUSTED_KEYS."""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

TRUSTED_KEYS_ENV = "GOV_TRUSTED_KEYS"


class SignatureError(Exception):
    pass


def key_id(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


def trusted_keys() -> dict[str, Ed25519PublicKey]:
    keys: dict[str, Ed25519PublicKey] = {}
    for item in filter(None, os.environ.get(TRUSTED_KEYS_ENV, "").split(os.pathsep)):
        try:
            key = serialization.load_pem_public_key(Path(item).read_bytes())
        except (OSError, ValueError) as exc:
            raise SignatureError(f"{TRUSTED_KEYS_ENV}: cannot load {item}: {exc}") from exc
        if not isinstance(key, Ed25519PublicKey):
            raise SignatureError(f"{TRUSTED_KEYS_ENV}: {item} is not an Ed25519 public key")
        keys[key_id(key)] = key
    return keys


def generate_keypair(private_path: Path, public_path: Path) -> str:
    private = Ed25519PrivateKey.generate()
    private_path.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    private_path.chmod(0o600)
    public = private.public_key()
    public_path.write_bytes(
        public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    return key_id(public)


def sign(private_key_path: Path, message: bytes) -> dict[str, str]:
    private = serialization.load_pem_private_key(private_key_path.read_bytes(), password=None)
    if not isinstance(private, Ed25519PrivateKey):
        raise SignatureError(f"{private_key_path} is not an Ed25519 private key")
    return {
        "key_id": key_id(private.public_key()),
        "algorithm": "ed25519",
        "signature": base64.b64encode(private.sign(message)).decode(),
    }


def verify(signatures: list[dict[str, Any]], message: bytes, what: str) -> str | None:
    """Key id of the first valid signature from a trusted key; None when no keys are configured.

    Raises when keys are configured and no trusted key signed, or a trusted key's signature is invalid.
    """
    keys = trusted_keys()
    for sig in signatures:
        key = keys.get(sig.get("key_id", ""))
        if key is None or sig.get("algorithm") != "ed25519":
            continue
        try:
            key.verify(base64.b64decode(sig["signature"]), message)
        except (InvalidSignature, ValueError):
            raise SignatureError(f"{what}: invalid signature from trusted key {sig['key_id']}") from None
        return str(sig["key_id"])
    if keys:
        raise SignatureError(f"{what}: no valid signature from a key in {TRUSTED_KEYS_ENV}")
    return None
