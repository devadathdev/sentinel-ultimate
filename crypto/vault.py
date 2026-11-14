"""SENTINEL post-layer cryptographic envelope: two independent AES-256-GCM layers."""
from __future__ import annotations
import base64, hashlib, json, os, time, uuid
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VERSION = 1
NONCE_BYTES = 12
KEY_BYTES = 32


def _b64e(v: bytes) -> str:
    return base64.urlsafe_b64encode(v).decode().rstrip("=")


def _b64d(v: str) -> bytes:
    return base64.urlsafe_b64decode(v + "=" * (-len(v) % 4))


def generate_key() -> str:
    """Generate a 256-bit key; store it in a KMS/HSM/secret manager in production."""
    return _b64e(os.urandom(KEY_BYTES))


def key_fingerprint(key: bytes) -> str:
    return hashlib.sha256(key).hexdigest()[:16]


@dataclass(frozen=True)
class KeyMaterial:
    key_id: str
    key: bytes

    @classmethod
    def from_b64(cls, key_id: str, encoded: str) -> "KeyMaterial":
        key = _b64d(encoded)
        if len(key) != KEY_BYTES:
            raise ValueError("AES-256 key must be exactly 32 bytes")
        return cls(key_id, key)


class CryptoVault:
    """Independent inner/outer AES-256-GCM envelope.

    Keys MUST be independent. The outer layer authenticates the complete inner
    envelope, while the inner layer authenticates the application plaintext.
    """
    def __init__(self, inner: KeyMaterial, outer: KeyMaterial):
        if inner.key == outer.key:
            raise ValueError("inner and outer AES keys must be independent")
        self.inner = inner
        self.outer = outer

    def seal(self, plaintext: bytes, *, aad: bytes = b"") -> dict:
        if not isinstance(plaintext, bytes):
            raise TypeError("plaintext must be bytes")
        event_id = str(uuid.uuid4())
        created = int(time.time())
        context = f"sentinel:v{VERSION}:{event_id}:{created}".encode()
        inner_nonce = os.urandom(NONCE_BYTES)
        inner_aad = context + b"|inner|" + aad
        inner_ct = AESGCM(self.inner.key).encrypt(inner_nonce, plaintext, inner_aad)
        inner = {
            "v": VERSION, "alg": "AES-256-GCM", "kid": self.inner.key_id,
            "nonce": _b64e(inner_nonce), "aad_hash": hashlib.sha256(inner_aad).hexdigest(),
            "ct": _b64e(inner_ct),
        }
        inner_bytes = json.dumps(inner, sort_keys=True, separators=(",", ":")).encode()
        outer_nonce = os.urandom(NONCE_BYTES)
        outer_aad = context + b"|outer|" + aad
        outer_ct = AESGCM(self.outer.key).encrypt(outer_nonce, inner_bytes, outer_aad)
        return {
            "v": VERSION, "scheme": "SENTINEL-2X-AES256-GCM", "event_id": event_id,
            "created_at": created, "outer_kid": self.outer.key_id,
            "outer_nonce": _b64e(outer_nonce), "outer_aad_hash": hashlib.sha256(outer_aad).hexdigest(),
            "outer_ct": _b64e(outer_ct),
        }

    def open(self, envelope: dict, *, aad: bytes = b"", max_age_seconds: int = 86400) -> bytes:
        self._validate(envelope)
        created = int(envelope["created_at"])
        now = int(time.time())
        if created > now + 60:
            raise ValueError("future-dated envelope")
        if now - created > max_age_seconds:
            raise ValueError("expired envelope")
        context = f"sentinel:v{VERSION}:{envelope['event_id']}:{created}".encode()
        outer_aad = context + b"|outer|" + aad
        if hashlib.sha256(outer_aad).hexdigest() != envelope["outer_aad_hash"]:
            raise ValueError("outer AAD mismatch")
        inner_bytes = AESGCM(self.outer.key).decrypt(_b64d(envelope["outer_nonce"]), _b64d(envelope["outer_ct"]), outer_aad)
        inner = json.loads(inner_bytes)
        if inner.get("v") != VERSION or inner.get("alg") != "AES-256-GCM":
            raise ValueError("unsupported inner envelope")
        if inner.get("kid") != self.inner.key_id:
            raise ValueError("unexpected inner key id")
        inner_aad = context + b"|inner|" + aad
        if hashlib.sha256(inner_aad).hexdigest() != inner.get("aad_hash"):
            raise ValueError("inner AAD mismatch")
        return AESGCM(self.inner.key).decrypt(_b64d(inner["nonce"]), _b64d(inner["ct"]), inner_aad)

    @staticmethod
    def _validate(e: dict) -> None:
        required = {"v","scheme","event_id","created_at","outer_kid","outer_nonce","outer_aad_hash","outer_ct"}
        if not required.issubset(e):
            raise ValueError("incomplete envelope")
        if e["v"] != VERSION or e["scheme"] != "SENTINEL-2X-AES256-GCM":
            raise ValueError("unsupported envelope")
        if len(_b64d(e["outer_nonce"])) != NONCE_BYTES:
            raise ValueError("invalid nonce")
